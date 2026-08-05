import Foundation
import CryptoKit
import Observation
import SwiftCBOR

@Observable
@MainActor
final class MdlVerificationSession {

    var state: VerificationState = .idle

    // Non-nil only during an active session; cleared when done
    private var transport: BleTransport?

    func startScanning() {
        state = .scanning
    }

    func cancel() {
        transport = nil
        state = .idle
    }

    func reset() {
        transport = nil
        state = .idle
    }

    // Called by ScanView when a QR code string is detected
    func handleQRCode(_ payload: String) {
        guard case .scanning = state else { return }
        state = .connecting(status: "Parsing device engagement…")
        Task {
            await runSession(qrPayload: payload)
        }
    }

    // MARK: - Full verification pipeline

    private func runSession(qrPayload: String) async {
        do {
            // 1. Parse DeviceEngagement from the mdoc: QR payload
            let engagement = try DeviceEngagement.parse(from: qrPayload)

            // 2. Generate the verifier's ephemeral EC key pair
            let eReaderPrivKey = P256.KeyAgreement.PrivateKey()

            // 3. Derive session keys and build SessionTranscript
            var crypto = try SessionCrypto(
                eReaderPrivKey: eReaderPrivKey,
                eDeviceKey: engagement.eDeviceKey,
                deviceEngagementBytes: engagement.rawCborBytes
            )

            // 4. Build and encrypt the DeviceRequest
            let deviceRequest = SessionCrypto.buildDeviceRequest()
            let encryptedRequest = try crypto.encryptReaderMessage(deviceRequest)

            // 5. Wrap into SessionEstablishment
            let sessionEstablishment = crypto.buildSessionEstablishment(
                encryptedDeviceRequest: encryptedRequest
            )

            state = .connecting(status: "Connecting via Bluetooth…")

            // 6. BLE exchange
            let bleTransport = BleTransport()
            transport = bleTransport
            let encryptedResponse = try await bleTransport.exchange(
                request: sessionEstablishment,
                engagement: engagement
            )
            transport = nil

            state = .exchanging(status: "Decrypting and verifying…")

            // 7. Decrypt SessionData from holder
            let sessionData = try parseSessionData(encryptedResponse)
            let deviceResponseData = try crypto.decryptDeviceMessage(sessionData)

            state = .verifying

            // 8. Verify MSO signatures, digests, cert chain
            let document = try MsoValidator.verify(
                deviceResponseData: deviceResponseData,
                sessionTranscript: crypto.sessionTranscriptBytes
            )

            state = .verified(document)

        } catch let e as MdlError {
            transport = nil
            state = .failed(e.errorDescription ?? e.localizedDescription)
        } catch {
            transport = nil
            state = .failed(error.localizedDescription)
        }
    }

    // MARK: - SessionData unwrapping

    // SessionData = { ? "data": bstr, ? "status": uint }
    private func parseSessionData(_ raw: Data) throws -> Data {
        let bytes = [UInt8](raw)

        // First check: is this a plain (non-session-wrapped) DeviceResponse?
        // Some implementations omit the SessionData wrapper.
        if let decoded = try? CBOR.decode(bytes),
           let _ = decoded.mapLookup("version") {
            // Looks like a raw DeviceResponse — return as-is
            return raw
        }

        guard let cbor = try? CBOR.decode(bytes) else {
            throw MdlError.invalidDeviceResponse("Cannot decode SessionData")
        }
        if let status = cbor.mapLookup("status")?.uint64Value, status != 0 {
            throw MdlError.invalidDeviceResponse("Session error status \(status)")
        }
        guard let dataBytes = cbor.mapLookup("data")?.byteStringValue else {
            throw MdlError.invalidDeviceResponse("No data field in SessionData")
        }
        return Data(dataBytes)
    }
}

// MARK: - Sendable conformance note
// MdlVerificationSession is @MainActor-isolated so all access is serialised.
