import Foundation
import CryptoKit
import SwiftCBOR

// ISO 18013-5 Section 8.2 — Device Engagement decoded from the mdoc: QR payload
struct DeviceEngagement: Sendable {
    let version: String
    let eDeviceKey: P256.KeyAgreement.PublicKey
    let retrievalMethods: [RetrievalMethod]
    let rawCborBytes: [UInt8]   // verbatim bytes from QR, used in SessionTranscript

    enum RetrievalMethod: Sendable {
        case ble(BleOptions)
        case nfc
        case wifi
    }

    struct BleOptions: Sendable {
        let peripheralServerMode: Bool   // holder advertises, verifier connects as central
        let centralClientMode: Bool      // verifier advertises, holder connects as central
        let peripheralUUID: String?      // UUID string embedded in the engagement
    }

    static func parse(from qrPayload: String) throws -> DeviceEngagement {
        guard qrPayload.hasPrefix("mdoc:") else {
            throw MdlError.invalidQRCode("Missing 'mdoc:' prefix")
        }
        let encoded = String(qrPayload.dropFirst(5))
        guard let data = Data(base64URLEncoded: encoded) else {
            throw MdlError.invalidQRCode("Cannot base64url-decode payload")
        }
        let bytes = [UInt8](data)
        guard let cbor = try? CBOR.decode(bytes) else {
            throw MdlError.invalidDeviceEngagement("Cannot decode CBOR")
        }
        return try build(from: cbor, rawBytes: bytes)
    }

    private static func build(from cbor: CBOR, rawBytes: [UInt8]) throws -> DeviceEngagement {
        guard let version = cbor.mapLookup(0)?.utf8StringValue, version == "1.0" else {
            throw MdlError.invalidDeviceEngagement("Unsupported or missing version")
        }

        // Security: [cipherSuiteIdentifier, EDeviceKeyBytes]
        guard let security = cbor.mapLookup(1)?.arrayValue, security.count >= 2 else {
            throw MdlError.invalidDeviceEngagement("Missing Security array")
        }
        let eDeviceKey = try extractCoseKey(from: security[1])

        // Retrieval methods: [[type, version, options]]
        var methods: [RetrievalMethod] = []
        if let methodsArray = cbor.mapLookup(2)?.arrayValue {
            for entry in methodsArray {
                guard let arr = entry.arrayValue, arr.count >= 3,
                      let typeInt = arr[0].uint64Value else { continue }
                switch typeInt {
                case 2:
                    if let optMap = arr[2].cborMap {
                        methods.append(.ble(parseBleOptions(optMap)))
                    }
                case 1: methods.append(.nfc)
                case 3: methods.append(.wifi)
                default: break
                }
            }
        }

        return DeviceEngagement(
            version: version,
            eDeviceKey: eDeviceKey,
            retrievalMethods: methods,
            rawCborBytes: rawBytes
        )
    }

    private static func parseBleOptions(_ map: [(CBOR, CBOR)]) -> BleOptions {
        var peripheral = false
        var central = false
        var uuid: String? = nil
        for (k, v) in map {
            guard let key = k.uint64Value else { continue }
            switch key {
            case 0: peripheral = v.boolValue ?? false
            case 1: central    = v.boolValue ?? false
            case 10:
                if let bytes = v.byteStringValue, bytes.count == 16 {
                    let t = (bytes[0], bytes[1], bytes[2], bytes[3],
                             bytes[4], bytes[5], bytes[6], bytes[7],
                             bytes[8], bytes[9], bytes[10], bytes[11],
                             bytes[12], bytes[13], bytes[14], bytes[15])
                    uuid = UUID(uuid: t).uuidString.uppercased()
                }
            default: break
            }
        }
        return BleOptions(peripheralServerMode: peripheral, centralClientMode: central, peripheralUUID: uuid)
    }

    // Decodes a COSE_Key map into a P-256 public key
    private static func extractCoseKey(from cbor: CBOR) throws -> P256.KeyAgreement.PublicKey {
        // EDeviceKeyBytes may be tag-24 wrapped
        let keyCbor: CBOR
        if let inner = cbor.tag24Content {
            keyCbor = inner
        } else if let bytes = cbor.byteStringValue {
            guard let decoded = try? CBOR.decode(bytes) else {
                throw MdlError.invalidDeviceEngagement("Cannot decode EDeviceKey CBOR")
            }
            keyCbor = decoded
        } else {
            keyCbor = cbor
        }
        guard let xBytes = keyCbor.mapLookup(-2)?.byteStringValue,
              let yBytes = keyCbor.mapLookup(-3)?.byteStringValue,
              xBytes.count == 32, yBytes.count == 32 else {
            throw MdlError.invalidDeviceEngagement("Invalid EDeviceKey coordinates")
        }
        var raw = Data([0x04])
        raw.append(contentsOf: xBytes)
        raw.append(contentsOf: yBytes)
        do {
            return try P256.KeyAgreement.PublicKey(x963Representation: raw)
        } catch {
            throw MdlError.invalidDeviceEngagement("Cannot create P-256 key: \(error)")
        }
    }
}

// MARK: - Data helpers

extension Data {
    init?(base64URLEncoded string: String) {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = s.count % 4
        if rem > 0 { s += String(repeating: "=", count: 4 - rem) }
        self.init(base64Encoded: s)
    }
}
