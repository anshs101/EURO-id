import Foundation
import CryptoKit
import SwiftCBOR

// ISO 18013-5 Section 9.1 — Session key derivation and message encryption/decryption
struct SessionCrypto: Sendable {
    let skReader: SymmetricKey   // verifier → holder (AES-256-GCM)
    let skDevice: SymmetricKey   // holder → verifier (AES-256-GCM)
    let eReaderKeyBytes: [UInt8] // CBOR-encoded COSE_Key of EReaderKey (for SessionTranscript)
    let sessionTranscriptBytes: [UInt8]

    private(set) var readerCounter: UInt32 = 1
    private(set) var deviceCounter: UInt32 = 1

    // Derive session keys from the verifier ephemeral key, holder ephemeral key, and engagement bytes.
    init(
        eReaderPrivKey: P256.KeyAgreement.PrivateKey,
        eDeviceKey: P256.KeyAgreement.PublicKey,
        deviceEngagementBytes: [UInt8]   // raw bytes from QR scan
    ) throws {
        // Encode verifier's ephemeral public key as COSE_Key
        let pubKey = eReaderPrivKey.publicKey
        let raw = pubKey.rawRepresentation  // 64 bytes: x || y
        let x = Array(raw.prefix(32))
        let y = Array(raw.suffix(32))
        let coseKeyMap: CBOR = .map([
            .unsignedInt(1):  .unsignedInt(2),      // kty: EC2
            .negativeInt(0):  .unsignedInt(1),      // crv: P-256
            .negativeInt(1):  .byteString(x),       // x
            .negativeInt(2):  .byteString(y),       // y
        ])
        let coseKeyEncoded = cborEncode(coseKeyMap)
        eReaderKeyBytes = coseKeyEncoded

        // SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
        // DeviceEngagementBytes = #6.24(bstr(rawEngagementCBOR))
        // EReaderKeyBytes       = #6.24(bstr(CBOR(COSE_Key)))
        // Handover              = null  (QR code handover)
        let deTag24  = CBOR.tag24(deviceEngagementBytes)
        let erkTag24 = CBOR.tag24(coseKeyEncoded)
        let transcript: CBOR = .array([deTag24, erkTag24, .null])
        sessionTranscriptBytes = cborEncode(transcript)

        // ECDH
        let sharedSecret = try eReaderPrivKey.sharedSecretFromKeyAgreement(with: eDeviceKey)

        // HKDF-SHA-256 key derivation
        let salt = Data(sessionTranscriptBytes)
        skReader = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("SKReader".utf8),
            outputByteCount: 32
        )
        skDevice = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("SKDevice".utf8),
            outputByteCount: 32
        )
    }

    // Encrypt plaintext with SKReader (verifier → holder direction)
    mutating func encryptReaderMessage(_ plaintext: Data) throws -> Data {
        let nonce = makeNonce(readerCounter)
        readerCounter &+= 1
        let sealed = try AES.GCM.seal(plaintext, using: skReader, nonce: nonce)
        return sealed.ciphertext + sealed.tag
    }

    // Decrypt ciphertext with SKDevice (holder → verifier direction)
    mutating func decryptDeviceMessage(_ ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw MdlError.decryptionFailed }
        let tag = ciphertext.suffix(16)
        let ct  = ciphertext.dropLast(16)
        let nonce = makeNonce(deviceCounter)
        deviceCounter &+= 1
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        do {
            return try AES.GCM.open(box, using: skDevice)
        } catch {
            throw MdlError.decryptionFailed
        }
    }

    // 12-byte big-endian counter nonce: 8 zero bytes + 4-byte counter
    private func makeNonce(_ counter: UInt32) -> AES.GCM.Nonce {
        var data = Data(repeating: 0, count: 8)
        data.append(contentsOf: counter.bigEndianBytes)
        return try! AES.GCM.Nonce(data: data)
    }
}

// MARK: - Device request builder

extension SessionCrypto {
    // Build a CBOR-encoded DeviceRequest asking for standard mDL elements
    static func buildDeviceRequest() -> Data {
        let elements: CBOR = .map([
            .utf8String(IsoMdl.Element.familyName):        .boolean(false),
            .utf8String(IsoMdl.Element.givenName):         .boolean(false),
            .utf8String(IsoMdl.Element.birthDate):         .boolean(false),
            .utf8String(IsoMdl.Element.documentNumber):    .boolean(false),
            .utf8String(IsoMdl.Element.expiryDate):        .boolean(false),
            .utf8String(IsoMdl.Element.issueDate):         .boolean(false),
            .utf8String(IsoMdl.Element.issuingCountry):    .boolean(false),
            .utf8String(IsoMdl.Element.issuingAuthority):  .boolean(false),
            .utf8String(IsoMdl.Element.portrait):          .boolean(false),
            .utf8String(IsoMdl.Element.drivingPrivileges): .boolean(false),
            .utf8String(IsoMdl.Element.ageOver18):         .boolean(false),
            .utf8String(IsoMdl.Element.ageOver21):         .boolean(false),
            .utf8String(IsoMdl.Element.ageInYears):        .boolean(false),
        ])

        let itemsRequest: CBOR = .map([
            .utf8String("docType"):    .utf8String(IsoMdl.mDLDocType),
            .utf8String("nameSpaces"): .map([.utf8String(IsoMdl.namespace): elements]),
        ])
        let itemsRequestBytes = cborEncode(itemsRequest)

        let docRequest: CBOR = .map([
            .utf8String("itemsRequest"): CBOR.tag24(itemsRequestBytes),
        ])

        let deviceRequest: CBOR = .map([
            .utf8String("version"):     .utf8String(IsoMdl.version),
            .utf8String("docRequests"): .array([docRequest]),
        ])

        return Data(cborEncode(deviceRequest))
    }

    // Wrap EReaderKey and encrypted DeviceRequest into a SessionEstablishment message
    func buildSessionEstablishment(encryptedDeviceRequest: Data) -> Data {
        let msg: CBOR = .map([
            .utf8String("eReaderKey"): CBOR.tag24(eReaderKeyBytes),
            .utf8String("data"):       .byteString([UInt8](encryptedDeviceRequest)),
        ])
        return Data(cborEncode(msg))
    }
}
