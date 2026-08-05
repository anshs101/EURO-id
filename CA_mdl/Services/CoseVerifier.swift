import Foundation
import CryptoKit
import SwiftCBOR

// ISO 18013-5 / RFC 8152 — COSE_Sign1 signature verification (ES256 / P-256 + SHA-256)
struct CoseVerifier {

    struct VerifiedPayload {
        let payload: [UInt8]
        let issuerPublicKey: P256.Signing.PublicKey?   // nil when cert chain is untrusted
        let issuerSubject: String
        let isCertificateChainTrusted: Bool
        let isMsoSignatureValid: Bool
    }

    // Verify a COSE_Sign1 structure (IssuerAuth from ISO 18013-5).
    // Returns the raw payload bytes on success.
    static func verify(_ cose: CBOR) throws -> VerifiedPayload {
        // COSE_Sign1 = [protected: bstr, unprotected: {}, payload: bstr/nil, signature: bstr]
        guard let arr = cose.arrayValue, arr.count == 4 else {
            throw MdlError.signatureInvalid
        }

        guard let protectedBytes = arr[0].byteStringValue else {
            throw MdlError.signatureInvalid
        }
        let unprotected = arr[1]
        let payloadCbor  = arr[2]
        guard let sigBytes = arr[3].byteStringValue else {
            throw MdlError.signatureInvalid
        }

        // Payload: either embedded bstr or detached (nil)
        let payloadBytes: [UInt8]
        if let bytes = payloadCbor.byteStringValue {
            payloadBytes = bytes
        } else if case .null = payloadCbor {
            throw MdlError.invalidDeviceResponse("Detached COSE payload not supported")
        } else {
            throw MdlError.signatureInvalid
        }

        // Extract x5chain from unprotected (key 33) or protected header
        let chainDer = extractX5Chain(unprotected: unprotected, protectedBytes: protectedBytes)
        guard !chainDer.isEmpty else {
            throw MdlError.certificateChainInvalid("No x5chain found in IssuerAuth headers")
        }

        // Validate certificate chain against IACA root
        var certTrusted = false
        var sigValid = false
        var issuerKey: P256.Signing.PublicKey? = nil
        var issuerSubject = "Unknown"

        do {
            let (key, subject) = try CertificateValidator.validate(chain: chainDer)
            issuerKey = key
            issuerSubject = subject
            certTrusted = true
        } catch {
            // Record that the chain is untrusted but continue to extract data
            certTrusted = false
        }

        // Verify ECDSA-P256 signature over Sig_Structure
        if let key = issuerKey {
            sigValid = verifyCoseSignature(
                protectedBytes: protectedBytes,
                payload: payloadBytes,
                sigBytes: sigBytes,
                publicKey: key
            )
        }

        return VerifiedPayload(
            payload: payloadBytes,
            issuerPublicKey: issuerKey,
            issuerSubject: issuerSubject,
            isCertificateChainTrusted: certTrusted,
            isMsoSignatureValid: sigValid
        )
    }

    // MARK: - Private helpers

    private static func extractX5Chain(unprotected: CBOR, protectedBytes: [UInt8]) -> [[UInt8]] {
        // COSE header key 33 = x5chain
        func fromMap(_ cbor: CBOR) -> [[UInt8]]? {
            guard let v = cbor.mapLookup(33) else { return nil }
            if let bytes = v.byteStringValue { return [bytes] }
            if let arr = v.arrayValue { return arr.compactMap { $0.byteStringValue } }
            return nil
        }

        if let chain = fromMap(unprotected) { return chain }
        if let protected = try? CBOR.decode(protectedBytes), let chain = fromMap(protected) {
            return chain
        }
        return []
    }

    private static func verifyCoseSignature(
        protectedBytes: [UInt8],
        payload: [UInt8],
        sigBytes: [UInt8],
        publicKey: P256.Signing.PublicKey
    ) -> Bool {
        // Sig_Structure = ["Signature1", protected_bstr, b"", payload_bstr]
        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(protectedBytes),
            .byteString([]),          // external_aad = empty bstr
            .byteString(payload),
        ])
        let toVerify = Data(cborEncode(sigStructure))

        // Signature in COSE ES256 is 64 bytes raw (r || s)
        guard sigBytes.count == 64 else { return false }
        do {
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(sigBytes))
            return publicKey.isValidSignature(sig, for: toVerify)
        } catch {
            return false
        }
    }
}
