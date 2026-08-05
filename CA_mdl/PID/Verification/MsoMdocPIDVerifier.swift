import Foundation
import CryptoKit
import Security
import SwiftCBOR

// mso_mdoc-format European PID verification (ISO 18013-5 IssuerAuth structure, docType
// "eu.europa.ec.eudi.pid.1") presented over OpenID4VP as a vp_token.
//
// This mirrors the cryptographic steps used for CA mDL verification in MsoValidator
// (COSE_Sign1 -> MSO -> per-namespace digest checks), but validates the issuer certificate
// chain against the per-country EU trust anchors in TrustAnchorStore instead of the
// hardcoded CA DMV IACA root — a PID verifier has to trust 27+ different national issuers,
// so CoseVerifier/CertificateValidator (which bake in the single CA DMV root) cannot be
// reused as-is here.
final class MsoMdocPIDVerifier {

    func verify(cborData: Data, expectedNonce: String, countryCode: String) async throws -> VerifiedPIDData {
        let bytes = [UInt8](cborData)
        guard let response = try? CBOR.decode(bytes) else {
            throw PIDError.invalidCBORStructure("Cannot decode DeviceResponse CBOR")
        }

        guard let documents = response.mapLookup("documents")?.arrayValue else {
            throw PIDError.invalidCBORStructure("No documents in DeviceResponse")
        }
        guard let doc = documents.first(where: { $0.mapLookup("docType")?.utf8StringValue == PIDNamespace.v1 }) else {
            throw PIDError.unsupportedCredentialType
        }

        let trustedRoots = await TrustAnchorStore.shared.certsForCountry(countryCode)
        guard !trustedRoots.isEmpty else {
            throw PIDError.noTrustAnchorForCountry(countryCode)
        }

        guard let issuerSigned = doc.mapLookup("issuerSigned") else {
            throw PIDError.invalidCBORStructure("Missing issuerSigned")
        }
        guard let issuerAuth = issuerSigned.mapLookup("issuerAuth") else {
            throw PIDError.invalidCBORStructure("Missing issuerAuth")
        }

        // COSE_Sign1 = [protected: bstr, unprotected: {}, payload: bstr/nil, signature: bstr]
        guard let coseArray = issuerAuth.arrayValue, coseArray.count == 4,
              let protectedBytes = coseArray[0].byteStringValue,
              let sigBytes = coseArray[3].byteStringValue else {
            throw PIDError.malformedSignature
        }
        let unprotected = coseArray[1]
        guard let payloadBytes = coseArray[2].byteStringValue else {
            throw PIDError.malformedSignature
        }

        let chainDer = Self.extractX5Chain(unprotected: unprotected, protectedBytes: protectedBytes)
        guard !chainDer.isEmpty else {
            throw PIDError.certificateChainInvalid
        }

        let leafKey = try PIDCertificateChainValidator.validate(chainDer: chainDer, trustedRoots: trustedRoots)
        let publicKey = try Self.p256PublicKey(from: leafKey)

        guard Self.verifyES256(protectedBytes: protectedBytes, payload: payloadBytes, sigBytes: sigBytes, publicKey: publicKey) else {
            throw PIDError.signatureVerificationFailed
        }

        guard let mso = try? CBOR.decode(payloadBytes) else {
            throw PIDError.invalidCBORStructure("Cannot decode MSO payload")
        }
        guard let msoDocType = mso.mapLookup("docType")?.utf8StringValue, msoDocType == PIDNamespace.v1 else {
            throw PIDError.unsupportedCredentialType
        }

        guard let validity = mso.mapLookup("validityInfo"),
              let validFrom = validity.mapLookup("validFrom")?.dateValue,
              let validUntil = validity.mapLookup("validUntil")?.dateValue else {
            throw PIDError.invalidCBORStructure("Missing validityInfo in MSO")
        }
        try Self.checkValidity(now: Date(), validFrom: validFrom, validUntil: validUntil)

        // Freshness check. NOTE: a production ISO/IEC 18013-7 (OpenID4VP-over-mdoc) flow
        // authenticates freshness via DeviceAuth over the SessionTranscript's OID4VPHandover,
        // not a bare nonce field. This checks a simplified nonce carried in deviceSigned for
        // the same purpose; it is not a substitute for verifying DeviceAuth in production.
        let presentedNonce = doc.mapLookup("deviceSigned")?.mapLookup("nonce")?.utf8StringValue
        try Self.checkNonce(presented: presentedNonce, expected: expectedNonce)

        guard let valueDigests = mso.mapLookup("valueDigests") else {
            throw PIDError.invalidCBORStructure("Missing valueDigests in MSO")
        }
        guard let nameSpaces = issuerSigned.mapLookup("nameSpaces"),
              let nsDigests = valueDigests.mapLookup(PIDNamespace.v1),
              let items = nameSpaces.mapLookup(PIDNamespace.v1)?.arrayValue else {
            throw PIDError.invalidCBORStructure("Missing \(PIDNamespace.v1) nameSpace")
        }

        var elements: [String: Any] = [:]
        for item in items {
            let innerBytes: [UInt8]
            if case .tagged(let tag, let inner) = item, tag.rawValue == 24, let b = inner.byteStringValue {
                innerBytes = b
            } else if let b = item.byteStringValue {
                innerBytes = b
            } else {
                continue
            }

            let digest = Array(SHA256.hash(data: Data(innerBytes)))
            guard let signedItem = try? CBOR.decode(innerBytes),
                  let digestID = signedItem.mapLookup("digestID")?.uint64Value,
                  let elementId = signedItem.mapLookup("elementIdentifier")?.utf8StringValue,
                  let elementValue = signedItem.mapLookup("elementValue") else { continue }

            guard let expectedCbor = nsDigests.mapLookup(Int(digestID)),
                  let expectedBytes = expectedCbor.byteStringValue,
                  digest == expectedBytes else {
                throw PIDError.digestMismatch(elementId)
            }

            elements[elementId] = Self.nativeValue(for: elementId, cbor: elementValue)
        }

        let issuingCountry = (elements[PIDElement.issuingCountry] as? String) ?? countryCode

        return VerifiedPIDData(
            elements: elements,
            issuingCountry: issuingCountry,
            verifiedAt: Date(),
            validUntil: validUntil,
            format: .msoMdoc
        )
    }

    // MARK: - Validity / freshness (broken out for unit testing without a full signed fixture)

    static func checkValidity(now: Date, validFrom: Date, validUntil: Date) throws {
        guard now >= validFrom else { throw PIDError.documentNotYetValid }
        guard now <= validUntil else { throw PIDError.expiredDocument }
    }

    static func checkNonce(presented: String?, expected: String) throws {
        guard presented == expected else { throw PIDError.nonceMismatch }
    }

    // MARK: - Element value conversion

    private static func nativeValue(for elementId: String, cbor: CBOR) -> Any? {
        switch elementId {
        case PIDElement.birthDate, PIDElement.expiryDate:
            return cbor.dateValue
        case PIDElement.portrait:
            return cbor.byteStringValue.map { Data($0) }
        case PIDElement.ageOver18:
            return cbor.boolValue
        default:
            return cbor.utf8StringValue ?? cbor.byteStringValue.map { Data($0) } ?? cbor.boolValue
        }
    }

    // MARK: - COSE helpers (parallel to CoseVerifier, generalized for injectable trust roots)

    private static func extractX5Chain(unprotected: CBOR, protectedBytes: [UInt8]) -> [[UInt8]] {
        func fromMap(_ cbor: CBOR) -> [[UInt8]]? {
            guard let v = cbor.mapLookup(33) else { return nil } // COSE header key 33 = x5chain
            if let bytes = v.byteStringValue { return [bytes] }
            if let arr = v.arrayValue { return arr.compactMap { $0.byteStringValue } }
            return nil
        }
        if let chain = fromMap(unprotected) { return chain }
        if let protected = try? CBOR.decode(protectedBytes), let chain = fromMap(protected) { return chain }
        return []
    }

    private static func p256PublicKey(from secKey: SecKey) throws -> P256.Signing.PublicKey {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) else {
            throw PIDError.certificateChainInvalid
        }
        do {
            return try P256.Signing.PublicKey(x963Representation: keyData as Data)
        } catch {
            throw PIDError.certificateChainInvalid
        }
    }

    private static func verifyES256(protectedBytes: [UInt8], payload: [UInt8], sigBytes: [UInt8], publicKey: P256.Signing.PublicKey) -> Bool {
        // Sig_Structure = ["Signature1", protected_bstr, external_aad, payload_bstr]
        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(protectedBytes),
            .byteString([]),
            .byteString(payload),
        ])
        let toVerify = Data(cborEncode(sigStructure))
        guard sigBytes.count == 64 else { return false }
        guard let sig = try? P256.Signing.ECDSASignature(rawRepresentation: Data(sigBytes)) else { return false }
        return publicKey.isValidSignature(sig, for: toVerify)
    }
}

// MARK: - Trust anchor chain validation

// Validates a DER-encoded certificate chain (leaf first) against a caller-supplied set of
// trust anchors, rather than a single hardcoded root. Used by both MsoMdocPIDVerifier and
// SDJWTVerifier, since a PID verifier must be able to trust any of the 27+ national issuers
// depending on the credential's issuing country.
enum PIDCertificateChainValidator {
    static func validate(chainDer: [[UInt8]], trustedRoots: [SecCertificate]) throws -> SecKey {
        guard !chainDer.isEmpty else {
            throw PIDError.certificateChainInvalid
        }

        let secCerts: [SecCertificate] = try chainDer.map { der in
            guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
                throw PIDError.certificateChainInvalid
            }
            return cert
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(secCerts as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else {
            throw PIDError.certificateChainInvalid
        }

        guard SecTrustSetAnchorCertificates(trust, trustedRoots as CFArray) == errSecSuccess else {
            throw PIDError.certificateChainInvalid
        }
        // Mandatory: only the supplied per-country anchors are trusted, never the system store.
        guard SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else {
            throw PIDError.certificateChainInvalid
        }
        SecTrustSetNetworkFetchAllowed(trust, false)

        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw PIDError.certificateChainInvalid
        }

        guard let secKey = SecTrustCopyKey(trust) else {
            throw PIDError.certificateChainInvalid
        }
        return secKey
    }
}
