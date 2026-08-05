import Foundation
import CryptoKit
import Security

// SD-JWT VC format European PID verification (SD-JWT-based Verifiable Credentials), as
// presented over OpenID4VP. Wire format: <issuer JWT>~<disclosure>~<disclosure>~...~[<KB-JWT>]
final class SDJWTVerifier {

    private static let reservedPayloadKeys: Set<String> = [
        "_sd", "_sd_alg", "iss", "iat", "exp", "nbf", "vct", "cnf", "status",
    ]

    func verify(sdJwtString: String, expectedNonce: String, countryCode: String) async throws -> VerifiedPIDData {
        let (issuerJWT, disclosures, keyBindingJWT) = try Self.splitPresentation(sdJwtString)

        let jwtParts = issuerJWT.components(separatedBy: ".")
        guard jwtParts.count == 3 else {
            throw PIDError.invalidSDJWT("Issuer JWT must have header.payload.signature")
        }
        let headerB64 = jwtParts[0], payloadB64 = jwtParts[1], sigB64 = jwtParts[2]

        guard let headerData = Data(base64URLEncoded: headerB64),
              let payloadData = Data(base64URLEncoded: payloadB64),
              let sigData = Data(base64URLEncoded: sigB64) else {
            throw PIDError.invalidSDJWT("Cannot base64url-decode JWT segments")
        }
        guard let headerObj = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw PIDError.invalidSDJWT("Cannot parse JWT header JSON")
        }
        guard let payloadObj = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw PIDError.invalidSDJWT("Cannot parse JWT payload JSON")
        }

        // MARK: Issuer key resolution — x5c only; JWKS endpoint resolution is out of scope.
        guard let x5c = headerObj["x5c"] as? [String], !x5c.isEmpty else {
            throw PIDError.issuerKeyResolutionFailed("JWT header has no x5c; JWKS resolution is not supported")
        }
        let chainDer: [[UInt8]] = try x5c.map { entry in
            guard let der = Data(base64Encoded: entry) else {
                throw PIDError.issuerKeyResolutionFailed("Cannot base64-decode x5c certificate")
            }
            return [UInt8](der)
        }
        let trustedRoots = await TrustAnchorStore.shared.certsForCountry(countryCode)
        guard !trustedRoots.isEmpty else {
            throw PIDError.noTrustAnchorForCountry(countryCode)
        }
        let leafKey = try PIDCertificateChainValidator.validate(chainDer: chainDer, trustedRoots: trustedRoots)

        // MARK: Signature verification
        guard let alg = headerObj["alg"] as? String else {
            throw PIDError.unsupportedAlgorithm("(missing alg)")
        }
        var keyError: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(leafKey, &keyError) else {
            throw PIDError.issuerKeyResolutionFailed("Cannot export leaf public key")
        }
        let signingInput = Data("\(headerB64).\(payloadB64)".utf8)
        let signatureValid = try Self.verifyECDSASignature(
            alg: alg, signingInput: signingInput, signature: sigData, publicKeyX963: keyData as Data
        )
        guard signatureValid else {
            throw PIDError.signatureVerificationFailed
        }

        // MARK: Key-binding nonce check
        // NOTE: this checks only the "nonce" claim carried by the KB-JWT payload; it does not
        // verify the KB-JWT's own signature against the holder's confirmation key ("cnf").
        // Production code MUST verify that signature too — otherwise an attacker who captures
        // a genuine vp_token could staple on a forged KB-JWT carrying any nonce they like.
        let presentedNonce = keyBindingJWT.flatMap(Self.extractNonce)
        guard presentedNonce == expectedNonce else {
            throw PIDError.nonceMismatch
        }

        // MARK: Selective disclosure verification — hash check always precedes decode.
        let sdArray = payloadObj["_sd"] as? [String] ?? []
        var disclosedClaims: [String: Any] = [:]
        for disclosure in disclosures {
            let (name, value) = try Self.verifyAndDecodeDisclosure(disclosure, sdArray: sdArray)
            disclosedClaims[name] = value
        }

        var directClaims: [String: Any] = [:]
        for (key, value) in payloadObj where !Self.reservedPayloadKeys.contains(key) {
            directClaims[key] = value
        }

        var elements: [String: Any] = [:]
        for (key, value) in directClaims { elements[key] = Self.normalize(key: key, value: value) }
        for (key, value) in disclosedClaims { elements[key] = Self.normalize(key: key, value: value) }

        let validUntil: Date
        if let exp = payloadObj["exp"] as? NSNumber {
            validUntil = Date(timeIntervalSince1970: exp.doubleValue)
        } else {
            validUntil = Date().addingTimeInterval(24 * 60 * 60)
        }
        if payloadObj["exp"] != nil, validUntil < Date() {
            throw PIDError.expiredDocument
        }

        let issuingCountry = (elements[PIDElement.issuingCountry] as? String) ?? countryCode

        return VerifiedPIDData(
            elements: elements,
            issuingCountry: issuingCountry,
            verifiedAt: Date(),
            validUntil: validUntil,
            format: .sdJWT
        )
    }

    // MARK: - Presentation splitting

    // Splits "<issuer JWT>~<disclosure>~...~[<KB-JWT>]". A well-formed SD-JWT with no
    // key-binding JWT ends with a trailing "~", producing an empty final component that must
    // be dropped rather than treated as a disclosure.
    static func splitPresentation(_ sdJwtString: String) throws -> (issuerJWT: String, disclosures: [String], keyBindingJWT: String?) {
        let rawParts = sdJwtString.components(separatedBy: "~")
        guard let issuerJWT = rawParts.first, !issuerJWT.isEmpty else {
            throw PIDError.invalidSDJWT("Empty SD-JWT presentation")
        }
        var middle = Array(rawParts.dropFirst())
        var keyBindingJWT: String? = nil
        if let last = middle.last, !last.isEmpty, last.hasPrefix("ey"), last != issuerJWT {
            keyBindingJWT = last
            middle.removeLast()
        }
        let disclosures = middle.filter { !$0.isEmpty }
        return (issuerJWT, disclosures, keyBindingJWT)
    }

    private static func extractNonce(from keyBindingJWT: String) -> String? {
        let parts = keyBindingJWT.components(separatedBy: ".")
        guard parts.count == 3,
              let data = Data(base64URLEncoded: parts[1]),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return obj["nonce"] as? String
    }

    // MARK: - Disclosure hashing / decoding (internal so unit tests can exercise them directly)

    static func disclosureDigest(_ disclosure: String) -> String {
        let hash = SHA256.hash(data: Data(disclosure.utf8))
        return Data(hash).base64URLEncodedStringNoPadding()
    }

    static func decodeDisclosure(_ disclosure: String) throws -> (name: String, value: Any) {
        guard let data = Data(base64URLEncoded: disclosure),
              let array = try? JSONSerialization.jsonObject(with: data) as? [Any],
              array.count == 3,
              let name = array[1] as? String else {
            throw PIDError.invalidSDJWT("Malformed disclosure; expected [salt, name, value]")
        }
        return (name, array[2])
    }

    // Hash-then-decode, in that order: an undisclosed claim must never be trusted even
    // transiently, so its hash is checked against the issuer's committed "_sd" array before
    // its content is parsed at all. A mismatch means someone handed us a disclosure the
    // issuer never signed for — a disclosure injection attack.
    static func verifyAndDecodeDisclosure(_ disclosure: String, sdArray: [String]) throws -> (name: String, value: Any) {
        let digest = disclosureDigest(disclosure)
        guard sdArray.contains(digest) else {
            throw PIDError.invalidSDJWT("Disclosure hash not found in _sd array")
        }
        return try decodeDisclosure(disclosure)
    }

    // MARK: - Claim value normalization

    private static func normalize(key: String, value: Any) -> Any {
        switch key {
        case PIDElement.birthDate, PIDElement.expiryDate:
            if let s = value as? String, let date = DateFormatter.isoDate.date(from: s) { return date }
            return value
        case PIDElement.portrait:
            if let s = value as? String, let data = Data(base64Encoded: s) ?? Data(base64URLEncoded: s) {
                return data
            }
            return value
        default:
            return value
        }
    }

    // MARK: - ECDSA signature verification (internal so unit tests can exercise it directly)

    static func verifyECDSASignature(alg: String, signingInput: Data, signature: Data, publicKeyX963: Data) throws -> Bool {
        switch alg {
        case "ES256":
            guard signature.count == 64,
                  let pub = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
                throw PIDError.malformedSignature
            }
            return pub.isValidSignature(sig, for: signingInput)
        case "ES384":
            guard signature.count == 96,
                  let pub = try? P384.Signing.PublicKey(x963Representation: publicKeyX963),
                  let sig = try? P384.Signing.ECDSASignature(rawRepresentation: signature) else {
                throw PIDError.malformedSignature
            }
            return pub.isValidSignature(sig, for: signingInput)
        case "ES512":
            guard signature.count == 132,
                  let pub = try? P521.Signing.PublicKey(x963Representation: publicKeyX963),
                  let sig = try? P521.Signing.ECDSASignature(rawRepresentation: signature) else {
                throw PIDError.malformedSignature
            }
            return pub.isValidSignature(sig, for: signingInput)
        default:
            throw PIDError.unsupportedAlgorithm(alg)
        }
    }
}

private extension Data {
    func base64URLEncodedStringNoPadding() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
