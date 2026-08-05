import Foundation
import Security
import CryptoKit

// Validates the mDL issuer certificate chain against the CA DMV IACA root certificate
// and extracts the signing public key from the leaf certificate.
struct CertificateValidator {

    // Returns the leaf certificate's P-256 signing key and the human-readable subject string.
    // Throws if the chain cannot be validated against the bundled IACA root.
    static func validate(
        chain: [[UInt8]]   // DER-encoded certs, leaf first
    ) throws -> (publicKey: P256.Signing.PublicKey, subjectSummary: String) {
        guard !chain.isEmpty else {
            throw MdlError.certificateChainInvalid("Empty certificate chain")
        }

        // Build SecCertificate objects
        let secCerts: [SecCertificate] = try chain.map { der in
            guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
                throw MdlError.certificateChainInvalid("Cannot create SecCertificate from DER bytes")
            }
            return cert
        }

        let leafCert = secCerts[0]

        // Load the bundled CA DMV IACA root certificate
        let iaca = try loadIacaRoot()

        // Build a trust object: leaf first, then any intermediate certs
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(secCerts as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else {
            throw MdlError.certificateChainInvalid("Cannot create SecTrust (OSStatus \(status))")
        }

        // Set the IACA root as the sole anchor
        try SecTrustSetAnchorCertificates(trust, [iaca] as CFArray).check("SetAnchors")
        try SecTrustSetAnchorCertificatesOnly(trust, true).check("SetAnchorsOnly")

        // Disable network revocation fetch — verifier must work offline
        SecTrustSetNetworkFetchAllowed(trust, false)

        // Evaluate
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            let msg = (error as Error?)?.localizedDescription ?? "Unknown"
            throw MdlError.certificateChainInvalid(msg)
        }

        // Extract the leaf public key as P-256
        guard let secKey = SecTrustCopyKey(trust) else {
            throw MdlError.certificateChainInvalid("Cannot copy leaf public key")
        }
        let p256Key = try secKeyToP256Signing(secKey)
        let subject = SecCertificateCopySubjectSummary(leafCert) as String? ?? "Unknown Issuer"

        return (p256Key, subject)
    }

    // MARK: - Private helpers

    private static func loadIacaRoot() throws -> SecCertificate {
        guard let url = Bundle.main.url(forResource: "ca-dmv-iaca-root-ca-crt", withExtension: "cer"),
              let data = try? Data(contentsOf: url) else {
            throw MdlError.certificateChainInvalid("IACA root certificate not found in bundle")
        }
        guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
            throw MdlError.certificateChainInvalid("Cannot parse bundled IACA root certificate")
        }
        return cert
    }

    private static func secKeyToP256Signing(_ secKey: SecKey) throws -> P256.Signing.PublicKey {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) else {
            let msg = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown"
            throw MdlError.certificateChainInvalid("Cannot export leaf key: \(msg)")
        }
        do {
            return try P256.Signing.PublicKey(x963Representation: keyData as Data)
        } catch {
            throw MdlError.certificateChainInvalid("Leaf key is not P-256: \(error)")
        }
    }
}

// MARK: - OSStatus convenience

private extension OSStatus {
    func check(_ label: String) throws {
        guard self == errSecSuccess else {
            throw MdlError.certificateChainInvalid("\(label) failed (OSStatus \(self))")
        }
    }
}
