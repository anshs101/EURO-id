import Foundation

enum PIDError: LocalizedError {
    // Parsing
    case invalidCBORStructure(String)
    case invalidSDJWT(String)
    case missingRequiredField(String)
    case unsupportedCredentialType

    // Trust
    case noTrustAnchorForCountry(String)
    case trustListUnavailable
    case issuerKeyResolutionFailed(String)
    case certificateChainInvalid

    // Signature
    case signatureVerificationFailed
    case unsupportedAlgorithm(String)
    case malformedSignature

    // Document
    case expiredDocument
    case documentNotYetValid
    case nonceMismatch
    case digestMismatch(String)

    // Flow
    case requestBuildFailed
    case walletNotInstalled
    case sessionExpired

    var errorDescription: String? {
        switch self {
        case .invalidCBORStructure(let msg):
            return "Invalid CBOR structure: \(msg)"
        case .invalidSDJWT(let msg):
            return "Invalid SD-JWT: \(msg)"
        case .missingRequiredField(let field):
            return "Missing required field: \(field)"
        case .unsupportedCredentialType:
            return "This credential is not a supported European PID document."
        case .noTrustAnchorForCountry(let code):
            return "No trust anchor is available for issuing country '\(code)'."
        case .trustListUnavailable:
            return "The EU trust list could not be loaded."
        case .issuerKeyResolutionFailed(let msg):
            return "Could not resolve the issuer's signing key: \(msg)"
        case .certificateChainInvalid:
            return "The issuer's certificate chain could not be validated against the EU trust list."
        case .signatureVerificationFailed:
            return "The credential's cryptographic signature is invalid."
        case .unsupportedAlgorithm(let alg):
            return "Unsupported signing algorithm: \(alg)"
        case .malformedSignature:
            return "The credential's signature is malformed."
        case .expiredDocument:
            return "This European Digital ID has expired."
        case .documentNotYetValid:
            return "This European Digital ID is not yet valid."
        case .nonceMismatch:
            return "The credential's freshness proof does not match this verification request. It may be a replay."
        case .digestMismatch(let elementId):
            return "Data integrity check failed for element '\(elementId)'."
        case .requestBuildFailed:
            return "Could not build the verification request."
        case .walletNotInstalled:
            return "No compatible EUDI Wallet app is installed on this device."
        case .sessionExpired:
            return "The verification session expired before a response was received."
        }
    }
}
