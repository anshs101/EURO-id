import Foundation

enum MdlError: LocalizedError {
    case invalidQRCode(String)
    case invalidDeviceEngagement(String)
    case unsupportedTransport
    case bluetoothUnavailable
    case connectionTimeout
    case connectionFailed(String)
    case transferFailed(String)
    case decryptionFailed
    case invalidDeviceResponse(String)
    case certificateChainInvalid(String)
    case signatureInvalid
    case digestMismatch(namespace: String, elementId: String)
    case documentExpired
    case unsupportedDocType(String)
    case missingRequiredElement(String)

    var errorDescription: String? {
        switch self {
        case .invalidQRCode(let msg): return "Invalid QR code: \(msg)"
        case .invalidDeviceEngagement(let msg): return "Invalid device engagement: \(msg)"
        case .unsupportedTransport: return "Holder device is not using a supported transport method."
        case .bluetoothUnavailable: return "Bluetooth is not available. Please enable Bluetooth to verify mDLs."
        case .connectionTimeout: return "Connection timed out. Please try again."
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .transferFailed(let msg): return "Data transfer failed: \(msg)"
        case .decryptionFailed: return "Failed to decrypt the mDL response. The session may have been tampered with."
        case .invalidDeviceResponse(let msg): return "Invalid device response: \(msg)"
        case .certificateChainInvalid(let msg): return "Certificate chain validation failed: \(msg)"
        case .signatureInvalid: return "The mDL's issuer signature is invalid."
        case .digestMismatch(let ns, let id): return "Data integrity check failed for element '\(id)' in namespace '\(ns)'."
        case .documentExpired: return "This mDL has expired."
        case .unsupportedDocType(let dt): return "Unsupported document type: \(dt)"
        case .missingRequiredElement(let el): return "Required element '\(el)' was not present."
        }
    }
}
