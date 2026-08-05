import Foundation

enum VerificationState: Sendable {
    case idle
    case scanning
    case connecting(status: String)
    case exchanging(status: String)
    case verifying
    case verified(MdlDocument)
    case failed(String)

    var isActive: Bool {
        switch self {
        case .connecting, .exchanging, .verifying: return true
        default: return false
        }
    }

    var statusMessage: String {
        switch self {
        case .idle: return "Ready to verify"
        case .scanning: return "Scan the QR code on the holder's device"
        case .connecting(let s): return s
        case .exchanging(let s): return s
        case .verifying: return "Verifying cryptographic signatures..."
        case .verified: return "Verification complete"
        case .failed(let msg): return msg
        }
    }
}
