import Foundation

enum PIDCredentialFormat {
    case msoMdoc
    case sdJWT
}

// Verified European PID data, held only in memory for the lifetime of a single verification
// screen.
//
// This intentionally does NOT conform to Codable, NSCoding, or any other serialization
// protocol — the same "privacy by type system" reasoning as VerifiedMDLData: if the type
// cannot be encoded, it cannot later be accidentally logged, cached, or written to disk by
// code added down the line. Do not add a conformance here.
struct VerifiedPIDData {
    let elements: [String: Any]
    let issuingCountry: String
    let verifiedAt: Date
    let validUntil: Date
    let format: PIDCredentialFormat

    var givenName: String? {
        elements[PIDElement.givenName] as? String
    }

    var familyName: String? {
        elements[PIDElement.familyName] as? String
    }

    var dateOfBirth: Date? {
        elements[PIDElement.birthDate] as? Date
    }

    var portrait: Data? {
        elements[PIDElement.portrait] as? Data
    }

    var isExpired: Bool {
        validUntil < Date()
    }

    var fullName: String {
        [givenName, familyName].compactMap { $0 }.joined(separator: " ")
    }
}
