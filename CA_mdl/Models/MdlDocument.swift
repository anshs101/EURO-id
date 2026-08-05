import Foundation

struct MdlDocument: Sendable {
    let docType: String

    // Core identity
    let familyName: String?
    let givenName: String?
    let birthDate: Date?
    let portrait: Data?

    // License metadata
    let documentNumber: String?
    let issueDate: Date?
    let expiryDate: Date?
    let issuingCountry: String?
    let issuingAuthority: String?

    // Driving privileges
    let drivingPrivileges: [DrivingPrivilege]

    // Age attestations
    let ageOver18: Bool?
    let ageOver21: Bool?
    let ageInYears: Int?

    // Physical description
    let sex: Sex?
    let height: Int?
    let weight: Int?
    let eyeColour: String?
    let hairColour: String?
    let birthPlace: String?
    let nationality: String?
    let residentAddress: String?

    // Verification metadata — never persisted, ephemeral only
    let verifiedAt: Date
    let issuerCertificateSubject: String
    let isCertificateChainTrusted: Bool
    let isMsoSignatureValid: Bool
    let areAllDigestsValid: Bool

    var isFullyVerified: Bool {
        isCertificateChainTrusted && isMsoSignatureValid && areAllDigestsValid
    }

    var isExpired: Bool {
        guard let exp = expiryDate else { return false }
        return exp < Date()
    }

    var formattedName: String {
        [givenName, familyName].compactMap { $0 }.joined(separator: " ")
    }
}

struct DrivingPrivilege: Sendable {
    let vehicleCategory: String
    let issueDate: Date?
    let expiryDate: Date?
    let codes: [RestrictionCode]

    struct RestrictionCode: Sendable {
        let code: String
        let sign: String?
        let value: String?
    }
}

enum Sex: Int, Sendable {
    case notSpecified = 0
    case male = 1
    case female = 2
    case notApplicable = 9

    var displayString: String {
        switch self {
        case .male: return "Male"
        case .female: return "Female"
        case .notSpecified: return "Not Specified"
        case .notApplicable: return "N/A"
        }
    }
}
