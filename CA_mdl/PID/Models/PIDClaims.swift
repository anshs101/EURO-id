import Foundation

// eu.europa.ec.eudi.pid.1 — the ARF-defined namespace/vct for the European PID.
enum PIDNamespace {
    static let v1 = "eu.europa.ec.eudi.pid.1"
}

// Data element identifiers shared by both the mso_mdoc and SD-JWT VC PID encodings.
enum PIDElement {
    static let familyName       = "family_name"
    static let givenName        = "given_name"
    static let birthDate        = "birth_date"
    static let portrait         = "portrait"
    static let ageOver18        = "age_over_18"
    static let nationality      = "nationality"
    static let issuingCountry   = "issuing_country"
    static let issuingAuthority = "issuing_authority"
    static let documentNumber   = "document_number"
    static let expiryDate       = "expiry_date"
}
