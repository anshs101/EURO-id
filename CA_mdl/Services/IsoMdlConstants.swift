import Foundation
import CoreBluetooth

// ISO 18013-5 constants and namespace identifiers
enum IsoMdl {
    static let mDLDocType  = "org.iso.18013.5.1.mDL"
    static let namespace   = "org.iso.18013.5.1"
    static let version     = "1.0"

    // BLE service / characteristic UUIDs (ISO 18013-5 Annex B, Table B.1)
    enum BLE {
        // Peripheral Server mode: holder advertises, verifier is central
        static let peripheralServerService = CBUUID(string: "00000001-A123-48CE-896B-4C76973373E6")
        static let stateChar               = CBUUID(string: "00000005-A123-48CE-896B-4C76973373E6")
        static let client2ServerChar       = CBUUID(string: "00000006-A123-48CE-896B-4C76973373E6")
        static let server2ClientChar       = CBUUID(string: "00000007-A123-48CE-896B-4C76973373E6")
        static let identChar               = CBUUID(string: "00000008-A123-48CE-896B-4C76973373E6")

        // State bytes
        static let stateStart: UInt8 = 0x01
        static let stateEnd:   UInt8 = 0x02

        // BLE data framing: first byte of each chunk
        static let frameMore: UInt8 = 0x01  // more chunks follow
        static let frameLast: UInt8 = 0x00  // last chunk

        // Maximum bytes of payload per write (conservative; actual MTU negotiated at runtime)
        static let defaultMaxChunk = 512
    }

    // Data element identifiers in the org.iso.18013.5.1 namespace
    enum Element {
        static let familyName       = "family_name"
        static let givenName        = "given_name"
        static let birthDate        = "birth_date"
        static let issueDate        = "issue_date"
        static let expiryDate       = "expiry_date"
        static let issuingCountry   = "issuing_country"
        static let issuingAuthority = "issuing_authority"
        static let documentNumber   = "document_number"
        static let portrait         = "portrait"
        static let drivingPrivileges = "driving_privileges"
        static let sex              = "sex"
        static let height           = "height"
        static let weight           = "weight"
        static let eyeColour        = "eye_colour"
        static let hairColour       = "hair_colour"
        static let birthPlace       = "birth_place"
        static let nationality      = "nationality"
        static let residentAddress  = "resident_address"
        static let ageInYears       = "age_in_years"
        static let ageOver18        = "age_over_18"
        static let ageOver21        = "age_over_21"
    }
}
