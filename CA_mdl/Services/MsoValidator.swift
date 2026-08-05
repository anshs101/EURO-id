import Foundation
import CryptoKit
import SwiftCBOR

// ISO 18013-5 Section 9.1.2 — Mobile Security Object (MSO) verification
// and data element extraction from a DeviceResponse
struct MsoValidator {

    // Full verification pipeline: COSE → MSO → digest checks → data extraction
    static func verify(
        deviceResponseData: Data,
        sessionTranscript: [UInt8]
    ) throws -> MdlDocument {
        let bytes = [UInt8](deviceResponseData)
        guard let response = try? CBOR.decode(bytes) else {
            throw MdlError.invalidDeviceResponse("Cannot decode DeviceResponse CBOR")
        }

        guard let status = response.mapLookup("status")?.uint64Value, status == 0 else {
            let s = response.mapLookup("status")?.uint64Value ?? 99
            throw MdlError.invalidDeviceResponse("Device returned error status \(s)")
        }

        guard let documents = response.mapLookup("documents")?.arrayValue,
              let doc = documents.first else {
            throw MdlError.invalidDeviceResponse("No documents in response")
        }

        guard let docType = doc.mapLookup("docType")?.utf8StringValue,
              docType == IsoMdl.mDLDocType else {
            let dt = doc.mapLookup("docType")?.utf8StringValue ?? "nil"
            throw MdlError.unsupportedDocType(dt)
        }

        guard let issuerSigned = doc.mapLookup("issuerSigned") else {
            throw MdlError.invalidDeviceResponse("Missing issuerSigned")
        }

        // IssuerAuth is a COSE_Sign1
        guard let issuerAuth = issuerSigned.mapLookup("issuerAuth") else {
            throw MdlError.invalidDeviceResponse("Missing issuerAuth")
        }

        // Verify the COSE_Sign1 and extract the MSO payload
        let verified = try CoseVerifier.verify(issuerAuth)

        // Decode MSO from the COSE payload
        guard let mso = try? CBOR.decode(verified.payload) else {
            throw MdlError.invalidDeviceResponse("Cannot decode MSO payload")
        }

        // Validate MSO fields
        guard let msoDocType = mso.mapLookup("docType")?.utf8StringValue,
              msoDocType == IsoMdl.mDLDocType else {
            throw MdlError.invalidDeviceResponse("MSO docType mismatch")
        }

        guard let digestAlgo = mso.mapLookup("digestAlgorithm")?.utf8StringValue,
              digestAlgo == "SHA-256" else {
            throw MdlError.invalidDeviceResponse("Unsupported digest algorithm in MSO")
        }

        // Validity check
        let now = Date()
        var isDocExpired = false
        if let validity = mso.mapLookup("validityInfo") {
            if let validUntil = validity.mapLookup("validUntil")?.dateValue {
                isDocExpired = validUntil < now
            }
        }

        // Collect expected digests from MSO
        guard let valueDigests = mso.mapLookup("valueDigests") else {
            throw MdlError.invalidDeviceResponse("Missing valueDigests in MSO")
        }

        // Verify and extract data elements from IssuerNameSpaces
        guard let nameSpaces = issuerSigned.mapLookup("nameSpaces") else {
            throw MdlError.invalidDeviceResponse("Missing nameSpaces in issuerSigned")
        }

        var allDigestsValid = true
        var elements: [String: CBOR] = [:]

        // Walk every namespace's array of IssuerSignedItemBytes
        if let nsMap = nameSpaces.cborMap {
            for (nsKeyCbor, nsValue) in nsMap {
                guard let nsName = nsKeyCbor.utf8StringValue,
                      let nsDigests = valueDigests.mapLookup(nsName),
                      let items = nsValue.arrayValue else { continue }

                for item in items {
                    // Each item is IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
                    let innerBytes: [UInt8]
                    if case .tagged(let tag, let inner) = item,
                       tag.rawValue == 24,
                       let bytes = inner.byteStringValue {
                        innerBytes = bytes
                    } else if let bytes = item.byteStringValue {
                        innerBytes = bytes
                    } else {
                        continue
                    }

                    // Digest = SHA-256(IssuerSignedItemBytes)
                    let digest = SHA256.hash(data: Data(innerBytes))
                    let digestBytes = Array(digest)

                    guard let signedItem = try? CBOR.decode(innerBytes),
                          let digestID = signedItem.mapLookup("digestID")?.uint64Value,
                          let elementId = signedItem.mapLookup("elementIdentifier")?.utf8StringValue,
                          let elementValue = signedItem.mapLookup("elementValue") else { continue }

                    // Verify against MSO digest
                    if let expectedCbor = nsDigests.mapLookup(Int(digestID)),
                       let expectedBytes = expectedCbor.byteStringValue {
                        if digestBytes != expectedBytes {
                            allDigestsValid = false
                        }
                    } else {
                        allDigestsValid = false
                    }

                    if nsName == IsoMdl.namespace {
                        elements[elementId] = elementValue
                    }
                }
            }
        }

        // Extract data elements into the document model
        return buildDocument(
            elements: elements,
            issuerSubject: verified.issuerSubject,
            isCertTrusted: verified.isCertificateChainTrusted,
            isSigValid: verified.isMsoSignatureValid,
            allDigestsValid: allDigestsValid,
            isDocExpired: isDocExpired
        )
    }

    // MARK: - Data element extraction

    private static func buildDocument(
        elements: [String: CBOR],
        issuerSubject: String,
        isCertTrusted: Bool,
        isSigValid: Bool,
        allDigestsValid: Bool,
        isDocExpired: Bool
    ) -> MdlDocument {
        func str(_ id: String) -> String?  { elements[id]?.utf8StringValue }
        func date(_ id: String) -> Date?   { elements[id]?.dateValue }
        func bool(_ id: String) -> Bool?   { elements[id]?.boolValue }
        func int_(_ id: String) -> Int?    { elements[id]?.intValue }

        let privileges = parseDrivingPrivileges(elements[IsoMdl.Element.drivingPrivileges])
        let sexInt = int_(IsoMdl.Element.sex)
        let sex: Sex? = sexInt.flatMap { Sex(rawValue: $0) }

        var portrait: Data? = nil
        if let portraitBytes = elements[IsoMdl.Element.portrait]?.byteStringValue {
            portrait = Data(portraitBytes)
        }

        return MdlDocument(
            docType: IsoMdl.mDLDocType,
            familyName:        str(IsoMdl.Element.familyName),
            givenName:         str(IsoMdl.Element.givenName),
            birthDate:         date(IsoMdl.Element.birthDate),
            portrait:          portrait,
            documentNumber:    str(IsoMdl.Element.documentNumber),
            issueDate:         date(IsoMdl.Element.issueDate),
            expiryDate:        date(IsoMdl.Element.expiryDate),
            issuingCountry:    str(IsoMdl.Element.issuingCountry),
            issuingAuthority:  str(IsoMdl.Element.issuingAuthority),
            drivingPrivileges: privileges,
            ageOver18:         bool(IsoMdl.Element.ageOver18),
            ageOver21:         bool(IsoMdl.Element.ageOver21),
            ageInYears:        int_(IsoMdl.Element.ageInYears),
            sex:               sex,
            height:            int_(IsoMdl.Element.height),
            weight:            int_(IsoMdl.Element.weight),
            eyeColour:         str(IsoMdl.Element.eyeColour),
            hairColour:        str(IsoMdl.Element.hairColour),
            birthPlace:        str(IsoMdl.Element.birthPlace),
            nationality:       str(IsoMdl.Element.nationality),
            residentAddress:   str(IsoMdl.Element.residentAddress),
            verifiedAt:        Date(),
            issuerCertificateSubject: issuerSubject,
            isCertificateChainTrusted: isCertTrusted,
            isMsoSignatureValid: isSigValid,
            areAllDigestsValid: allDigestsValid
        )
    }

    private static func parseDrivingPrivileges(_ cbor: CBOR?) -> [DrivingPrivilege] {
        guard let arr = cbor?.arrayValue else { return [] }
        return arr.compactMap { item -> DrivingPrivilege? in
            guard let cat = item.mapLookup("vehicle_category_code")?.utf8StringValue else { return nil }
            let codes: [DrivingPrivilege.RestrictionCode] =
                item.mapLookup("codes")?.arrayValue?.compactMap { codeItem -> DrivingPrivilege.RestrictionCode? in
                    guard let code = codeItem.mapLookup("code")?.utf8StringValue else { return nil }
                    return DrivingPrivilege.RestrictionCode(
                        code:  code,
                        sign:  codeItem.mapLookup("sign")?.utf8StringValue,
                        value: codeItem.mapLookup("value")?.utf8StringValue
                    )
                } ?? []
            return DrivingPrivilege(
                vehicleCategory: cat,
                issueDate:  item.mapLookup("issue_date")?.dateValue,
                expiryDate: item.mapLookup("expiry_date")?.dateValue,
                codes:      codes
            )
        }
    }
}
