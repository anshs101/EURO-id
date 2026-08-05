import Foundation

// Parses an ETSI TS 119612 Trusted List XML document (the EU LOTL itself, or one of the
// national lists it points to) and extracts issuer certificates for services marked as
// eIDAS PID providers.
//
// NOTE ON SCOPE: eu-lotl.xml is a "list of the lists" — it points to each member state's own
// national TSL via <OtherTSLPointer> rather than containing PID issuer services directly.
// This parser operates on a single TSL-shaped XML document (which is the same schema at
// every level) and extracts <SchemeTerritory> as that document's country code. A full
// production refresh needs to walk eu-lotl.xml's pointers and run this same parser against
// each national list; that pointer-following step is not implemented here. Until it is, the
// bundled fallback in Resources/eu_pid_trust_anchors.json is the real source of truth.
enum TrustedListParser {

    // eIDAS PID service type identifier (ETSI TS 119612 §5.5.1 ServiceTypeIdentifier OID).
    fileprivate static let pidServiceTypeMarker = "0.4.0.194121.1.2"

    // Never throws — malformed or partial XML yields whatever entries were parsed before the
    // failure (possibly none). A bad or truncated fetch must never break trust refresh, since
    // the bundled fallback remains active regardless.
    static func parsePIDCerts(from data: Data) throws -> [TrustAnchorEntry] {
        let delegate = LOTLDelegate()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        _ = parser.parse()
        return delegate.entries
    }
}

private final class LOTLDelegate: NSObject, XMLParserDelegate {
    private(set) var entries: [TrustAnchorEntry] = []

    private var currentText = ""
    private var listTerritory: String?
    private var insideTSPName = false
    private var currentTSPName: String?
    private var currentServiceIsPID = false

    func parser(
        _ parser: XMLParser,
        didStartElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?,
        attributes attributeDict: [String: String]
    ) {
        currentText = ""
        switch elementName {
        case "TSPName":
            insideTSPName = true
        case "TSPService", "ServiceInformation":
            currentServiceIsPID = false
        default:
            break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        currentText += string
    }

    func parser(
        _ parser: XMLParser,
        didEndElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?
    ) {
        let text = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
        defer { currentText = "" }

        switch elementName {
        case "SchemeTerritory":
            if listTerritory == nil, !text.isEmpty { listTerritory = text }
        case "Name":
            if insideTSPName, !text.isEmpty { currentTSPName = text }
        case "TSPName":
            insideTSPName = false
        case "ServiceTypeIdentifier":
            if text.contains(TrustedListParser.pidServiceTypeMarker) {
                currentServiceIsPID = true
            }
        case "X509Certificate":
            guard currentServiceIsPID, !text.isEmpty else { break }
            let entry = TrustAnchorEntry(
                countryCode: listTerritory ?? "EU",
                issuerName: currentTSPName ?? "Unknown Issuer",
                certBase64: text,
                validUntil: Self.farFutureDateString
            )
            entries.append(entry)
        default:
            break
        }
    }

    // The TSL XML doesn't carry a simple per-service expiry string — the real expiry lives
    // in the X.509 certificate itself. This placeholder is deliberately conservative;
    // SecTrust's own notAfter check during chain validation is the authoritative answer.
    private static let farFutureDateString: String = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let tenYearsOut = Calendar(identifier: .gregorian).date(byAdding: .year, value: 10, to: Date()) ?? Date()
        return formatter.string(from: tenYearsOut)
    }()
}
