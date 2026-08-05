import Foundation
import Security

struct TrustAnchorEntry: Codable {
    let countryCode: String
    let issuerName: String
    let certBase64: String
    let validUntil: String
}

// In-memory-only store of per-country EU PID issuer trust anchors, keyed by ISO 3166-1
// alpha-2 country code. Never persisted to disk in any form — certificates live only for the
// lifetime of the process. Populated at launch from the bundled fallback list and refreshed
// periodically from the EU LOTL by EUTrustedListManager. Actor isolation is what makes
// concurrent reads (during verification) and writes (during a background refresh) safe.
actor TrustAnchorStore {
    static let shared = TrustAnchorStore()

    private var anchorsByCountry: [String: [SecCertificate]] = [:]
    private var lastRefreshedAt: Date?

    private static let refreshInterval: TimeInterval = 24 * 60 * 60

    init() {}

    // `bundle` defaults to `.main` for production use; unit tests pass the test bundle so
    // they can load a fixture without touching the app's bundled trust list.
    func loadBundledFallback(bundle: Bundle = .main) throws {
        guard let url = bundle.url(forResource: "eu_pid_trust_anchors", withExtension: "json") else {
            throw PIDError.trustListUnavailable
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw PIDError.trustListUnavailable
        }

        struct BundledFile: Decodable {
            let anchors: [TrustAnchorEntry]
        }

        let decoded: BundledFile
        do {
            decoded = try JSONDecoder().decode(BundledFile.self, from: data)
        } catch {
            throw PIDError.trustListUnavailable
        }

        anchorsByCountry = Self.buildCertMap(from: decoded.anchors)
    }

    func update(with entries: [TrustAnchorEntry]) async {
        anchorsByCountry = Self.buildCertMap(from: entries)
    }

    func certsForCountry(_ code: String) -> [SecCertificate] {
        anchorsByCountry[code.uppercased()] ?? []
    }

    func shouldRefresh() -> Bool {
        guard let last = lastRefreshedAt else { return true }
        return Date().timeIntervalSince(last) > Self.refreshInterval
    }

    func markRefreshed() {
        lastRefreshedAt = Date()
    }

    // MARK: - Private

    private static func buildCertMap(from entries: [TrustAnchorEntry]) -> [String: [SecCertificate]] {
        var map: [String: [SecCertificate]] = [:]
        for entry in entries {
            // Skip malformed entries rather than failing the whole trust list — one bad
            // entry from a national list should not take down every other country's trust.
            guard let der = Data(base64Encoded: entry.certBase64),
                  let cert = SecCertificateCreateWithData(nil, der as CFData) else {
                continue
            }
            map[entry.countryCode.uppercased(), default: []].append(cert)
        }
        return map
    }
}
