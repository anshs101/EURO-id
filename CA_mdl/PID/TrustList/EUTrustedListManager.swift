import Foundation

// Periodically refreshes TrustAnchorStore from the EU List of Trusted Lists. Any failure
// (network or parse) is logged and swallowed — the bundled fallback trust list stays active,
// so a flaky connection never blocks verification.
actor EUTrustedListManager {
    static let shared = EUTrustedListManager()

    private static let lotlURL = URL(string: "https://ec.europa.eu/tools/lotl/eu-lotl.xml")!
    private static let refreshInterval: TimeInterval = 24 * 60 * 60

    private var refreshLoopTask: Task<Void, Never>?

    private init() {}

    func refresh() async {
        do {
            let (data, response) = try await URLSession.shared.data(from: Self.lotlURL)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                print("EUTrustedListManager: LOTL fetch returned a non-2xx status; keeping bundled fallback")
                return
            }
            let entries = try await TrustedListParser.parsePIDCerts(from: data)
            guard !entries.isEmpty else {
                print("EUTrustedListManager: LOTL parse yielded no PID entries; keeping bundled fallback")
                return
            }
            await TrustAnchorStore.shared.update(with: entries)
            await TrustAnchorStore.shared.markRefreshed()
        } catch {
            print("EUTrustedListManager: refresh failed (\(error.localizedDescription)); keeping bundled fallback")
        }
    }

    func startPeriodicRefresh() {
        guard refreshLoopTask == nil else { return }
        refreshLoopTask = Task.detached(priority: .background) { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.refresh()
                try? await Task.sleep(nanoseconds: UInt64(Self.refreshInterval * 1_000_000_000))
            }
        }
    }
}
