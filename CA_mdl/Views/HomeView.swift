import SwiftUI
import Security

struct HomeView: View {
    @Environment(MdlVerificationSession.self) private var mdlSession
    @State private var pidCoordinator = PIDVerificationCoordinator()

    // One sheet drives every mDL state after idle — unchanged from the original mDL-only flow.
    private var showMDLSheet: Bool {
        if case .idle = mdlSession.state { return false }
        return true
    }

    private var anyVerificationInProgress: Bool {
        showMDLSheet || pidCoordinator.isVerifying
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Spacer()

                // Hero
                VStack(spacing: 16) {
                    ZStack {
                        Circle()
                            .fill(.blue.opacity(0.12))
                            .frame(width: 100, height: 100)
                        Image(systemName: "person.badge.shield.checkmark.fill")
                            .font(.system(size: 44))
                            .foregroundStyle(.blue)
                    }
                    Text("Digital ID Verifier")
                        .font(.largeTitle.bold())
                    Text("Verify a California mobile Driver's License or a European Digital Identity credential.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

                Spacer()

                // Privacy notice
                VStack(spacing: 8) {
                    HStack(spacing: 6) {
                        Image(systemName: "lock.shield.fill").foregroundStyle(.green)
                        Text("No data is stored or transmitted.")
                            .font(.subheadline.weight(.medium))
                    }
                    Text("Verified information is displayed on-screen only and discarded when you leave this session.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .padding(16)
                .background(.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(.green.opacity(0.2)))
                .padding(.horizontal, 24)

                Spacer()

                VStack(spacing: 12) {
                    credentialButton(
                        flag: "🇺🇸",
                        title: "California mDL",
                        subtitle: "CA DMV Wallet",
                        systemImage: "qrcode.viewfinder"
                    ) {
                        mdlSession.startScanning()
                    }

                    credentialButton(
                        flag: "🇪🇺",
                        title: "European Digital ID",
                        subtitle: "eIDAS 2.0 Wallet",
                        systemImage: "person.text.rectangle"
                    ) {
                        Task { await pidCoordinator.startPIDVerification() }
                    }
                }
                .disabled(anyVerificationInProgress)
                .padding(.horizontal, 24)
                .padding(.bottom, 40)
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("Digital ID Verifier").font(.headline)
                }
            }
        }
        .onOpenURL { url in
            pidCoordinator.handleCallback(url)
        }
        .fullScreenCover(isPresented: Binding(get: { showMDLSheet }, set: { if !$0 { mdlSession.reset() } })) {
            SessionFlowView()
                .environment(mdlSession)
        }
        .sheet(isPresented: Binding(
            get: { pidCoordinator.pidResult != nil },
            set: { if !$0 { pidCoordinator.pidResult = nil } }
        )) {
            if let result = pidCoordinator.pidResult {
                PIDResultView(data: result)
            }
        }
        .alert(
            "PID Verification Failed",
            isPresented: Binding(
                get: { pidCoordinator.showPIDError },
                set: { pidCoordinator.showPIDError = $0 }
            )
        ) {
            Button("OK", role: .cancel) { pidCoordinator.pidError = nil }
        } message: {
            Text(pidCoordinator.pidError?.errorDescription ?? "An unknown error occurred.")
        }
    }

    private func credentialButton(
        flag: String,
        title: String,
        subtitle: String,
        systemImage: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 16) {
                Text(flag).font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline)
                    Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: systemImage)
                    .font(.title3)
                    .foregroundStyle(.blue)
            }
            .padding(16)
            .background(.gray.opacity(0.08), in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(.gray.opacity(0.15)))
            .contentShape(RoundedRectangle(cornerRadius: 14))
        }
        .buttonStyle(.plain)
    }
}

// MARK: - PID verification coordinator
//
// Real HomeView.swift originally paired with a HomeViewModel that doesn't exist in this
// codebase; the app's actual convention (see MdlVerificationSession) is an @Observable
// @MainActor class stored via @State, so PID state follows that same pattern instead.
@Observable
@MainActor
final class PIDVerificationCoordinator {
    var pidResult: VerifiedPIDData?
    var pidError: PIDError?
    var showPIDError: Bool = false
    private(set) var isVerifying: Bool = false

    private var pendingNonce: String?

    // Demo relying-party identity. A production deployment registers a real client_id
    // (x509_san_dns or a did:) and a response_uri backed by an actual HTTPS endpoint. The
    // custom-scheme response_uri below only works because this same app also registers and
    // handles that scheme via .onOpenURL, standing in for that backend for a same-device demo.
    private let clientID = "x509_san_dns:verifier.ca-mdl-app.example"
    private let responseURI = "ca-mdl-verifier://openid4vp/callback"

    // TODO(production): the issuing country isn't known until the credential itself is read,
    // but TrustAnchorStore is keyed by country. A single-country pilot can pin an expected
    // country as done here; a general verifier needs a country-selection step, or must try
    // every bundled country's anchors and accept whichever one validates the chain.
    private let expectedCountryCode = "DE"

    func startPIDVerification() async {
        isVerifying = true
        pidError = nil
        let nonce = Self.generateNonce()
        pendingNonce = nonce
        do {
            let builder = PIDRequestBuilder(clientID: clientID, responseURI: responseURI)
            try await builder.launchVerification(nonce: nonce)
        } catch let error as PIDError {
            isVerifying = false
            pidError = error
            showPIDError = true
        } catch {
            isVerifying = false
            pidError = .requestBuildFailed
            showPIDError = true
        }
    }

    func handleCallback(_ url: URL) {
        guard url.scheme == "ca-mdl-verifier",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let vpTokenString = components.queryItems?.first(where: { $0.name == "vp_token" })?.value,
              let nonce = pendingNonce else {
            return
        }
        pendingNonce = nil
        let vpTokenData = Data(vpTokenString.utf8)
        Task {
            do {
                let result = try await PIDVerifier.shared.verify(
                    vpToken: vpTokenData,
                    expectedNonce: nonce,
                    countryCode: expectedCountryCode
                )
                isVerifying = false
                pidResult = result
            } catch let error as PIDError {
                isVerifying = false
                pidError = error
                showPIDError = true
            } catch {
                isVerifying = false
                pidError = .sessionExpired
                showPIDError = true
            }
        }
    }

    private static func generateNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
