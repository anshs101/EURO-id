import SwiftUI

struct PIDResultView: View {
    let data: VerifiedPIDData
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                if let portrait = data.portrait, let uiImage = UIImage(data: portrait) {
                    Section("Photo") {
                        Image(uiImage: uiImage)
                            .resizable()
                            .scaledToFit()
                            .frame(height: 160)
                            .frame(maxWidth: .infinity)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }

                Section("Identity") {
                    LabeledContent("Given Name", value: data.givenName ?? "—")
                    LabeledContent("Family Name", value: data.familyName ?? "—")
                    LabeledContent(
                        "Date of Birth",
                        value: data.dateOfBirth.map { DateFormatter.displayDate.string(from: $0) } ?? "—"
                    )
                }

                Section("Credential Info") {
                    LabeledContent("Issuing Country", value: data.issuingCountry)
                    LabeledContent("Format", value: formatLabel)
                    LabeledContent("Valid Until", value: DateFormatter.displayDate.string(from: data.validUntil))
                }

                Section("Verification") {
                    Label("eIDAS 2.0 Verified", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                    Label("EU Trust List Validated", systemImage: "lock.shield.fill")
                        .foregroundStyle(.blue)
                    LabeledContent("Verified At", value: DateFormatter.displayDate.string(from: data.verifiedAt))
                }
            }
            .navigationTitle("European Digital ID")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .privacyScreenProtected()
    }

    private var formatLabel: String {
        switch data.format {
        case .msoMdoc: return "ISO 18013-5 mso_mdoc"
        case .sdJWT: return "SD-JWT VC"
        }
    }
}

// MARK: - Privacy screen protection
//
// There is no PrivacyOverlayView / .privacyScreenProtected() modifier in this codebase to
// reuse, so this covers the same need directly: hide the portrait/name/DOB from the iOS App
// Switcher snapshot by overlaying an opaque blur whenever the scene isn't active.
private struct PrivacyScreenModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content.overlay {
            if scenePhase != .active {
                Rectangle()
                    .fill(.regularMaterial)
                    .ignoresSafeArea()
            }
        }
    }
}

private extension View {
    func privacyScreenProtected() -> some View {
        modifier(PrivacyScreenModifier())
    }
}
