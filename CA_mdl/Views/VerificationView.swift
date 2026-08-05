import SwiftUI

struct VerificationView: View {
    let document: MdlDocument
    @Environment(MdlVerificationSession.self) private var session
    @Environment(\.dismiss) private var dismiss
    @State private var showPortrait = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // Trust header
                    trustHeader

                    // Portrait + name card
                    identityCard

                    // Age attestations
                    ageCard

                    // License info
                    licenseCard

                    // Driving privileges
                    if !document.drivingPrivileges.isEmpty {
                        privilegesCard
                    }

                    // Physical description
                    if hasPhysicalDetails {
                        physicalCard
                    }

                    // Verification metadata
                    metadataCard

                    // Privacy notice
                    privacyNotice
                }
                .padding(16)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Verification Result")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        session.reset()
                        dismiss()
                    }
                    .fontWeight(.semibold)
                }
            }
        }
    }

    // MARK: - Sub-views

    private var trustHeader: some View {
        HStack(spacing: 12) {
            Image(systemName: document.isFullyVerified ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.largeTitle)
                .foregroundStyle(document.isFullyVerified ? .green : .orange)
            VStack(alignment: .leading, spacing: 4) {
                Text(document.isFullyVerified ? "Verified" : "Verification Issues")
                    .font(.title2.bold())
                Text(document.isExpired ? "Document is expired" : document.issuingAuthority ?? "CA DMV")
                    .font(.subheadline)
                    .foregroundStyle(document.isExpired ? .red : .secondary)
            }
            Spacer()
        }
        .padding(16)
        .background(
            (document.isFullyVerified && !document.isExpired) ? Color.green.opacity(0.1) : Color.orange.opacity(0.1),
            in: RoundedRectangle(cornerRadius: 14)
        )
    }

    private var identityCard: some View {
        SectionCard(title: "Identity", systemImage: "person.crop.circle") {
            HStack(alignment: .top, spacing: 16) {
                portraitThumbnail
                VStack(alignment: .leading, spacing: 6) {
                    Text(document.formattedName.isEmpty ? "—" : document.formattedName)
                        .font(.title3.bold())
                    if let dob = document.birthDate {
                        Label(DateFormatter.displayDate.string(from: dob), systemImage: "calendar")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    if let years = document.ageInYears {
                        Text("Age \(years)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var portraitThumbnail: some View {
        if let data = document.portrait, let img = UIImage(data: data) {
            Image(uiImage: img)
                .resizable()
                .scaledToFill()
                .frame(width: 72, height: 90)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .onTapGesture { showPortrait = true }
                .sheet(isPresented: $showPortrait) {
                    PortraitFullView(image: img)
                }
        } else {
            RoundedRectangle(cornerRadius: 8)
                .fill(.quaternary)
                .frame(width: 72, height: 90)
                .overlay(Image(systemName: "person.crop.square").foregroundStyle(.tertiary))
        }
    }

    private var ageCard: some View {
        SectionCard(title: "Age Attestation", systemImage: "person.badge.clock") {
            HStack(spacing: 12) {
                AgeAttestation(label: "Age 18+", confirmed: document.ageOver18)
                AgeAttestation(label: "Age 21+", confirmed: document.ageOver21)
            }
        }
    }

    private var licenseCard: some View {
        SectionCard(title: "License", systemImage: "car.badge.checkmark") {
            VStack(spacing: 6) {
                if let num = document.documentNumber {
                    FieldRow(label: "Document No.", value: num)
                    Divider()
                }
                if let issue = document.issueDate {
                    FieldRow(label: "Issued", value: DateFormatter.displayDate.string(from: issue))
                    Divider()
                }
                if let exp = document.expiryDate {
                    FieldRow(label: "Expires", value: DateFormatter.displayDate.string(from: exp))
                        .foregroundStyle(document.isExpired ? .red : .primary)
                    Divider()
                }
                if let country = document.issuingCountry {
                    FieldRow(label: "Issuing Country", value: country)
                    Divider()
                }
                if let auth = document.issuingAuthority {
                    FieldRow(label: "Issuing Authority", value: auth)
                }
            }
        }
    }

    private var privilegesCard: some View {
        SectionCard(title: "Driving Privileges", systemImage: "steeringwheel") {
            VStack(spacing: 8) {
                ForEach(document.drivingPrivileges.indices, id: \.self) { i in
                    let priv = document.drivingPrivileges[i]
                    HStack {
                        Text("Class \(priv.vehicleCategory)")
                            .font(.subheadline.weight(.semibold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(.blue.opacity(0.1), in: Capsule())
                        Spacer()
                        if let exp = priv.expiryDate {
                            Text("Exp: \(DateFormatter.displayDate.string(from: exp))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if !priv.codes.isEmpty {
                        Text(priv.codes.map(\.code).joined(separator: ", "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if i < document.drivingPrivileges.count - 1 { Divider() }
                }
            }
        }
    }

    private var hasPhysicalDetails: Bool {
        document.sex != nil || document.height != nil ||
        document.eyeColour != nil || document.hairColour != nil
    }

    private var physicalCard: some View {
        SectionCard(title: "Physical Description", systemImage: "figure.stand") {
            VStack(spacing: 6) {
                if let sex = document.sex {
                    FieldRow(label: "Sex", value: sex.displayString); Divider()
                }
                if let h = document.height {
                    FieldRow(label: "Height", value: "\(h) cm"); Divider()
                }
                if let eye = document.eyeColour {
                    FieldRow(label: "Eye Colour", value: eye.capitalized); Divider()
                }
                if let hair = document.hairColour {
                    FieldRow(label: "Hair Colour", value: hair.capitalized)
                }
            }
        }
    }

    private var metadataCard: some View {
        SectionCard(title: "Verification Details", systemImage: "lock.shield") {
            VStack(alignment: .leading, spacing: 8) {
                VerificationBadge(
                    status: document.isCertificateChainTrusted ? .valid : .invalid,
                    label: document.isCertificateChainTrusted ? "CA DMV Certificate Trusted" : "Certificate Chain Invalid"
                )
                VerificationBadge(
                    status: document.isMsoSignatureValid ? .valid : .invalid,
                    label: document.isMsoSignatureValid ? "MSO Signature Valid" : "MSO Signature Invalid"
                )
                VerificationBadge(
                    status: document.areAllDigestsValid ? .valid : .invalid,
                    label: document.areAllDigestsValid ? "All Data Digests Match" : "Digest Mismatch Detected"
                )
                VerificationBadge(
                    status: document.isExpired ? .invalid : .valid,
                    label: document.isExpired ? "Document Expired" : "Document Not Expired"
                )
                Divider()
                FieldRow(label: "Issuer Cert", value: document.issuerCertificateSubject)
                FieldRow(label: "Verified At", value: {
                    let f = DateFormatter()
                    f.dateStyle = .short
                    f.timeStyle = .medium
                    return f.string(from: document.verifiedAt)
                }())
            }
        }
    }

    private var privacyNotice: some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.shield.fill")
                .foregroundStyle(.green)
            Text("This data has not been stored or transmitted. It will be discarded when you close this screen.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
        .background(.green.opacity(0.07), in: RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Portrait full-screen view

struct PortraitFullView: View {
    let image: UIImage
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .padding()
                .navigationTitle("Portrait")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close") { dismiss() }
                    }
                }
        }
    }
}
