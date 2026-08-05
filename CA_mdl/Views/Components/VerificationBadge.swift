import SwiftUI

struct VerificationBadge: View {
    enum Status {
        case valid, invalid, warning
    }

    let status: Status
    let label: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: iconName)
                .font(.caption.weight(.semibold))
                .foregroundStyle(color)
            Text(label)
                .font(.caption.weight(.medium))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(color.opacity(0.12), in: Capsule())
        .overlay(Capsule().stroke(color.opacity(0.3), lineWidth: 1))
    }

    private var iconName: String {
        switch status {
        case .valid:   return "checkmark.shield.fill"
        case .invalid: return "xmark.shield.fill"
        case .warning: return "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        switch status {
        case .valid:   return .green
        case .invalid: return .red
        case .warning: return .orange
        }
    }
}

struct AgeAttestation: View {
    let label: String
    let confirmed: Bool?

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(iconColor)
                .font(.title3.weight(.semibold))
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.subheadline.weight(.medium))
                Text(result)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
    }

    private var icon: String {
        switch confirmed {
        case true:  return "checkmark.circle.fill"
        case false: return "xmark.circle.fill"
        case nil:   return "questionmark.circle.fill"
        }
    }

    private var iconColor: Color {
        switch confirmed {
        case true:  return .green
        case false: return .red
        case nil:   return .secondary
        }
    }

    private var result: String {
        switch confirmed {
        case true:  return "Confirmed"
        case false: return "Not confirmed"
        case nil:   return "Not disclosed"
        }
    }
}
