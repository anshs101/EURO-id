import Foundation
import SwiftCBOR

// MARK: - CBOR access helpers

extension CBOR {
    // Integer-keyed map lookup (handles both positive and negative keys)
    func mapLookup(_ key: Int) -> CBOR? {
        guard case .map(let m) = self else { return nil }
        if key >= 0 {
            return m[.unsignedInt(UInt64(key))]
        } else {
            return m[.negativeInt(UInt64(-1 - key))]
        }
    }

    // String-keyed map lookup
    func mapLookup(_ key: String) -> CBOR? {
        guard case .map(let m) = self else { return nil }
        return m[.utf8String(key)]
    }

    // Access the underlying ordered map as array of pairs (preserves SwiftCBOR structure)
    var cborMap: [(CBOR, CBOR)]? {
        if case .map(let m) = self { return m.map { ($0.key, $0.value) } }
        return nil
    }

    var utf8StringValue: String? {
        if case .utf8String(let s) = self { return s }
        return nil
    }

    var uint64Value: UInt64? {
        if case .unsignedInt(let n) = self { return n }
        return nil
    }

    var intValue: Int? {
        if case .unsignedInt(let n) = self { return Int(n) }
        if case .negativeInt(let n) = self { return -1 - Int(n) }
        return nil
    }

    var boolValue: Bool? {
        if case .boolean(let b) = self { return b }
        return nil
    }

    var byteStringValue: [UInt8]? {
        if case .byteString(let b) = self { return b }
        return nil
    }

    var arrayValue: [CBOR]? {
        if case .array(let a) = self { return a }
        return nil
    }

    // Tag-24: bstr .cbor <inner CBOR>
    var tag24Content: CBOR? {
        guard case .tagged(let tag, let inner) = self, tag.rawValue == 24 else { return nil }
        if let bytes = inner.byteStringValue {
            return try? CBOR.decode(bytes)
        }
        return nil
    }

    // Date from tdate (tag 1004) or full-date string or datetime string
    var dateValue: Date? {
        if case .tagged(let tag, let inner) = self {
            switch tag.rawValue {
            case 1004:  // full-date
                return inner.utf8StringValue.flatMap { DateFormatter.isoDate.date(from: $0) }
            case 0:     // date-time string
                return inner.utf8StringValue.flatMap { ISO8601DateFormatter().date(from: $0) }
            default: break
            }
        }
        if let s = utf8StringValue {
            return DateFormatter.isoDate.date(from: s) ?? ISO8601DateFormatter().date(from: s)
        }
        return nil
    }
}

// MARK: - Encoding helpers

extension CBOR {
    // Wrap a byte array in a tag-24 (bstr .cbor)
    static func tag24(_ bytes: [UInt8]) -> CBOR {
        .tagged(CBOR.Tag(rawValue: 24), .byteString(bytes))
    }
}

// Encode a CBOR value to raw bytes using SwiftCBOR
func cborEncode(_ cbor: CBOR) -> [UInt8] {
    cbor.encode()
}

// MARK: - Date formatters

extension DateFormatter {
    static let isoDate: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(abbreviation: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    static let displayDate: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .long
        f.timeStyle = .none
        return f
    }()
}

// MARK: - UInt32 big-endian bytes

extension UInt32 {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian) { Array($0) }
    }
}
