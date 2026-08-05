import Foundation

// The two credential presentation formats a EUDI Wallet can return in a vp_token.
enum VPTokenFormat {
    case msoMdoc(Data)
    case sdJWT(String)
}

// Detects which of the two formats a raw vp_token payload is in, before any verification
// happens. SD-JWT VC presentations are UTF-8 text shaped like
// "<jwt>~<disclosure>~...~[<kb-jwt>]"; mso_mdoc presentations are raw CBOR bytes that are
// not valid SD-JWT text.
enum VPTokenHandler {
    static func detectFormat(from data: Data) -> VPTokenFormat {
        if let string = String(data: data, encoding: .utf8),
           string.contains("~") || string.hasPrefix("ey") {
            return .sdJWT(string)
        }
        return .msoMdoc(data)
    }
}
