import Foundation

// Single entry point for European PID verification: detects the vp_token's credential
// format and routes to the matching verifier.
actor PIDVerifier {
    static let shared = PIDVerifier()

    private let mdocVerifier = MsoMdocPIDVerifier()
    private let sdJwtVerifier = SDJWTVerifier()

    private init() {}

    func verify(vpToken: Data, expectedNonce: String, countryCode: String) async throws -> VerifiedPIDData {
        switch await VPTokenHandler.detectFormat(from: vpToken) {
        case .msoMdoc(let cborData):
            return try await mdocVerifier.verify(cborData: cborData, expectedNonce: expectedNonce, countryCode: countryCode)
        case .sdJWT(let jwtString):
            return try await sdJwtVerifier.verify(sdJwtString: jwtString, expectedNonce: expectedNonce, countryCode: countryCode)
        }
    }
}
