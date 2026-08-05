import Foundation
import UIKit

// Builds and launches an OpenID4VP same-device authorization request asking a EUDI Wallet
// for the European PID, requesting family_name, given_name, birth_date, and portrait via a
// DCQL query that accepts either credential format (mso_mdoc or SD-JWT VC) the wallet holds.
final class PIDRequestBuilder {
    private let clientID: String
    private let responseURI: String

    init(clientID: String, responseURI: String) {
        self.clientID = clientID
        self.responseURI = responseURI
    }

    func buildRequestURL(nonce: String) throws -> URL {
        guard let dcqlData = try? JSONSerialization.data(withJSONObject: Self.buildDCQLQuery()),
              let dcqlString = String(data: dcqlData, encoding: .utf8) else {
            throw PIDError.requestBuildFailed
        }

        var components = URLComponents()
        components.scheme = "openid4vp"
        components.host = ""
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "response_uri", value: responseURI),
            URLQueryItem(name: "response_type", value: "vp_token"),
            URLQueryItem(name: "response_mode", value: "direct_post"),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "dcql_query", value: dcqlString),
        ]

        guard let url = components.url else {
            throw PIDError.requestBuildFailed
        }
        return url
    }

    @MainActor
    func launchVerification(nonce: String) async throws {
        let url = try buildRequestURL(nonce: nonce)
        guard UIApplication.shared.canOpenURL(url) else {
            throw PIDError.walletNotInstalled
        }
        let opened = await UIApplication.shared.open(url)
        guard opened else {
            throw PIDError.walletNotInstalled
        }
    }

    // MARK: - DCQL query

    // Requests both formats simultaneously (via credential_sets options) so either an
    // mso_mdoc-native or an SD-JWT-VC-native EUDI Wallet can satisfy the request.
    private static func buildDCQLQuery() -> [String: Any] {
        let claimPaths: [[String]] = [
            [PIDElement.familyName],
            [PIDElement.givenName],
            [PIDElement.birthDate],
            [PIDElement.portrait],
        ]

        let mdocClaims = claimPaths.map { ["path": [PIDNamespace.v1] + $0] }
        let sdJwtClaims = claimPaths.map { ["path": $0] }

        let mdocCredential: [String: Any] = [
            "id": "eu_pid_mdoc",
            "format": "mso_mdoc",
            "meta": ["doctype_value": PIDNamespace.v1],
            "claims": mdocClaims,
        ]
        let sdJwtCredential: [String: Any] = [
            "id": "eu_pid_sdjwt",
            "format": "dc+sd-jwt",
            "meta": ["vct_values": [PIDNamespace.v1]],
            "claims": sdJwtClaims,
        ]

        return [
            "credentials": [mdocCredential, sdJwtCredential],
            "credential_sets": [
                [
                    "purpose": "Identity verification",
                    "options": [["eu_pid_mdoc"], ["eu_pid_sdjwt"]],
                ]
            ],
        ]
    }
}
