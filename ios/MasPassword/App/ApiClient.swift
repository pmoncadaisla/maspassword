import Foundation
import MasPasswordCore

/// Errors surfaced to the UI with actionable messages.
enum ApiClientError: Error, LocalizedError {
    /// 401/403 — token revoked or invalid.
    case unauthorized(String)
    /// Any other non-2xx JSON error from the server.
    case server(status: Int, message: String)
    /// The response was a redirect or an HTML page instead of JSON — the
    /// telltale sign of Cloud IAP (or another SSO proxy) intercepting the
    /// request. Device tokens cannot answer an IAP login page.
    case iapBlocked
    case invalidResponse
    case network(Error)

    var errorDescription: String? {
        switch self {
        case .unauthorized(let message):
            return "Device not authorized: \(message). Re-link from the web app (Settings > Devices)."
        case .server(let status, let message):
            return message.isEmpty ? "Server error (HTTP \(status))" : message
        case .iapBlocked:
            return "The server answered with a login redirect/HTML page instead of JSON. "
                + "It is probably behind Cloud IAP or another SSO proxy, which mobile device "
                + "tokens cannot pass. Expose /api to the app (see ios/README.md, 'IAP caveat')."
        case .invalidResponse:
            return "Unexpected response from the server."
        case .network(let error):
            return "Network error: \(error.localizedDescription)"
        }
    }
}

/// Thin async URLSession wrapper: Bearer device-token auth, no redirect
/// following (a 30x is evidence of an SSO proxy, not something to chase),
/// JSON-or-error handling. Parsing of response bodies lives in
/// MasPasswordCore.ApiModels so it stays unit-tested.
final class ApiClient: NSObject, URLSessionTaskDelegate {

    private let baseURL: URL
    private let token: String
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.httpAdditionalHeaders = ["Accept": "application/json"]
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    init?(serverUrl: String, token: String) {
        guard let url = URL(string: serverUrl), url.scheme?.hasPrefix("http") == true else { return nil }
        self.baseURL = url
        self.token = token
    }

    convenience init?(account: LinkedAccount) {
        self.init(serverUrl: account.serverUrl, token: account.token)
    }

    // MARK: endpoints

    func fetchSession() async throws -> ApiModels.SessionInfo {
        try ApiModels.parseSession(await getString("/api/auth/session"))
    }

    func fetchVaults() async throws -> [ApiModels.VaultSummary] {
        try ApiModels.parseVaults(await getString("/api/vaults"))
    }

    func fetchItems(vaultId: String) async throws -> [ApiModels.EncryptedItem] {
        try ApiModels.parseItems(await getString("/api/vaults/\(vaultId)/items"))
    }

    func fetchVaultKey(vaultId: String) async throws -> String {
        try ApiModels.parseVaultKey(await getString("/api/vaults/\(vaultId)/key"))
    }

    // MARK: plumbing

    /// Refuse redirects so a 302 from an SSO proxy surfaces as the original
    /// status code instead of silently landing on a login page.
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }

    private func getString(_ path: String) async throws -> String {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ApiClientError.network(error)
        }
        guard let http = response as? HTTPURLResponse else { throw ApiClientError.invalidResponse }

        let body = String(data: data, encoding: .utf8) ?? ""
        let contentType = (http.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        let looksLikeHtml = contentType.contains("text/html")
            || body.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("<")

        // IAP / SSO detection: redirects or HTML instead of API JSON.
        if (300...399).contains(http.statusCode) { throw ApiClientError.iapBlocked }
        if looksLikeHtml { throw ApiClientError.iapBlocked }

        guard (200...299).contains(http.statusCode) else {
            let apiError = ApiModels.parseError(body)
            let message = apiError?.message ?? ""
            if http.statusCode == 401 || http.statusCode == 403 {
                throw ApiClientError.unauthorized(message.isEmpty ? "HTTP \(http.statusCode)" : message)
            }
            throw ApiClientError.server(status: http.statusCode, message: message)
        }
        return body
    }
}
