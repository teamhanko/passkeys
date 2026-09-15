import Foundation

/// Errors surfaced by HankoPasskeyKit.
public struct HankoError: Error, LocalizedError {
    public enum Kind {
        case server(statusCode: Int)
        case network(String)
        case missingField(String)
    }

    public let kind: Kind
    public let message: String

    public var errorDescription: String? {
        switch kind {
        case .server(let code): "Passkey server error (HTTP \(code)): \(message)"
        case .network: "Network error: \(message)"
        case .missingField: "Missing field in server response: \(message)"
        }
    }
}

/// A network client for a Hanko Passkey Server, using the WebAuthn JSON
/// serialization. Registration initialize is authenticated server-side with
/// an API key; finalize and both login calls are unauthenticated.
public final class HankoPasskeyServer: Sendable {
    public let baseURL: URL
    public let tenantID: String
    public let apiKey: String?

    private var rootURL: URL {
        baseURL.deletingLastPathComponent()
    }

    public init(baseURL: URL, tenantID: String, apiKey: String? = nil) {
        self.baseURL = baseURL
        self.tenantID = tenantID
        self.apiKey = apiKey
    }

    /// POST /{tenant}/registration/initialize
    public func registrationInitialize(userId: String, identifier: String?) async throws -> String {
        var fields: [String: String] = ["userId": userId]
        if let identifier {
            fields["identifier"] = identifier
        }
        let body = try await post(path: "registration/initialize",
                                  body: fieldsJSON(fields),
                                  authenticated: true)
        return body
    }

    /// POST /{tenant}/registration/finalize
    public func registrationFinalize(attestationJSON: String) async throws -> String {
        try await postRaw(path: "registration/finalize", body: attestationJSON, authenticated: false)
    }

    /// POST /{tenant}/login/initialize
    public func loginInitialize(identifier: String?) async throws -> String {
        let fields: [String: String] = identifier.map { ["email": $0] } ?? [:]
        return try await post(path: "login/initialize", body: fieldsJSON(fields), authenticated: false)
    }

    /// POST /{tenant}/login/finalize
    public func loginFinalize(assertionJSON: String) async throws -> String {
        try await postRaw(path: "login/finalize", body: assertionJSON, authenticated: false)
    }

    /// GET /{tenant}/.well-known/jwks.json
    public func jwks() async throws -> String {
        try await get(path: ".well-known/jwks.json")
    }

    private func endpoint(_ path: String) -> URL {
        var path = path
        if !tenantID.isEmpty && !path.hasPrefix(tenantID + "/") {
            path = tenantID + "/" + path
        }
        return rootURL.appendingPathComponent(path)
    }

    private func fieldsJSON(_ fields: [String: String]) -> String {
        let pairs = fields.map { "\"\($0)\":\"\($1)\"" }.joined(separator: ",")
        return "{\(pairs)}"
    }

    private func post(path: String, body: String, authenticated: Bool) async throws -> String {
        try await postRaw(path: path, body: body, authenticated: authenticated)
    }

    private func postRaw(path: String, body: String, authenticated: Bool) async throws -> String {
        var request = URLRequest(url: endpoint(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let data = body.data(using: .utf8) ?? Data()
        request.httpBody = data
        if authenticated {
            guard let apiKey else {
                throw HankoError(kind: .missingField("apiKey"), message: "An API key is required to initialize registration")
            }
            request.setValue(apiKey, forHTTPHeaderField: "X-API-KEY")
        }
        return try await send(request)
    }

    private func get(path: String) async throws -> String {
        try await send(URLRequest(url: endpoint(path)))
    }

    private func send(_ request: URLRequest) async throws -> String {
        let (data, response) = try await performRequest(request)
        guard let http = response as? HTTPURLResponse else {
            throw HankoError(kind: .network("not an HTTP response"), message: "")
        }
        let text = String(data: data, encoding: .utf8) ?? ""
        guard (200..<300).contains(http.statusCode) else {
            throw HankoError(kind: .server(statusCode: http.statusCode), message: text)
        }
        return text
    }

    private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await URLSession.shared.data(for: request)
        } catch {
            throw HankoError(kind: .network(error.localizedDescription), message: "")
        }
    }
}
