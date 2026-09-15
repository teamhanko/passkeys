package social.ausa.hanko.passkeys

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/**
 * HTTP client for a Hanko Passkey Server.
 *
 * Endpoints (see `spec/passkey-server.yaml`):
 * - POST /{tenant}/registration/initialize  (server-side, X-API-KEY)
 * - POST /{tenant}/registration/finalize    -> { "token": ... }
 * - POST /{tenant}/login/initialize
 * - POST /{tenant}/login/finalize           -> { "token": ... }
 * - GET  /{tenant}/.well-known/jwks.json
 */
class PasskeyServerClient(
    baseUrl: String,
    private val tenantId: String,
    private val apiKey: String? = null,
    client: OkHttpClient? = null,
) {
    private val http: OkHttpClient = client ?: defaultClient()

    private val rootUrl: String = baseUrl.removePathSuffix(tenantId).trimEnd('/')

    companion object {
        private fun defaultClient() = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .build()

        private fun String.removePathSuffix(tenantId: String) =
            if (endsWith("/$tenantId")) {
                removeSuffix("/$tenantId")
            } else {
                this
            }

        private val JSON = "application/json; charset=utf-8".toMediaType()
    }

    /** Returns the raw WebAuthn `publicKey` creation options JSON for passkey registration. */
    fun registrationInitialize(userId: String, identifier: String?): String {
        val body = json("email" to identifier, "userId" to userId)
        return postJson("$rootUrl/$tenantId/registration/initialize", body, authenticated = true)
    }

    /** Posts the WebAuthn attestation response and returns the vendor registration token. */
    fun registrationFinalize(attestationJson: String): String =
        postJson("$rootUrl/$tenantId/registration/finalize", attestationJson, authenticated = false)

    /** Returns the raw WebAuthn assertion options JSON for passkey sign-in. */
    fun loginInitialize(identifier: String?): String {
        val body = json("email" to identifier)
        return postJson("$rootUrl/$tenantId/login/initialize", body, authenticated = false)
    }

    /** Posts the WebAuthn assertion response and returns the session token. */
    fun loginFinalize(assertionJson: String): String =
        postJson("$rootUrl/$tenantId/login/finalize", assertionJson, authenticated = false)

    /** JWKS used to branch on vendor-level token claims. */
    fun jwks(): String = get("$rootUrl/$tenantId/.well-known/jwks.json")

    private fun postJson(url: String, body: String, authenticated: Boolean): String {
        val builder = Request.Builder()
            .url(url)
            .post(body.toRequestBody(JSON))
            .header("Content-Type", "application/json")
        if (authenticated) {
            requireNotNull(apiKey) { "Passkey server API key required for $url" }
            builder.header("X-API-KEY", apiKey)
        }
        return execute(builder.build())
    }

    private fun get(url: String): String = execute(Request.Builder().url(url).get().build())

    private fun execute(request: Request): String {
        http.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw PasskeyServerError(response.code, text)
            }
            return text
        }
    }

    private fun json(vararg fields: Pair<String, String?>): String =
        fields.mapNotNull { (k, v) ->
            val escaped = v?.replace("\\", "\\\\")
                ?.replace("\"", "\\\"")
            escaped?.let { "\"$k\":\"$it\"" }
        }.joinToString(",", "{", "}")
}

class PasskeyServerError(val statusCode: Int, val body: String) :
    Exception("Passkey server error HTTP $statusCode: $body")
