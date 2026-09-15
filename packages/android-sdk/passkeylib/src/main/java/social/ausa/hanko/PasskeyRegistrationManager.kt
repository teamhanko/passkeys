package social.ausa.hanko.passkeys

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import org.json.JSONObject

/**
 * High-level Android passkey UI flow on top of androidx Credential Manager.
 *
 * Wraps the Hanko passkey server responses (which follow the WebAuthn JSON
 * serialization) into Credential Manager requests and returns the raw WebAuthn
 * JSON the finalize endpoints accept.
 */
class PasskeyRegistrationManager(context: Context) {
    private val credentialManager = CredentialManager.create(context.applicationContext)
    private val appContext = context.applicationContext

    /** Wraps raw creation options from a Hanko server into a Credential Manager request. */
    fun creationRequest(rawCreateOptions: String): CreatePublicKeyCredentialRequest {
        val requestJson = unwrapOptions(rawCreateOptions)
            ?: throw IllegalStateException("Missing 'publicKey' credential creation options in server response")
        return CreatePublicKeyCredentialRequest(requestJson)
    }

    suspend fun register(request: CreatePublicKeyCredentialRequest): String {
        val response = credentialManager.createCredential(appContext, request)
        check(response is CreatePublicKeyCredentialResponse) {
            "Unexpected create response type: ${response::class.java.simpleName}"
        }
        return response.registrationResponseJson
    }

    /** Wraps raw assertion options from a Hanko server into a Credential Manager option. */
    fun assertionOption(rawAssertionOptions: String): GetPublicKeyCredentialOption {
        val requestJson = unwrapOptions(rawAssertionOptions)
            ?: throw IllegalStateException("Missing 'publicKey' credential assertion options in server response")
        return GetPublicKeyCredentialOption(requestJson = requestJson)
    }

    suspend fun sign(option: GetPublicKeyCredentialOption): String {
        val response = credentialManager.getCredential(
            appContext,
            GetCredentialRequest(listOf(option)),
        )
        val credential = response.credential
        check(credential is PublicKeyCredential) {
            "Unexpected credential type: ${credential.type}"
        }
        // PublicKeyCredential may carry either the assertion, depending on flow
        // shape and library version.
        return credential.authenticationResponseJson
            .ifEmpty { throw IllegalStateException("Credential bundle contained no WebAuthn assertion JSON") }
    }

    private fun unwrapOptions(raw: String): String? {
        val root = JSONObject(raw)
        val publicKey = root.optJSONObject("publicKey")
        // Credential Manager consumes the WebAuthn JSON directly; the Hanko
        // server returns it wrapped in a single-element CreatePublicKeyCredentialRequest
        // payload when clients ask for raw WebAuthn, so handle both.
        return (publicKey ?: rawOptionsIfAlreadyTopLevel(root))?.toString()
    }

    private fun rawOptionsIfAlreadyTopLevel(root: JSONObject): JSONObject? =
        if (root.has("rp") && root.has("challenge")) root else null
}
