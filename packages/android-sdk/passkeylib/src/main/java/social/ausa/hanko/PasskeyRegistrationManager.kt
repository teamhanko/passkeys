package social.ausa.hanko.passkeys

import android.content.Context
import androidx.credentials.CreateCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.PublicKeyCredential
import androidx.credentials.CustomCredential
import androidx.credentials.provider.CreateCredentialException
import androidx.credentials.CreateCredentialRequest.Companion.createPublicKeyCredential
import androidx.credentials.GetCredentialRequest.Companion.getCredentialRequest
import org.json.JSONObject

/**
 * High-level Android passkey UI flow on top of androidx Credential Manager.
 *
 * Wraps the Hanko passkey server responses (which follow the WebAuthn JSON
 * serialization) into Credential Manager requests and mirrors the platform
 * results back into the JSON bodies the finalize endpoints accept.
 */
class PasskeyRegistrationManager(mContext: Context) {
    private val credentialManager = CredentialManager.create(mContext)
    private val context: Context = mContext.applicationContext

    /** Wraps raw creation options from a Hanko server into a Credential Manager request. */
    fun creationRequest(rawCreateOptions: String): CreatePublicKeyCredentialRequest =
        CreatePublicKeyCredentialRequest(rawCredentialOptions(rawCreateOptions))

    suspend fun register(request: CreatePublicKeyCredentialRequest): String {
        val response = credentialManager.createCredential(
            request = request,
            context = context,
        )
        return extractCredentialJson(response.credential)
    }

    /** Wraps raw assertion options from a Hanko server into a Credential Manager request. */
    fun assertionRequest(rawAssertionOptions: String): GetPublicKeyCredentialOption =
        GetPublicKeyCredentialOption(rawCredentialOptions(rawAssertionOptions))

    suspend fun login(request: GetPublicKeyCredentialOption): String {
        val response = credentialManager.getCredential(
            context = context,
            request = GetCredentialRequest(listOf(request)),
        )
        return extractCredentialJson(response.credential)
    }

    private fun rawCredentialOptions(raw: String): String {
        @Suppress("SameValueUsage")
        val root = JSONObject(raw).optJSONObject("publicKey")
            ?: throw IllegalStateException("Missing 'publicKey' credential options in server response")
        return root.toString()
    }

    private fun extractCredentialJson(credential: androidx.credentials.Credential): String {
        require(credential is PublicKeyCredential) {
            "Unexpected credential type: ${credential.type}"
        }
        // Credential Manager exposes `authenticationResponseJson` /
        // `registrationResponseJson` on PublicKeyCredential subclasses.
        return when (credential) {
            is CustomCredential -> credential.data.getString("authenticationResponseJson")
                ?: credential.data.getString("registrationResponseJson")
                ?: error("No WebAuthn JSON in credential bundle")
            else -> error("Unsupported credential bundle")
        }
    }
}
