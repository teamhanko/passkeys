import { type CredentialRequestOptionsJSON, get } from "@github/webauthn-json";
import { type JWTPayload } from "jose";
import { signIn } from "next-auth/react";
import { DEFAULT_PROVIDER_ID } from ".";

const headers = { "Content-Type": "application/json" };

interface Common {
	mediation?: CredentialRequestOptionsJSON["mediation"];
	signal?: AbortSignal;
}

interface SignInConfig extends Common {
	tenantId: string;

	baseUrl?: string;
	provider?: string;
	callbackUrl?: string;
	redirect?: boolean;
}

interface ClientFirstLoginConfig extends Common {
	baseUrl?: string;
	tenantId: string;
}

/**
 * Sign in with a passkey. Requires `PasskeyProvider` to be configured in `pages/api/auth/[...nextauth].ts`
 */
export async function signInWithPasskey(config: SignInConfig) {
	const finalizeJWT = await clientFirstPasskeyLogin(config);

	await signIn(config.provider ?? DEFAULT_PROVIDER_ID, {
		finalizeJWT,
		callbackUrl: config.callbackUrl,
		redirect: config.redirect,
	});
}

signInWithPasskey.autofill = async function (config: SignInConfig, signal?: AbortSignal) {
	return signInWithPasskey({
		...config,
		mediation: "conditional",
	});
};

/**
 * You likely want to use {@link signInWithPasskey} instead.
 *
 * This method runs the ["Client-First Login Flow"]() triggers the "select passkey" dialog and returns a JWT signed by the Hanko Passkey API.
 *
 * @returns a JWT that can be exchanged for a session on the backend.
 *          To verify the JWT, use the JWKS endpoint of the tenant. (`{tenantId}/.well-known/jwks.json`)
 */
export async function clientFirstPasskeyLogin(config: ClientFirstLoginConfig): Promise<JWTPayload> {
	const baseUrl = config.baseUrl ?? "https://passkeys.hanko.io";

	const loginOptions = await fetch(new URL(`${config.tenantId}/login/initialize`, baseUrl), {
		method: "POST",
		headers,
	}).then((res) => res.json());

	if (config.mediation) {
		loginOptions.mediation = config.mediation;
	}

	if (config.signal) {
		loginOptions.signal = config.signal;
	}

	// Open "select passkey" dialog
	const credential = await get(loginOptions);

	// User selected a passkey to use.
	//
	// The returned `credential` object needs to be sent back to the
	// Passkey API as-is.
	return fetch(new URL(`${config.tenantId}/login/finalize`, baseUrl), {
		method: "POST",
		headers,
		body: JSON.stringify(credential),
	})
		.then((res) => res.json())
		.then((data) => {
			if (!data?.token) {
				throw new Error("Passkey API did not return any token");
			}
			return data.token;
		});
}
