import { Tenant } from "@teamhanko/passkeys-sdk";
import { JWTPayload, JWTVerifyResult, createRemoteJWKSet, jwtVerify } from "jose";
import Credentials, { CredentialsConfig } from "next-auth/providers/credentials";
import { Provider } from "next-auth/providers/index";

export * from "@teamhanko/passkeys-sdk";

const TOKEN_MAX_AGE_SECONDS = 60;
export const DEFAULT_PROVIDER_ID = "passkeys";

export class PasskeyProviderError extends Error {
	constructor(message: string, public readonly code: ErrorCode, public originalError?: unknown) {
		super(message);
	}
}

export enum ErrorCode {
	JWTSubClaimMissing = "jwtSubClaimMissing",
	JWTVerificationFailed = "jwtVerificationFailed",
	JWTExpired = "jwtExpired",
}

// TODO in future versions, remove `export const PasskeyProvider/Passkeys` and make this `export default function Passkeys`
//      this is only named this way so we can export both the legacy (PasskeyProvider) and new (Passkeys) variable names
function createPasskeyProvider({
	tenant,
	authorize: authorize,
	id = DEFAULT_PROVIDER_ID,
}: {
	tenant: Tenant;
	/**
	 * Called after the JWT has been verified. The passed-in `userId` is the value of the `sub` claim of the JWT.
	 *
	 * The `userId` can safely be used to log the user in, e.g.:
	 *
	 * @example
	 * async function authorize({ userId }) {
	 *     const user = await db.users.find(userId);
	 *
	 *     if (!user) return null;
	 *
	 *     return user;
	 * }
	 */
	authorize?: (data: { userId: string; token: JWTPayload }) => any;
	id?: string;
}) {
	const url = new URL(`${tenant.config.tenantId}/.well-known/jwks.json`, tenant.config.baseUrl);
	const JWKS = createRemoteJWKSet(url);

	// TODO call normally when this is fixed: https://github.com/nextauthjs/next-auth/issues/572
	return {
		id,
		name: "Passkeys",
		type: "credentials",
		credentials: {
			/**
			 * Token returned by `passkeyApi.login.finalize()`
			 */
			finalizeJWT: {
				label: "JWT returned by /login/finalize",
				type: "text",
			},
		} as any,
		async authorize(credentials?: { finalizeJWT?: string }) {
			const jwt = credentials?.finalizeJWT;
			if (!jwt) throw new Error("No JWT provided");

			let token: JWTVerifyResult;
			try {
				token = await jwtVerify(jwt, JWKS);
			} catch (e) {
				throw new PasskeyProviderError("JWT verification failed", ErrorCode.JWTVerificationFailed, e);
			}

			const userId = token.payload.sub;
			if (!userId) {
				throw new PasskeyProviderError("JWT does not contain a `sub` claim", ErrorCode.JWTSubClaimMissing);
			}

			// Make sure token is not older than TOKEN_MAX_AGE_SECONDS
			// This can be removed in the future, when the JWT issued by the Passkey Server gets an `exp` claim.
			// As of now, it only has aud, cred, iat, and sub, so jwtVerify() does not check for expiration.
			const now = Date.now() / 1000;
			if (token.payload.iat == null || now > token.payload.iat + TOKEN_MAX_AGE_SECONDS) {
				throw new PasskeyProviderError("JWT has expired", ErrorCode.JWTExpired);
			}

			let user = { id: userId };

			if (authorize) {
				user = await authorize({ userId, token: token.payload });
			}

			return user;
		},
	} as const;
}

/**
 * @deprecated Use the default export instead
 */
export const PasskeyProvider = createPasskeyProvider;

const Passkeys = createPasskeyProvider; // So TS language server auto-imports it as "Passkeys" which is the preferred spelling in Auth.js v5
export default Passkeys;
