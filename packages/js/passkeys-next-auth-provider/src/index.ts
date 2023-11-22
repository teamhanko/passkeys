import { Tenant } from "@teamhanko/passkeys-sdk";
import { JWTPayload, JWTVerifyResult, createRemoteJWKSet, jwtVerify } from "jose";
import CredentialsProvider from "next-auth/providers/credentials";

export const DEFAULT_PROVIDER_ID = "passkeys";

export function PasskeyProvider({
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

	return CredentialsProvider({
		id,
		credentials: {
			/**
			 * Token returned by `passkeyApi.login.finalize()`
			 */
			finalizeJWT: {
				label: "JWT returned by /login/finalize",
				type: "text",
			},
		},
		async authorize(credentials) {
			const jwt = credentials?.finalizeJWT;
			if (!jwt) throw new Error("No JWT provided");

			let token: JWTVerifyResult;
			try {
				token = await jwtVerify(jwt, JWKS);
			} catch (e) {
				console.warn("JWT verification failed", e);
				return null;
			}

			const userId = token.payload.sub;
			if (!userId) {
				console.error('JWT does not contain a "sub" claim');
				return null;
			}

			let user = { id: userId };

			if (authorize) {
				user = await authorize({ userId, token: token.payload });
			}

			return user;
		},
	});
}
