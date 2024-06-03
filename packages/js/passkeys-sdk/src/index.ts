import createClient from "openapi-fetch";
import { components, paths } from "./schema";

export const DEFAULT_BASE_URL = "https://passkeys.hanko.io";

class PasskeyError extends Error {
	constructor(message: string, public originalError?: unknown) {
		super(message);
	}
}

type RequestBody<T extends keyof components["requestBodies"]> = Exclude<
	components["requestBodies"][T],
	undefined
>["content"]["application/json"];

type PostLoginFinalizeBody = RequestBody<"post-login-finalize">;
type PostRegistrationFinalizeBody = RequestBody<"post-registration-finalize">;

export type Tenant = ReturnType<typeof tenant>;

export function tenant(config: { baseUrl?: string; apiKey: string; tenantId: string }) {
	const { apiKey, tenantId } = config;

	if (!tenantId) throw new PasskeyError("No tenant ID provided");

	let baseUrl: string;
	try {
		baseUrl = new URL(config.baseUrl ?? DEFAULT_BASE_URL).href;
	} catch (err) {
		throw new PasskeyError("Invalid base URL", err);
	}

	const client = createClient<paths>({ baseUrl });

	// Default params
	const header = { apiKey, "Content-Type": "application/json" };
	const path = { tenant_id: tenantId };
	const params = { path, header };

	async function wrap<P extends Promise<{ error?: unknown; data?: unknown }>>(
		p: P
	): Promise<Exclude<Awaited<P>["data"], undefined>> {
		const { error, data } = await p;

		if (error) {
			throw new PasskeyError(
				"Request failed: " + (error instanceof Error ? error.message : JSON.stringify(error)),
				error
			);
		}

		return data as any;
	}

	return {
		config: {
			// Getters (for now) since you can't change the config of `client` after it's created
			get baseUrl() {
				return baseUrl;
			},
			get tenantId() {
				return tenantId;
			},
		},
		user(userId: string) {
			return {
				credentials() {
					return wrap(
						client.GET("/{tenant_id}/credentials", {
							params: {
								path,
								header,
								query: { user_id: userId },
							},
						})
					);
				},
				mfa: {
					registration: {
						initialize(data: { username: string; icon?: string; displayName?: string }) {
							return wrap(
								client.POST("/{tenant_id}/mfa/registration/initialize", {
									params,
									body: {
										user_id: userId,
										username: data.username,
										icon: data.icon,
										display_name: data.displayName,
									},
								})
							);
						},
						finalize(credential: PostRegistrationFinalizeBody) {
							return wrap(
								client.POST("/{tenant_id}/mfa/registration/finalize", { params, body: credential })
							);
						},
					},
					login: {
						initialize() {
							return wrap(
								client.POST("/{tenant_id}/mfa/login/initialize", {
									params,
									body: { user_id: userId },
								})
							);
						},
						finalize(credential: PostLoginFinalizeBody) {
							return wrap(client.POST("/{tenant_id}/mfa/login/finalize", { params, body: credential }));
						},
					},
				},
			};
		},
		jwks() {
			return wrap(client.GET("/{tenant_id}/.well-known/jwks.json", { params }));
		},
		login: {
			initialize() {
				return wrap(client.POST("/{tenant_id}/login/initialize", { params }));
			},
			/**
			 * Finalize the login process. The first argument should be the credential returned by the user's browser (from `navigator.credentials.get()`)
			 */
			finalize(credential: PostLoginFinalizeBody) {
				return wrap(client.POST("/{tenant_id}/login/finalize", { params, body: credential }));
			},
		},
		registration: {
			initialize(data: { userId: string; username: string; icon?: string; displayName?: string }) {
				return wrap(
					client.POST("/{tenant_id}/registration/initialize", {
						params,
						body: {
							user_id: data.userId,
							username: data.username,
							icon: data.icon,
							display_name: data.displayName,
						},
					})
				);
			},
			/**
			 * Finalize the registration process. The first argument should be the credential returned by the user's browser (from `navigator.credentials.create()`)
			 */
			finalize(credential: PostRegistrationFinalizeBody) {
				return wrap(client.POST("/{tenant_id}/registration/finalize", { params, body: credential }));
			},
		},
		credential(credentialId: string) {
			const params = { header, path: { ...path, credential_id: credentialId } };
			return {
				remove() {
					return wrap(client.DELETE("/{tenant_id}/credentials/{credential_id}", { params }));
				},
				// TODO no query, no response (always 204) ???
				// update() {
				// 	return wrap(client.PATCH("/{tenant_id}/credentials/{credential_id}", { params }));
				// },
			};
		},
	};
}
