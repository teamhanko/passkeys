# Hanko Passkey API SDK

JavaScript and TypeScript **server SDK** for the [Hanko Passkey API](https://github.com/teamhanko/passkeys).

Use the Hanko Passkey API to build passkey authentication into new or existing web and mobile applications. Support passkeys and FIDO2 security keys for primary authentication, multi-factor authentication, or step-up authentication before sensitive actions.

This SDK simplifies communication between your backend and the Passkey API. It provides typed methods for registration, authentication, and credential management, and works with both Hanko-hosted and self-hosted deployments.

> **Server-side use only:** This SDK requires a secret API key. Never include it in browser code or distribute it with a mobile application.

## Installation

```sh
npm install @teamhanko/passkeys-sdk
```

## Initialize the SDK

Create a client for your Passkey API tenant:

```ts
import { tenant } from "@teamhanko/passkeys-sdk";

const passkeys = tenant({
  apiKey: process.env.HANKO_PASSKEYS_API_KEY!,
  tenantId: process.env.HANKO_PASSKEYS_TENANT_ID!,
});
```

For a self-hosted deployment, provide your API base URL:

```ts
const passkeys = tenant({
  apiKey: process.env.HANKO_PASSKEYS_API_KEY!,
  tenantId: process.env.HANKO_PASSKEYS_TENANT_ID!,
  baseUrl: "https://passkeys.example.com",
});
```

Create a separate client for each tenant you need to access.

## How it fits into your application

A passkey registration or authentication involves your frontend, your backend, and the Passkey API:

1. Your backend uses this SDK to initialize a ceremony.
2. Your frontend passes the returned options to the browser's WebAuthn API or the native platform's passkey API.
3. Your frontend sends the resulting credential response to your backend.
4. Your backend uses this SDK to finalize the ceremony with the Passkey API.

Your application remains responsible for user onboarding, authorization, recovery, and application sessions.

The SDK does not invoke browser or native passkey APIs, provide a login UI, or create application sessions.

## Register a passkey

Initialize registration from your backend using your application's user ID:

```ts
const options = await passkeys.registration.initialize({
  userId: user.id,
  username: user.username,
  displayName: user.displayName,
});
```

Send the returned options to your frontend and complete the passkey creation using the browser or native platform API.

After your frontend sends the serialized credential response back to your backend, finalize registration:

```ts
const result = await passkeys.registration.finalize(credential);
```

Only allow registration for a user whose identity and authorization your backend has established. Derive the user ID from trusted application state.

## Authenticate with a passkey

Initialize authentication on your backend:

```ts
const options = await passkeys.login.initialize();
```

Send the returned options to your frontend and request authentication using the browser or native platform API.

Finalize authentication on your backend with the serialized credential response:

```ts
const result = await passkeys.login.finalize(credential);
```

Use the verified result to establish your application's session according to the Passkey API integration requirements.

## Multi-factor authentication

For user-specific MFA flows, scope the request to a user:

```ts
const userPasskeys = passkeys.user(user.id);
```

Register a credential for MFA:

```ts
const options = await userPasskeys.mfa.registration.initialize({
  username: user.username,
  displayName: user.displayName,
});

// After completing passkey creation on the frontend:
const result =
  await userPasskeys.mfa.registration.finalize(credential);
```

Authenticate with an MFA credential:

```ts
const options = await userPasskeys.mfa.login.initialize();

// After completing authentication on the frontend:
const result = await userPasskeys.mfa.login.finalize(credential);
```

Derive the user ID from your authenticated session or trusted authentication flow. Your backend decides when an additional authentication factor is required and which action it authorizes.

## Manage credentials

List a user's registered credentials:

```ts
const credentials = await passkeys.user(user.id).credentials();
```

Delete a credential:

```ts
await passkeys.credential(credentialId).remove();
```

Before deleting a credential, verify that the requesting user is authorized to manage it.

## Retrieve public signing keys

Retrieve the tenant's JSON Web Key Set:

```ts
const jwks = await passkeys.jwks();
```

The SDK retrieves the keys but does not verify JWTs. Use a JWT verification library and validate the signature and required claims according to the Passkey API documentation.

## Error handling

Failed API requests throw an error. Handle errors in your backend before returning an appropriate response to your frontend:

```ts
try {
  const result = await passkeys.login.finalize(credential);
  // Continue your application's authentication flow.
} catch (error) {
  // Handle the failed authentication.
}
```

## Documentation and support

- [Hanko documentation](https://docs.hanko.io)
- [Passkey API repository](https://github.com/teamhanko/passkeys)
- [Report an issue](https://github.com/teamhanko/passkeys/issues)
- Contact: [info@hanko.io](mailto:info@hanko.io)

## License

This SDK is licensed under the MIT License. The Passkey API server is licensed separately.
