# Hanko Passkeys JavaScript SDK

[View docs on docs.hanko.io](https://docs.hanko.io/passkey-api/js-sdk)

The `@teamhanko/passkeys-sdk` package lets you call the Hanko Passkey API from JavaScript/TypeScript that supports `fetch`.

This includes Node.js, Browsers, Deno, Bun, and frameworks like Next.js, Astro, and SvelteKit.

<CodeGroup>

```bash npm
npm i @teamhanko/passkeys-sdk
```

```bash yarn
yarn add @teamhanko/passkeys-sdk
```

```bash bun
bun add @teamhanko/passkeys-sdk
```

```bash pnpm
pnpm add @teamhanko/passkeys-sdk
```

</CodeGroup>

## Usage

A `tenant` is an API client instance for one tenant of the Hanko Passkey API.

[👉 See multitenancy](https://docs.hanko.io/passkey-api/faq#tenant-id-and-multitenancy)

Create a new tenant instance:

```ts
const passkeyApi = tenant({
	tenantId: "<your tenant id>",
	apiKey: "<your secret api key>",
});
```

Make sure the API key stays secret. It should never be exposed to the client/frontend. If you're using a framework that handles both frontend and backend (like Next.js, for example), create two separate `tenant` instances, each in their own file (e.g. `tenant-server.ts` and `tenant-client.ts`).

-   If you only use public API methods, like `/login/initialize`, you can omit the `apiKey`.
-   If you're self-hosting the Passkey API, make sure to pass the `baseUrl` as well.

Now you're ready to call the API. For example, to start the process of registering a new passkey:

```ts
const creationOptions = await tenant.registration.initialize({
	userId: "<id of the user in your database>",
	username: "<username of the user>",
});
```
