# Hanko Passkey API

**Add passkeys to your existing app. Keep your authentication stack.**

Hanko Passkey API is an open-source, FIDO2-certified WebAuthn server for adding passkey registration and authentication to applications with an existing user base.

Integrate through an HTTP API or JavaScript/TypeScript SDK. Self-host the server or use the managed service on [Hanko Cloud](https://cloud.hanko.io).

Built-in **multi-tenancy** lets you manage passkeys for multiple applications or customers within a single deployment.

[Documentation](https://docs.hanko.io/passkey-api/introduction) · [Hanko Cloud](https://cloud.hanko.io) · [Self-hosting](server/README.md) · [Discord](https://discord.com/invite/jW2r526qjg)

## Features

- **Passkey registration and authentication:** Add passwordless login to existing user accounts.
- **Second-factor authentication:** Use WebAuthn credentials, including hardware security keys, alongside your existing login.
- **Multi-tenancy:** Manage multiple tenants with their own WebAuthn configuration and API keys.
- **Credential management:** List, update, and remove registered credentials.
- **Transaction authentication:** Require WebAuthn authentication to authorize transactions.
- **FIDO2-certified server:** Built on Hanko’s certified WebAuthn infrastructure.
- **Flexible integration:** Use the HTTP API from any backend or the JavaScript/TypeScript SDK.
- **Self-hosted or managed:** Run the Go server on your own infrastructure or use Hanko Cloud.

## Getting started

### Hanko Cloud

Use the managed Passkey API without operating your own server.

1. Create an account on [Hanko Cloud](https://cloud.hanko.io).
2. Create a Passkey API project.
3. Follow the [integration documentation](https://docs.hanko.io/passkey-api/introduction) to add passkey registration and login to your application.

### Self-hosting

Run the server locally using Docker Compose:

```bash
git clone https://github.com/teamhanko/passkeys.git
cd passkeys/deploy/docker-compose
docker compose -f backend.yaml up -d
```

The Passkey API is available at `http://localhost:8000`, and the Admin API at `http://localhost:8001`.

Next, [create a tenant](server/README.md#create-tenant) to configure your relying party, allowed origins, and API key.

See the [server README](server/README.md) for configuration, database setup, and deployment instructions. The local Docker Compose setup is intended as a starting point; secure access to the Admin API before deploying to production.

## How it works

Your application continues to manage users, accounts, and sessions. Hanko Passkey API handles WebAuthn registration, credential storage, and authentication verification.

**Register a passkey**

1. A user signs in through your existing authentication system.
2. Your backend starts passkey registration for that user.
3. The user creates a passkey using their device or security key.
4. Hanko Passkey API verifies and stores the credential.

**Sign in with a passkey**

1. Your application starts passkey authentication.
2. The user authenticates using their passkey.
3. Hanko Passkey API verifies the response.
4. Your backend validates the authentication result and creates a session through your existing authentication system.

Keep secret API keys on your backend. Requests that require an API key must never expose it to the browser or mobile client.

For implementation details and examples, see the [documentation](https://docs.hanko.io/passkey-api/introduction).

## Multi-tenancy

A single Passkey API deployment can serve multiple tenants, making it suitable for SaaS platforms and service providers that offer passkey authentication to their customers.

Each tenant has its own relying party configuration, allowed origins, and API keys. Use the Admin API to provision and manage tenants programmatically.

See the [tenant setup guide](server/README.md#create-tenant) for an example.

## Repository structure

| Directory | Contents |
| --- | --- |
| [`server`](server) | Go-based Passkey API server and Admin API |
| [`packages`](packages) | JavaScript/TypeScript SDK packages |
| [`spec`](spec) | OpenAPI specifications |
| [`deploy/docker-compose`](deploy/docker-compose) | Docker Compose configuration for local setup |

## Documentation and support

- [Passkey API documentation](https://docs.hanko.io/passkey-api/introduction)
- [Self-hosting guide](server/README.md)
- [OpenAPI specifications](spec)
- [GitHub issues](https://github.com/teamhanko/passkeys/issues) for bugs and feature requests
- [Discord](https://discord.com/invite/jW2r526qjg) for questions and community discussions

Developed and maintained by [Hanko](https://www.hanko.io). For commercial licensing, deployment support, or a managed service, contact [info@hanko.io](mailto:info@hanko.io).

## License

The Passkey API server is licensed under [AGPL-3.0](LICENSE). JavaScript/TypeScript SDKs are available under the MIT license; see the respective package licenses.

Commercial licenses are available for organizations that need alternative licensing terms. Contact [info@hanko.io](mailto:info@hanko.io) for details.
