# Review instructions

## Severity

Important is for: weakened WebAuthn verification, cross-tenant access,
routes missing `ApiKeyMiddleware`, leaked secrets or personal data, broken
transaction/MFA semantics, and breaking API changes. Everything about style,
naming or refactoring is Nit at most. Report at most five Nits.

## Do not report

- Formatting
- `packages/js/passkeys-sdk/src/schema.ts` (generated from the spec) and
  lockfiles
- Fake keys in test fixtures

## Always check

- Tenant IDs on every new record, JWK and lookup.
- API keys and secrets are compared in constant time, not with `==`.
- Changes to handlers or DTOs are reflected in `spec/*.yaml`, with a
  regenerated `schema.ts` where the SDK is affected.
- Success and failure paths both write an audit log entry, and failure
  entries include the error.
- New tenant or MFA config fields work for existing tenants whose stored
  config doesn't have them yet.
- Every `.up.fizz` has a `.down.fizz` that actually reverts it.
