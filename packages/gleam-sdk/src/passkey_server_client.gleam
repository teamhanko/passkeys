//// Gleam client for a Hanko Passkey Server.
////
//// Covers the passkey flows from the passkey-server OpenAPI spec:
//// registration initialize/finalize and login initialize/finalize.
//// Registration initialize is authenticated server-side with an API key;
//// finalize and both login calls are unauthenticated (they are completed
//// by the device holding the passkey).
////
//// Handlers can forward the returned JSON payloads straight to their
//// mobile client, where they feed the platform WebAuthn APIs (androidx
//// Credential Manager / ASAuthorizationPlatformPublicKeyCredential*).

import gleam/dynamic/decode
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/json.{type Json}
import gleam/result
import gleam/string
import gleam/hackney

pub type Config {
  Config(base_url: String, tenant_id: String, api_key: String)
}

pub type ServerError {
  ServerError(message: String, code: String)
}

pub type Token {
  Token(token: String)
}

fn url_path(config: Config, path: String) -> String {
  string.replace(path, "{tenant_id}", config.tenant_id)
}

fn send(request: Request(String)) -> Result(Response(String), ServerError) {
  hackney.send(request)
  |> result.map_error(fn(e) { ServerError(string.inspect(e), "NETWORK") })
}

fn post(
  config: Config,
  path: String,
  body: String,
  with_api_key: Bool,
) -> Result(Response(String), ServerError) {
  let request =
    request.new()
    |> request.set_method(http.Post)
    |> request.set_body(body)
    |> request.set_header("content-type", "application/json")
  let keyed_request = case with_api_key {
    True -> request.set_header(request, "X-API-KEY", config.api_key)
    False -> request
  }
  let request = request.set_path(keyed_request, url_path(config, path))
  send(request)
}

fn parse_error(status: Int, body: String) -> ServerError {
  let message =
    json.parse(body, decode.at(["message"], decode.string))
    |> result.unwrap(body)
  ServerError(message, int.to_string(status))
}

/// POST /{tenant}/registration/initialize
/// Returns the raw public key credential creation options JSON, which maps
/// directly to a platform CredentialCreationOptions.
pub fn registration_initialize(
  config: Config,
  body: Json,
) -> Result(String, ServerError) {
  use res <- result.try(
    post(
      config,
      "/{tenant_id}/registration/initialize",
      json.to_string(body),
      True,
    ),
  )
  from_json_body(res)
}

/// POST /{tenant}/registration/finalize with the WebAuthn attestation
/// response from the device. Returns the session Token.
pub fn registration_finalize(
  config: Config,
  body: String,
) -> Result(Token, ServerError) {
  use res <- result.try(
    post(config, "/{tenant_id}/registration/finalize", body, False),
  )
  from_token(res)
}

/// POST /{tenant}/login/initialize for a user identifier.
/// Returns the raw public key credential assertion options JSON for
/// CredentialAssertion on the device.
pub fn login_initialize(
  config: Config,
  body: Json,
) -> Result(String, ServerError) {
  use res <- result.try(
    post(config, "/{tenant_id}/login/initialize", json.to_string(body), False),
  )
  from_json_body(res)
}

/// POST /{tenant}/login/finalize with the WebAuthn assertion response.
/// Returns the session Token.
pub fn login_finalize(config: Config, body: String) -> Result(Token, ServerError) {
  use res <- result.try(
    post(config, "/{tenant_id}/login/finalize", body, False),
  )
  from_token(res)
}

/// GET /{tenant}/.well-known/jwks.json used to verify finalize tokens.
pub fn jwks(config: Config) -> Result(String, ServerError) {
  use res <- result.try(
    post(config, "/{tenant_id}/.well-known/jwks.json", "", False),
  )
  from_json_body(res)
}

fn from_json_body(res: Response(String)) -> Result(String, ServerError) {
  case res.status {
    200 -> Ok(res.body)
    status -> Error(parse_error(status, res.body))
  }
}

fn from_token(res: Response(String)) -> Result(Token, ServerError) {
  case res.status {
    200 ->
      json.parse(res.body, decode.at(["token"], decode.string))
      |> result.map(Token)
      |> result.replace_error(ServerError("token decode failed", "SDK"))
    status -> Error(parse_error(status, res.body))
  }
}
