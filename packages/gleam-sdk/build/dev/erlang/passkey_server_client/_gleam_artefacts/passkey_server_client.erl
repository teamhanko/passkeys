-module(passkey_server_client).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([registration_initialize/2, registration_finalize/2, login_initialize/2, login_finalize/2, jwks/1]).
-export_type([config/0, server_error/0, token/0]).
-moduledoc(~" Gleam client for a Hanko Passkey Server.

 Covers the passkey flows from the passkey-server OpenAPI spec:
 registration initialize/finalize and login initialize/finalize.
 Registration initialize is authenticated server-side with an API key;
 finalize and both login calls are unauthenticated (they are completed
 by the device holding the passkey).

 Handlers can forward the returned JSON payloads straight to their
 mobile client, where they feed the platform WebAuthn APIs (androidx
 Credential Manager / ASAuthorizationPlatformPublicKeyCredential*).").

-type config() :: {config, binary(), binary(), binary()}.

-type server_error() :: {server_error, binary(), binary()}.

-type token() :: {token, binary()}.

-file("src/passkey_server_client.gleam", 35).
-spec url_path(config(), binary()) -> binary().
url_path(Config, Path) ->
    gleam@string:replace(Path, ~"{tenant_id}", erlang:element(3, Config)).

-file("src/passkey_server_client.gleam", 39).
-spec send(gleam@http@request:request(binary())) -> {ok, gleam@http@response:response(binary())} | {error, server_error()}.
send(Request) ->
    _pipe = gleam@hackney:send(Request),
    gleam@result:map_error(_pipe, fun(E) ->
        {server_error, gleam@string:inspect(E), ~"NETWORK"}
    end).

-file("src/passkey_server_client.gleam", 44).
-spec post(config(), binary(), binary(), boolean()) -> {ok, gleam@http@response:response(binary())} | {error, server_error()}.
post(Config, Path, Body, With_api_key) ->
    Request = begin
        _pipe = gleam@http@request:new(),
        _pipe@1 = gleam@http@request:set_method(_pipe, post),
        _pipe@2 = gleam@http@request:set_body(_pipe@1, Body),
        gleam@http@request:set_header(_pipe@2, ~"content-type", ~"application/json")
    end,
    Keyed_request = case With_api_key of
        true ->
            gleam@http@request:set_header(Request, ~"X-API-KEY", erlang:element(4, Config));

        false ->
            Request
    end,
    Request@1 = gleam@http@request:set_path(Keyed_request, url_path(Config, Path)),
    send(Request@1).

-file("src/passkey_server_client.gleam", 63).
-spec parse_error(integer(), binary()) -> server_error().
parse_error(Status, Body) ->
    Message = begin
        _pipe = gleam@json:parse(Body, gleam@dynamic@decode:at([~"message"], {decoder, fun gleam@dynamic@decode:decode_string/1})),
        gleam@result:unwrap(_pipe, Body)
    end,
    {server_error, Message, erlang:integer_to_binary(Status)}.

-file("src/passkey_server_client.gleam", 130).
-spec from_json_body(gleam@http@response:response(binary())) -> {ok, binary()} | {error, server_error()}.
from_json_body(Res) ->
    case erlang:element(2, Res) of
        200 ->
            {ok, erlang:element(4, Res)};

        Status ->
            {error, parse_error(Status, erlang:element(4, Res))}
    end.

-file("src/passkey_server_client.gleam", 73).
-spec registration_initialize(config(), gleam@json:json()) -> {ok, binary()} | {error, server_error()}.
-doc(~" POST /{tenant}/registration/initialize
 Returns the raw public key credential creation options JSON, which maps
 directly to a platform CredentialCreationOptions.").
registration_initialize(Config, Body) ->
    gleam@result:'try'(post(Config, ~"/{tenant_id}/registration/initialize", gleam@json:to_string(Body), true), fun(Res) ->
        from_json_body(Res)
    end).

-file("src/passkey_server_client.gleam", 137).
-spec from_token(gleam@http@response:response(binary())) -> {ok, token()} | {error, server_error()}.
from_token(Res) ->
    case erlang:element(2, Res) of
        200 ->
            _pipe = gleam@json:parse(erlang:element(4, Res), gleam@dynamic@decode:at([~"token"], {decoder, fun gleam@dynamic@decode:decode_string/1})),
            _pipe@1 = gleam@result:map(_pipe, fun(_value) ->
                {token, _value}
            end),
            gleam@result:replace_error(_pipe@1, {server_error, ~"token decode failed", ~"SDK"});

        Status ->
            {error, parse_error(Status, erlang:element(4, Res))}
    end.

-file("src/passkey_server_client.gleam", 90).
-spec registration_finalize(config(), binary()) -> {ok, token()} | {error, server_error()}.
-doc(~" POST /{tenant}/registration/finalize with the WebAuthn attestation
 response from the device. Returns the session Token.").
registration_finalize(Config, Body) ->
    gleam@result:'try'(post(Config, ~"/{tenant_id}/registration/finalize", Body, false), fun(Res) ->
        from_token(Res)
    end).

-file("src/passkey_server_client.gleam", 103).
-spec login_initialize(config(), gleam@json:json()) -> {ok, binary()} | {error, server_error()}.
-doc(~" POST /{tenant}/login/initialize for a user identifier.
 Returns the raw public key credential assertion options JSON for
 CredentialAssertion on the device.").
login_initialize(Config, Body) ->
    gleam@result:'try'(post(Config, ~"/{tenant_id}/login/initialize", gleam@json:to_string(Body), false), fun(Res) ->
        from_json_body(Res)
    end).

-file("src/passkey_server_client.gleam", 115).
-spec login_finalize(config(), binary()) -> {ok, token()} | {error, server_error()}.
-doc(~" POST /{tenant}/login/finalize with the WebAuthn assertion response.
 Returns the session Token.").
login_finalize(Config, Body) ->
    gleam@result:'try'(post(Config, ~"/{tenant_id}/login/finalize", Body, false), fun(Res) ->
        from_token(Res)
    end).

-file("src/passkey_server_client.gleam", 123).
-spec jwks(config()) -> {ok, binary()} | {error, server_error()}.
-doc(~" GET /{tenant}/.well-known/jwks.json used to verify finalize tokens.").
jwks(Config) ->
    gleam@result:'try'(post(Config, ~"/{tenant_id}/.well-known/jwks.json", ~"", false), fun(Res) ->
        from_json_body(Res)
    end).

