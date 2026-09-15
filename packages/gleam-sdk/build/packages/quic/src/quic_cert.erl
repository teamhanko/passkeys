%%% -*- erlang -*-
%%%
%%% Server certificate validation for QUIC clients.
%%%
%%% Performs the two checks RFC 8446 requires of a client after it
%%% receives the server's Certificate message: chain validation against
%%% a set of trust anchors (§4.4.2.4) and identity (hostname) matching
%%% (RFC 6125). Signature verification of CertificateVerify is handled
%%% in `quic_tls:verify_certificate_verify/4'; this module covers the
%%% chain and the name.

-module(quic_cert).

-include_lib("public_key/include/public_key.hrl").

-export([validate_server/4, validate_client/3]).

-define(MAX_PATH_LENGTH, 10).

%% @doc Validate a server's certificate chain and identity.
%%
%% `Leaf' is the server's end-entity certificate (DER). `Intermediates'
%% are the remaining certificates sent by the peer (DER), in the
%% leaf-to-root order they arrive on the wire. `CaCerts' are the trust
%% anchors as a DER list, or `undefined' to use the OS trust store.
%% `ServerName' is the expected identity (binary hostname or IP literal),
%% or `undefined' to skip the hostname check.
-spec validate_server(
    binary() | undefined,
    [binary()],
    [binary()] | undefined,
    binary() | undefined
) -> ok | {error, term()}.
validate_server(undefined, _Intermediates, _CaCerts, _ServerName) ->
    {error, no_certificate};
validate_server(Leaf, Intermediates, CaCerts, ServerName) when is_binary(Leaf) ->
    case verify_chain(Leaf, Intermediates, trust_anchors(CaCerts)) of
        ok -> verify_hostname(Leaf, ServerName);
        {error, _} = Error -> Error
    end.

%% @doc Validate a client's certificate chain (mutual TLS, RFC 8446 §4.4.2.4).
%%
%% Same trust-anchor chain validation as {@link validate_server/4}, but with no
%% identity/hostname check: a client certificate is not bound to a server name,
%% and the peer's application identity is established separately (e.g. from the
%% certificate subject plus an out-of-band token). `Leaf' is the client's
%% end-entity certificate (DER), `Intermediates' the rest of the chain in
%% wire (leaf-to-root) order, and `CaCerts' the trust anchors (DER list, or
%% `undefined' for the OS trust store).
-spec validate_client(binary() | undefined, [binary()], [binary()] | undefined) ->
    ok | {error, term()}.
validate_client(undefined, _Intermediates, _CaCerts) ->
    {error, no_certificate};
validate_client(Leaf, Intermediates, CaCerts) when is_binary(Leaf) ->
    verify_chain(Leaf, Intermediates, trust_anchors(CaCerts)).

%%====================================================================
%% Chain validation
%%====================================================================

%% Trust anchors as DER. `cacerts_get/0' returns `#cert{}' records on
%% recent OTP and bare DER on older ones; normalise both.
trust_anchors(undefined) ->
    [normalize_anchor(C) || C <- safe_cacerts_get()];
trust_anchors(CaCerts) when is_list(CaCerts) ->
    [normalize_anchor(C) || C <- CaCerts].

safe_cacerts_get() ->
    try
        public_key:cacerts_get()
    catch
        _:_ -> []
    end.

normalize_anchor(#cert{der = Der}) -> Der;
normalize_anchor(Der) when is_binary(Der) -> Der.

verify_chain(_Leaf, _Intermediates, []) ->
    {error, no_trust_anchors};
verify_chain(Leaf, Intermediates, Anchors) ->
    %% `pkix_path_validation/3' wants the path ordered from the cert
    %% issued by the anchor down to the leaf; the wire order is the
    %% reverse (leaf first).
    Path = lists:reverse([Leaf | Intermediates]),
    case candidate_anchorings(Path, Anchors) of
        [] ->
            {error, unknown_ca};
        [Primary | Alternatives] ->
            validate_anchored(Primary, Alternatives)
    end.

%% Every `{Anchor, SubPath}' pairing, highest anchorable cert first. The
%% head is the pairing the single-anchor lookup would have chosen (lets
%% the server send extra or cross-signed certs above the cert that
%% actually chains); the tail anchors lower in the served chain, or at a
%% different trust anchor for the same cert.
candidate_anchorings([], _Anchors) ->
    [];
candidate_anchorings([Cert | Rest] = SubPath, Anchors) ->
    [{Anchor, SubPath} || Anchor <- Anchors, is_issuer(Cert, Anchor)] ++
        candidate_anchorings(Rest, Anchors).

%% Validate the primary anchoring; on an expired-cert failure, recover by
%% trying the alternatives. Mirrors OTP's
%% `ssl_certificate:find_cross_sign_root_paths/4': an expired cross-signed
%% root (e.g. Let's Encrypt ISRG Root X2 cross-signed by the expired X1)
%% is dropped for a still-valid trust anchor with the same key, reached
%% lower in the chain. Recovery only moves the anchor; an expired leaf or
%% intermediate stays in every remaining sub-path, so it still fails as
%% `cert_expired'.
validate_anchored(Primary, Alternatives) ->
    case validate_path(Primary) of
        ok ->
            ok;
        {error, {bad_cert, Reason}} = Error ->
            case is_expiry(Reason) of
                true ->
                    case try_anchorings(Alternatives) of
                        ok -> ok;
                        error -> {error, {bad_cert, cert_expired}}
                    end;
                false ->
                    Error
            end
    end.

%% First anchoring that validates wins. Returns a bare `error' on
%% exhaustion, discarding each alternative's reason, so a failing
%% alternative never replaces the caller's expiry outcome.
try_anchorings([]) ->
    error;
try_anchorings([Candidate | Rest]) ->
    case validate_path(Candidate) of
        ok -> ok;
        {error, _} -> try_anchorings(Rest)
    end.

validate_path({Anchor, SubPath}) ->
    try
        public_key:pkix_path_validation(
            Anchor, SubPath, [{max_path_length, ?MAX_PATH_LENGTH}]
        )
    of
        {ok, _} -> ok;
        {error, {bad_cert, Reason}} -> {error, {bad_cert, Reason}}
    catch
        _:_ -> {error, {bad_cert, validation_failed}}
    end.

is_expiry(cert_expired) -> true;
is_expiry(root_cert_expired) -> true;
is_expiry(_) -> false.

%% A self-signed cert is its own issuer, which covers self-signed leaves
%% supplied as anchors.
is_issuer(Cert, Anchor) ->
    try
        public_key:pkix_is_issuer(Cert, Anchor)
    catch
        _:_ -> false
    end.

%%====================================================================
%% Hostname validation
%%====================================================================

verify_hostname(_Leaf, undefined) ->
    ok;
verify_hostname(Leaf, ServerName) when is_binary(ServerName) ->
    Host = binary_to_list(ServerName),
    RefId =
        case inet:parse_address(Host) of
            {ok, IP} -> {ip, IP};
            {error, _} -> {dns_id, Host}
        end,
    case safe_verify_hostname(Leaf, RefId) of
        true -> ok;
        false -> {error, {hostname_mismatch, ServerName}}
    end.

%% The `https' match fun applies the RFC 6125 §6.4.3 wildcard rules, which
%% OTP's default match fun leaves out: without it a leftmost-label wildcard
%% (`*.example.com') never matches, so wildcard-only servers are rejected.
safe_verify_hostname(Leaf, RefId) ->
    try
        MatchFun = public_key:pkix_verify_hostname_match_fun(https),
        public_key:pkix_verify_hostname(Leaf, [RefId], [{match_fun, MatchFun}])
    catch
        _:_ -> false
    end.
