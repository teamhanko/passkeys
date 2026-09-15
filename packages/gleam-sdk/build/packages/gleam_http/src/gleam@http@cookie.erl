-module(gleam@http@cookie).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([defaults/1, set_header/3, parse/1]).
-export_type([same_site_policy/0, attributes/0]).

-type same_site_policy() :: lax | strict | none.

-type attributes() :: {attributes, gleam@option:option(integer()), gleam@option:option(binary()), gleam@option:option(binary()), boolean(), boolean(), gleam@option:option(same_site_policy())}.

-spec same_site_to_string(same_site_policy()) -> binary().
same_site_to_string(Policy) ->
    case Policy of
        lax ->
            ~"Lax";

        strict ->
            ~"Strict";

        none ->
            ~"None"
    end.

-spec defaults(gleam@http:scheme()) -> attributes().
-doc(~" Helper to create sensible default attributes for a set cookie.

 https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Attributes").
defaults(Scheme) ->
    {attributes, none, none, {some, ~"/"}, Scheme =:= https, true, {some, lax}}.

-spec cookie_attributes_to_list(attributes()) -> list(binary()).
cookie_attributes_to_list(Attributes) ->
    {attributes, Max_age, Domain, Path, Secure, Http_only, Same_site} = Attributes,
    _pipe = [case Max_age of
        {some, 0} ->
            {some, ~"Expires=Thu, 01 Jan 1970 00:00:00 GMT"};

        _ ->
            none
    end, gleam@option:map(Max_age, fun(Max_age@1) ->
        <<"Max-Age="/utf8, (erlang:integer_to_binary(Max_age@1))/binary>>
    end), gleam@option:map(Domain, fun(Domain@1) ->
        <<"Domain="/utf8, Domain@1/binary>>
    end), gleam@option:map(Path, fun(Path@1) ->
        <<"Path="/utf8, Path@1/binary>>
    end), case Secure of
        true ->
            {some, ~"Secure"};

        false ->
            none
    end, case Http_only of
        true ->
            {some, ~"HttpOnly"};

        false ->
            none
    end, gleam@option:map(Same_site, fun(Same_site@1) ->
        <<"SameSite="/utf8, (same_site_to_string(Same_site@1))/binary>>
    end)],
    gleam@list:filter_map(_pipe, fun(_capture) ->
        gleam@option:to_result(_capture, nil)
    end).

-spec set_header(binary(), binary(), attributes()) -> binary().
set_header(Name, Value, Attributes) ->
    _pipe = [<<<<Name/binary, "="/utf8>>/binary, Value/binary>> | cookie_attributes_to_list(Attributes)],
    gleam@string:join(_pipe, ~"; ").

-spec check_token(binary()) -> {ok, nil} | {error, nil}.
check_token(Token) ->
    Contains_invalid_charachter = (((gleam_stdlib:contains_string(Token, ~" ") orelse gleam_stdlib:contains_string(Token, ~"\t")) orelse gleam_stdlib:contains_string(Token, ~"\r")) orelse gleam_stdlib:contains_string(Token, ~"\n")) orelse gleam_stdlib:contains_string(Token, ~"\f"),
    case Contains_invalid_charachter of
        true ->
            {error, nil};

        false ->
            {ok, nil}
    end.

-spec parse(binary()) -> list({binary(), binary()}).
-doc(~" Parse a list of cookies from a header string. Any malformed cookies will be
 discarded.

 ## Backwards compatibility

 RFC 6265 states that cookies in the cookie header should be separated by a
 `;`, however this function will also accept a `,` separator to remain
 compatible with the now-deprecated RFC 2965, and any older software
 following that specification.
").
parse(Cookie_string) ->
    _pipe = Cookie_string,
    _pipe@1 = gleam@string:split(_pipe, ~";"),
    _pipe@2 = gleam@list:flat_map(_pipe@1, fun(_capture) ->
        gleam@string:split(_capture, ~",")
    end),
    gleam@list:filter_map(_pipe@2, fun(Pair) ->
        case gleam@string:split_once(gleam@string:trim(Pair), ~"=") of
            {ok, {~"", _}} ->
                {error, nil};

            {ok, {Key, Value}} ->
                Key@1 = gleam@string:trim(Key),
                gleam@result:'try'(check_token(Key@1), fun(_) ->
                    Value@1 = gleam@string:trim(Value),
                    gleam@result:'try'(check_token(Value@1), fun(_) ->
                        {ok, {Key@1, Value@1}}
                    end)
                end);

            {error, nil} ->
                {error, nil}
        end
    end).

