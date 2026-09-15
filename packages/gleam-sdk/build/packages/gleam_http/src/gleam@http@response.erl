-module(gleam@http@response).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([set_body/2, try_map/2, new/1, get_header/2, set_header/3, prepend_header/3, map/2, redirect/1, get_cookies/1, set_cookie/4, expire_cookie/3]).
-export_type([response/1]).

-type response(EGG) :: {response, integer(), list({binary(), binary()}), EGG}.

-spec set_body(response(any()), EHD) -> response(EHD).
-doc(~" Set the body of the response, overwriting any existing body.
").
set_body(Response, Body) ->
    {response, erlang:element(2, Response), erlang:element(3, Response), Body}.

-spec try_map(response(EGH), fun((EGH) -> {ok, EGJ} | {error, EGK})) -> {ok, response(EGJ)} | {error, EGK}.
-doc(~" Update the body of a response using a given result returning function.

 If the given function returns an `Ok` value the body is set, if it returns
 an `Error` value then the error is returned.
").
try_map(Response, Transform) ->
    gleam@result:'try'(Transform(erlang:element(4, Response)), fun(Body) ->
        {ok, set_body(Response, Body)}
    end).

-spec new(integer()) -> response(binary()).
-doc(~" Construct an empty Response.

 The body type of the returned response is `String` and could be set with a
 call to `set_body`.
").
new(Status) ->
    {response, Status, [], ~""}.

-spec get_header(response(any()), binary()) -> {ok, binary()} | {error, nil}.
-doc(~" Get the value for a given header.

 If the response does not have that header then `Error(Nil)` is returned.
").
get_header(Response, Key) ->
    gleam@list:key_find(erlang:element(3, Response), string:lowercase(Key)).

-spec set_header(response(EGV), binary(), binary()) -> response(EGV).
-doc(~" Set the header with the given value under the given header key.

 If the response already has that key, it is replaced.

 Header keys are always lowercase in `gleam_http`. To use any uppercase
 letter is invalid.
").
set_header(Response, Key, Value) ->
    Headers = gleam@list:key_set(erlang:element(3, Response), string:lowercase(Key), Value),
    {response, erlang:element(2, Response), Headers, erlang:element(4, Response)}.

-spec prepend_header(response(EGY), binary(), binary()) -> response(EGY).
-doc(~" Prepend the header with the given value under the given header key.

 Similar to `set_header` except if the header already exists it prepends
 another header with the same key.

 Header keys are always lowercase in `gleam_http`. To use any uppercase
 letter is invalid.
").
prepend_header(Response, Key, Value) ->
    Headers = [{string:lowercase(Key), Value} | erlang:element(3, Response)],
    {response, erlang:element(2, Response), Headers, erlang:element(4, Response)}.

-spec map(response(EHF), fun((EHF) -> EHH)) -> response(EHH).
-doc(~" Update the body of a response using a given function.
").
map(Response, Transform) ->
    _pipe = erlang:element(4, Response),
    _pipe@1 = Transform(_pipe),
    fun(_capture) ->
        set_body(Response, _capture)
    end(_pipe@1).

-spec redirect(binary()) -> response(binary()).
-doc(~" Create a response that redirects to the given uri.
").
redirect(Uri) ->
    {response, 303, [{~"location", Uri}], gleam@string:append(~"You are being redirected to ", Uri)}.

-spec get_cookies(response(any())) -> list({binary(), binary()}).
-doc(~" Fetch the cookies sent in a response.

 Badly formed cookies will be discarded.
").
get_cookies(Resp) ->
    {response, _, Headers, _} = Resp,
    gleam@list:flat_map(Headers, fun(Header) ->
        case Header of
            {~"set-cookie", Value} ->
                gleam@http@cookie:parse(Value);

            _ ->
                []
        end
    end).

-spec set_cookie(response(EHN), binary(), binary(), gleam@http@cookie:attributes()) -> response(EHN).
-doc(~" Set a cookie value for a client
").
set_cookie(Response, Name, Value, Attributes) ->
    prepend_header(Response, ~"set-cookie", gleam@http@cookie:set_header(Name, Value, Attributes)).

-spec expire_cookie(response(EHQ), binary(), gleam@http@cookie:attributes()) -> response(EHQ).
-doc(~" Expire a cookie value for a client

 Note: The attributes value should be the same as when the response cookie was set.").
expire_cookie(Response, Name, Attributes) ->
    Attrs = {attributes, {some, 0}, erlang:element(3, Attributes), erlang:element(4, Attributes), erlang:element(5, Attributes), erlang:element(6, Attributes), erlang:element(7, Attributes)},
    set_cookie(Response, Name, ~"", Attrs).

