-module(gleam@http@request).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([to_uri/1, from_uri/1, get_header/2, set_header/3, prepend_header/3, set_body/2, map/2, path_segments/1, get_query/1, set_query/2, set_method/2, new/0, to/1, set_scheme/2, set_host/2, set_port/2, set_path/2, set_cookie/3, get_cookies/1, remove_cookie/2]).
-export_type([request/1]).

-type request(DWC) :: {request, gleam@http:method(), list({binary(), binary()}), DWC, gleam@http:scheme(), binary(), gleam@option:option(integer()), binary(), gleam@option:option(binary())}.

-spec to_uri(request(any())) -> gleam@uri:uri().
-doc(~" Return the uri that a request was sent to.
").
to_uri(Request) ->
    {uri, {some, gleam@http:scheme_to_string(erlang:element(5, Request))}, none, {some, erlang:element(6, Request)}, erlang:element(7, Request), erlang:element(8, Request), erlang:element(9, Request), none}.

-spec from_uri(gleam@uri:uri()) -> {ok, request(binary())} | {error, nil}.
-doc(~" Construct a request from a URI.
").
from_uri(Uri) ->
    gleam@result:'try'(begin
        _pipe = erlang:element(2, Uri),
        _pipe@1 = gleam@option:unwrap(_pipe, ~""),
        gleam@http:scheme_from_string(_pipe@1)
    end, fun(Scheme) ->
        gleam@result:'try'(begin
            _pipe@2 = erlang:element(4, Uri),
            gleam@option:to_result(_pipe@2, nil)
        end, fun(Host) ->
            Req = {request, get, [], ~"", Scheme, Host, erlang:element(5, Uri), erlang:element(6, Uri), erlang:element(7, Uri)},
            {ok, Req}
        end)
    end).

-spec get_header(request(any()), binary()) -> {ok, binary()} | {error, nil}.
-doc(~" Get the value for a given header.

 If the request does not have that header then `Error(Nil)` is returned.

 Header keys are always lowercase in `gleam_http`. To use any uppercase
 letter is invalid.
").
get_header(Request, Key) ->
    gleam@list:key_find(erlang:element(3, Request), string:lowercase(Key)).

-spec set_header(request(DWM), binary(), binary()) -> request(DWM).
-doc(~" Set the header with the given value under the given header key.

 If already present, it is replaced.

 Header keys are always lowercase in `gleam_http`. To use any uppercase
 letter is invalid.
").
set_header(Request, Key, Value) ->
    Headers = gleam@list:key_set(erlang:element(3, Request), string:lowercase(Key), Value),
    {request, erlang:element(2, Request), Headers, erlang:element(4, Request), erlang:element(5, Request), erlang:element(6, Request), erlang:element(7, Request), erlang:element(8, Request), erlang:element(9, Request)}.

-spec prepend_header(request(DWP), binary(), binary()) -> request(DWP).
-doc(~" Prepend the header with the given value under the given header key.

 Similar to `set_header` except if the header already exists it prepends
 another header with the same key.

 Header keys are always lowercase in `gleam_http`. To use any uppercase
 letter is invalid.
").
prepend_header(Request, Key, Value) ->
    Headers = [{string:lowercase(Key), Value} | erlang:element(3, Request)],
    {request, erlang:element(2, Request), Headers, erlang:element(4, Request), erlang:element(5, Request), erlang:element(6, Request), erlang:element(7, Request), erlang:element(8, Request), erlang:element(9, Request)}.

-spec set_body(request(any()), DWU) -> request(DWU).
-doc(~" Set the body of the request, overwriting any existing body.
").
set_body(Req, Body) ->
    {request, erlang:element(2, Req), erlang:element(3, Req), Body, erlang:element(5, Req), erlang:element(6, Req), erlang:element(7, Req), erlang:element(8, Req), erlang:element(9, Req)}.

-spec map(request(DWW), fun((DWW) -> DWY)) -> request(DWY).
-doc(~" Update the body of a request using a given function.
").
map(Request, Transform) ->
    _pipe = erlang:element(4, Request),
    _pipe@1 = Transform(_pipe),
    fun(_capture) ->
        set_body(Request, _capture)
    end(_pipe@1).

-spec path_segments(request(any())) -> list(binary()).
-doc(~" Return the non-empty segments of a request path.

 # Examples

 ```gleam
 > new()
 > |> set_path(\"/one/two/three\")
 > |> path_segments
 [\"one\", \"two\", \"three\"]
 ```
").
path_segments(Request) ->
    _pipe = erlang:element(8, Request),
    gleam@uri:path_segments(_pipe).

-spec get_query(request(any())) -> {ok, list({binary(), binary()})} | {error, nil}.
-doc(~" Decode the query of a request.").
get_query(Request) ->
    case erlang:element(9, Request) of
        {some, Query_string} ->
            gleam_stdlib:parse_query(Query_string);

        none ->
            {ok, []}
    end.

-spec set_query(request(DXI), list({binary(), binary()})) -> request(DXI).
-doc(~" Set the query of the request.
 Query params will be percent encoded before being added to the Request.
").
set_query(Req, Query) ->
    Query@1 = begin
        _pipe = gleam@list:map(Query, fun(Pair) ->
            {Key, Value} = Pair,
            <<<<(gleam_stdlib:percent_encode(Key))/binary, "="/utf8>>/binary, (gleam_stdlib:percent_encode(Value))/binary>>
        end),
        _pipe@1 = gleam@string:join(_pipe, ~"&"),
        {some, _pipe@1}
    end,
    {request, erlang:element(2, Req), erlang:element(3, Req), erlang:element(4, Req), erlang:element(5, Req), erlang:element(6, Req), erlang:element(7, Req), erlang:element(8, Req), Query@1}.

-spec set_method(request(DXM), gleam@http:method()) -> request(DXM).
-doc(~" Set the method of the request.
").
set_method(Req, Method) ->
    {request, Method, erlang:element(3, Req), erlang:element(4, Req), erlang:element(5, Req), erlang:element(6, Req), erlang:element(7, Req), erlang:element(8, Req), erlang:element(9, Req)}.

-spec new() -> request(binary()).
-doc(~" A request with commonly used default values. This request can be used as
 an initial value and then update to create the desired request.
").
new() ->
    {request, get, [], ~"", https, ~"localhost", none, ~"", none}.

-spec to(binary()) -> {ok, request(binary())} | {error, nil}.
-doc(~" Construct a request from a URL string
").
to(Url) ->
    _pipe = Url,
    _pipe@1 = gleam_stdlib:uri_parse(_pipe),
    gleam@result:'try'(_pipe@1, fun from_uri/1).

-spec set_scheme(request(DXT), gleam@http:scheme()) -> request(DXT).
-doc(~" Set the scheme (protocol) of the request.
").
set_scheme(Req, Scheme) ->
    {request, erlang:element(2, Req), erlang:element(3, Req), erlang:element(4, Req), Scheme, erlang:element(6, Req), erlang:element(7, Req), erlang:element(8, Req), erlang:element(9, Req)}.

-spec set_host(request(DXW), binary()) -> request(DXW).
-doc(~" Set the host of the request.
").
set_host(Req, Host) ->
    {request, erlang:element(2, Req), erlang:element(3, Req), erlang:element(4, Req), erlang:element(5, Req), Host, erlang:element(7, Req), erlang:element(8, Req), erlang:element(9, Req)}.

-spec set_port(request(DXZ), integer()) -> request(DXZ).
-doc(~" Set the port of the request.
").
set_port(Req, Port) ->
    {request, erlang:element(2, Req), erlang:element(3, Req), erlang:element(4, Req), erlang:element(5, Req), erlang:element(6, Req), {some, Port}, erlang:element(8, Req), erlang:element(9, Req)}.

-spec set_path(request(DYC), binary()) -> request(DYC).
-doc(~" Set the path of the request.
").
set_path(Req, Path) ->
    {request, erlang:element(2, Req), erlang:element(3, Req), erlang:element(4, Req), erlang:element(5, Req), erlang:element(6, Req), erlang:element(7, Req), Path, erlang:element(9, Req)}.

-spec set_cookie(request(DYF), binary(), binary()) -> request(DYF).
-doc(~" Set a cookie on a request, replacing any previous cookie with that name.

 All cookies should be stored in a single header named `cookie`.
 There should be at most one header with the name `cookie`, otherwise this
 function cannot guarentee that previous cookies with the same name are
 replaced.
").
set_cookie(Req, Name, Value) ->
    {Cookies, Headers} = begin
        _pipe = gleam@list:key_pop(erlang:element(3, Req), ~"cookie"),
        gleam@result:unwrap(_pipe, {~"", erlang:element(3, Req)})
    end,
    Cookies@1 = begin
        _pipe@1 = gleam@http@cookie:parse(Cookies),
        _pipe@2 = gleam@list:key_set(_pipe@1, Name, Value),
        _pipe@3 = gleam@list:map(_pipe@2, fun(Pair) ->
            <<<<(erlang:element(1, Pair))/binary, "="/utf8>>/binary, (erlang:element(2, Pair))/binary>>
        end),
        gleam@string:join(_pipe@3, ~"; ")
    end,
    {request, erlang:element(2, Req), [{~"cookie", Cookies@1} | Headers], erlang:element(4, Req), erlang:element(5, Req), erlang:element(6, Req), erlang:element(7, Req), erlang:element(8, Req), erlang:element(9, Req)}.

-spec get_cookies(request(any())) -> list({binary(), binary()}).
-doc(~" Fetch the cookies sent in a request.

 Note badly formed cookie pairs will be ignored.
 RFC6265 specifies that invalid cookie names/attributes should be ignored.").
get_cookies(Req) ->
    {request, _, Headers, _, _, _, _, _, _} = Req,
    gleam@list:flat_map(Headers, fun(Header) ->
        case Header of
            {~"cookie", Value} ->
                gleam@http@cookie:parse(Value);

            _ ->
                []
        end
    end).

-spec remove_cookie(request(DYL), binary()) -> request(DYL).
-doc(~" Remove a cookie from a request

 Remove a cookie from the request. If no cookie is found return the request
 unchanged. This will not remove the cookie from the client.").
remove_cookie(Req, Name) ->
    case gleam@list:key_pop(erlang:element(3, Req), ~"cookie") of
        {ok, {Cookies_string, Headers}} ->
            New_cookies_string = begin
                _pipe = gleam@http@cookie:parse(Cookies_string),
                _pipe@1 = gleam@list:filter_map(_pipe, fun(Cookie) ->
                    case Cookie of
                        {Cookie_name, _} when Cookie_name =:= Name ->
                            {error, nil};

                        {Name@1, Value} ->
                            {ok, <<<<Name@1/binary, "="/utf8>>/binary, Value/binary>>}
                    end
                end),
                gleam@string:join(_pipe@1, ~"; ")
            end,
            {request, erlang:element(2, Req), [{~"cookie", New_cookies_string} | Headers], erlang:element(4, Req), erlang:element(5, Req), erlang:element(6, Req), erlang:element(7, Req), erlang:element(8, Req), erlang:element(9, Req)};

        {error, _} ->
            Req
    end.

