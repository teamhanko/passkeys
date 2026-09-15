-module(gleam@http).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([parse_method/1, method_to_string/1, scheme_to_string/1, scheme_from_string/1, parse_multipart_headers/2, parse_multipart_body/2, parse_content_disposition/1]).
-export_type([method/0, scheme/0, multipart_headers/0, multipart_body/0, content_disposition/0]).
-moduledoc(~" Functions and types for working with HTTP Gleam.").

-type method() :: get | post | patch | put | delete | head | options | trace | connect | {other, binary()}.

-type scheme() :: http | https.

-type multipart_headers() :: {multipart_headers, list({binary(), binary()}), bitstring()} | {more_required_for_headers, fun((bitstring()) -> {ok, multipart_headers()} | {error, nil})}.

-type multipart_body() :: {multipart_body, bitstring(), boolean(), bitstring()} | {more_required_for_body, bitstring(), fun((bitstring()) -> {ok, multipart_body()} | {error, nil})}.

-type content_disposition() :: {content_disposition, binary(), list({binary(), binary()})}.

-spec is_valid_token_loop(binary()) -> boolean().
is_valid_token_loop(Token) ->
    case Token of
        ~"" ->
            true;

        <<"!"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"#"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"$"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"%"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"&"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"'"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"*"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"+"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"-"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"."/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"^"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"_"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"`"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"|"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"~"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"0"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"1"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"2"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"3"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"4"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"5"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"6"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"7"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"8"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"9"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"A"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"B"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"C"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"D"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"E"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"F"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"G"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"H"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"I"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"J"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"K"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"L"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"M"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"N"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"O"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"P"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"Q"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"R"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"S"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"T"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"U"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"V"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"W"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"X"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"Y"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"Z"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"a"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"b"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"c"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"d"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"e"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"f"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"g"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"h"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"i"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"j"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"k"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"l"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"m"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"n"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"o"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"p"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"q"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"r"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"s"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"t"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"u"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"v"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"w"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"x"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"y"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        <<"z"/utf8, Rest/binary>> ->
            is_valid_token_loop(Rest);

        _ ->
            false
    end.

-spec is_valid_token(binary()) -> boolean().
is_valid_token(Token) ->
    case Token of
        ~"" ->
            false;

        _ ->
            is_valid_token_loop(Token)
    end.

-spec parse_method(binary()) -> {ok, method()} | {error, nil}.
parse_method(Method) ->
    case Method of
        ~"CONNECT" ->
            {ok, connect};

        ~"DELETE" ->
            {ok, delete};

        ~"GET" ->
            {ok, get};

        ~"HEAD" ->
            {ok, head};

        ~"OPTIONS" ->
            {ok, options};

        ~"PATCH" ->
            {ok, patch};

        ~"POST" ->
            {ok, post};

        ~"PUT" ->
            {ok, put};

        ~"TRACE" ->
            {ok, trace};

        Method@1 ->
            case is_valid_token(Method@1) of
                true ->
                    {ok, {other, Method@1}};

                false ->
                    {error, nil}
            end
    end.

-spec method_to_string(method()) -> binary().
method_to_string(Method) ->
    case Method of
        connect ->
            ~"CONNECT";

        delete ->
            ~"DELETE";

        get ->
            ~"GET";

        head ->
            ~"HEAD";

        options ->
            ~"OPTIONS";

        patch ->
            ~"PATCH";

        post ->
            ~"POST";

        put ->
            ~"PUT";

        trace ->
            ~"TRACE";

        {other, Method@1} ->
            Method@1
    end.

-spec scheme_to_string(scheme()) -> binary().
-doc(~" Convert a scheme into a string.

 # Examples

 ```gleam
 assert \"http\" == scheme_to_string(Http)
 assert \"https\" == scheme_to_string(Https)
 ```
").
scheme_to_string(Scheme) ->
    case Scheme of
        http ->
            ~"http";

        https ->
            ~"https"
    end.

-spec scheme_from_string(binary()) -> {ok, scheme()} | {error, nil}.
-doc(~" Parse a HTTP scheme from a string

 # Examples

 ```gleam
 assert Ok(Http) == scheme_from_string(\"http\")
 assert Error(Nil) == scheme_from_string(\"ftp\")
 ```
").
scheme_from_string(Scheme) ->
    case string:lowercase(Scheme) of
        ~"http" ->
            {ok, http};

        ~"https" ->
            {ok, https};

        _ ->
            {error, nil}
    end.

-spec more_please_headers(bitstring(), fun((bitstring()) -> {ok, multipart_headers()} | {error, nil})) -> {ok, multipart_headers()} | {error, nil}.
more_please_headers(Existing, Continuation) ->
    {ok, {more_required_for_headers, fun(More) ->
        gleam@bool:guard(More =:= <<>>, {error, nil}, fun() ->
            Continuation(<<Existing/bitstring, More/bitstring>>)
        end)
    end}}.

-spec parse_header_value_loop(bitstring(), list({binary(), binary()}), binary(), bitstring()) -> {ok, multipart_headers()} | {error, nil}.
parse_header_value_loop(Data, Headers, Name, Value) ->
    case Data of
        <<>> ->
            more_please_headers(Data, fun(Data@1) ->
                parse_header_value_loop(Data@1, Headers, Name, Value)
            end);

        <<_>> ->
            more_please_headers(Data, fun(Data@1) ->
                parse_header_value_loop(Data@1, Headers, Name, Value)
            end);

        <<_, _>> ->
            more_please_headers(Data, fun(Data@1) ->
                parse_header_value_loop(Data@1, Headers, Name, Value)
            end);

        <<_, _, _>> ->
            more_please_headers(Data, fun(Data@1) ->
                parse_header_value_loop(Data@1, Headers, Name, Value)
            end);

        <<"\r\n\r\n"/utf8, Data@1/binary>> ->
            gleam@result:map(gleam@bit_array:to_string(Value), fun(Value@1) ->
                Headers@1 = lists:reverse([{string:lowercase(Name), Value@1} | Headers]),
                {multipart_headers, Headers@1, Data@1}
            end);

        <<"\r\n "/utf8, Data@2/binary>> ->
            parse_header_value_loop(Data@2, Headers, Name, Value);

        <<"\r\n\t"/utf8, Data@2/binary>> ->
            parse_header_value_loop(Data@2, Headers, Name, Value);

        <<"\r\n"/utf8, Data@3/binary>> ->
            gleam@result:'try'(gleam@bit_array:to_string(Value), fun(Value@1) ->
                Headers@1 = [{string:lowercase(Name), Value@1} | Headers],
                parse_header_name(Data@3, Headers@1)
            end);

        <<Char, Rest/binary>> ->
            parse_header_value_loop(Rest, Headers, Name, <<Value/bitstring, Char>>);

        _ ->
            {error, nil}
    end.

-spec parse_header_value(bitstring(), list({binary(), binary()}), binary()) -> {ok, multipart_headers()} | {error, nil}.
parse_header_value(Data, Headers, Name) ->
    case Data of
        <<" "/utf8, Rest/bitstring>> ->
            parse_header_value(Rest, Headers, Name);

        <<"\t"/utf8, Rest/bitstring>> ->
            parse_header_value(Rest, Headers, Name);

        <<_, _/bitstring>> ->
            parse_header_value_loop(Data, Headers, Name, <<>>);

        _ ->
            more_please_headers(Data, fun(_capture) ->
                parse_header_value(_capture, Headers, Name)
            end)
    end.

-spec parse_header_name_loop(bitstring(), list({binary(), binary()}), bitstring()) -> {ok, multipart_headers()} | {error, nil}.
parse_header_name_loop(Data, Headers, Name) ->
    case Data of
        <<":"/utf8, Data@1/bitstring>> ->
            case gleam@bit_array:to_string(Name) of
                {ok, Name@1} ->
                    parse_header_value(Data@1, Headers, Name@1);

                {error, nil} ->
                    {error, nil}
            end;

        <<Char, Data@2/bitstring>> ->
            parse_header_name_loop(Data@2, Headers, <<Name/bitstring, Char>>);

        _ ->
            more_please_headers(Data, fun(_capture) ->
                parse_header_name_loop(_capture, Headers, Name)
            end)
    end.

-spec parse_header_name(bitstring(), list({binary(), binary()})) -> {ok, multipart_headers()} | {error, nil}.
parse_header_name(Data, Headers) ->
    case Data of
        <<" "/utf8, Rest/bitstring>> ->
            parse_header_name(Rest, Headers);

        <<"\t"/utf8, Rest/bitstring>> ->
            parse_header_name(Rest, Headers);

        <<_, _/bitstring>> ->
            parse_header_name_loop(Data, Headers, <<>>);

        _ ->
            more_please_headers(Data, fun(_capture) ->
                parse_header_name(_capture, Headers)
            end)
    end.

-spec do_parse_headers(bitstring()) -> {ok, multipart_headers()} | {error, nil}.
do_parse_headers(Data) ->
    case Data of
        <<"\r\n\r\n"/utf8, Data@1/binary>> ->
            {ok, {multipart_headers, [], Data@1}};

        <<"\r\n"/utf8, Data@2/binary>> ->
            parse_header_name(Data@2, []);

        <<"\r"/utf8>> ->
            more_please_headers(Data, fun do_parse_headers/1);

        <<>> ->
            more_please_headers(Data, fun do_parse_headers/1);

        _ ->
            {error, nil}
    end.

-spec skip_preamble(bitstring(), bitstring(), integer()) -> {ok, multipart_headers()} | {error, nil}.
skip_preamble(Data, Boundary, Boundary_bytes) ->
    case Data of
        <<"\r\n--"/utf8, Rest/binary>> ->
            case Rest of
                <<Found:Boundary_bytes/binary, Rest@1/bitstring>> when Found =:= Boundary ->
                    do_parse_headers(Rest@1);

                <<_:Boundary_bytes/binary, _/bitstring>> ->
                    skip_preamble(Rest, Boundary, Boundary_bytes);

                _ ->
                    more_please_headers(Data, fun(_capture) ->
                        skip_preamble(_capture, Boundary, Boundary_bytes)
                    end)
            end;

        <<>> ->
            more_please_headers(Data, fun(_capture) ->
                skip_preamble(_capture, Boundary, Boundary_bytes)
            end);

        <<"\r"/utf8>> ->
            more_please_headers(Data, fun(_capture) ->
                skip_preamble(_capture, Boundary, Boundary_bytes)
            end);

        <<"\r\n"/utf8>> ->
            more_please_headers(Data, fun(_capture) ->
                skip_preamble(_capture, Boundary, Boundary_bytes)
            end);

        <<"\r\n-"/utf8>> ->
            more_please_headers(Data, fun(_capture) ->
                skip_preamble(_capture, Boundary, Boundary_bytes)
            end);

        <<_, Data@1/binary>> ->
            skip_preamble(Data@1, Boundary, Boundary_bytes);

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => ~"unreachable",
                file => ~"src/gleam/http.gleam",
                module => ~"gleam/http",
                function => ~"skip_preamble",
                line => 356
            })
    end.

-spec do_parse_multipart_headers(bitstring(), bitstring(), integer()) -> {ok, multipart_headers()} | {error, nil}.
do_parse_multipart_headers(Data, Boundary, Boundary_bytes) ->
    case Data of
        <<"--"/utf8, Found:Boundary_bytes/binary, Rest/bitstring>> when Found =:= Boundary ->
            case Rest of
                <<"--"/utf8, Rest@1/bitstring>> ->
                    {ok, {multipart_headers, [], Rest@1}};

                <<_, _, _/bitstring>> ->
                    do_parse_headers(Rest);

                _ ->
                    more_please_headers(Data, fun(Data@1) ->
                        do_parse_multipart_headers(Data@1, Boundary, Boundary_bytes)
                    end)
            end;

        _ ->
            skip_preamble(Data, Boundary, Boundary_bytes)
    end.

-spec parse_multipart_headers(bitstring(), binary()) -> {ok, multipart_headers()} | {error, nil}.
-doc(~" Parse the headers for part of a multipart message, as defined in RFC 2045.

 This function skips any preamble before the boundary. The preamble may be
 retrieved using `parse_multipart_body`.

 This function will accept input of any size, it is up to the caller to limit
 it if needed.

 To enable streaming parsing of multipart messages, this function will return
 a continuation if there is not enough data to fully parse the headers.
 Further information is available in the documentation for `MultipartBody`.
").
parse_multipart_headers(Data, Boundary) ->
    Boundary@1 = gleam_stdlib:identity(Boundary),
    Boundary_bytes = erlang:byte_size(Boundary@1),
    do_parse_multipart_headers(Data, Boundary@1, Boundary_bytes).

-spec more_please_body(bitstring(), bitstring(), fun((bitstring()) -> {ok, multipart_body()} | {error, nil})) -> {ok, multipart_body()} | {error, nil}.
more_please_body(Chunk, Existing, Continuation) ->
    {ok, {more_required_for_body, Chunk, fun(More) ->
        gleam@bool:guard(More =:= <<>>, {error, nil}, fun() ->
            Continuation(<<Existing/bitstring, More/bitstring>>)
        end)
    end}}.

-spec parse_body_loop(bitstring(), bitstring(), integer(), bitstring()) -> {ok, multipart_body()} | {error, nil}.
parse_body_loop(Data, Boundary, Boundary_bytes, Body) ->
    case Data of
        <<>> ->
            more_please_body(Body, Data, fun(Data@1) ->
                parse_body_loop(Data@1, Boundary, Boundary_bytes, <<>>)
            end);

        <<"\r"/utf8>> ->
            more_please_body(Body, Data, fun(Data@1) ->
                parse_body_loop(Data@1, Boundary, Boundary_bytes, <<>>)
            end);

        <<"\r\n"/utf8, Rest/bitstring>> ->
            case Rest of
                <<"--"/utf8, Found:Boundary_bytes/binary, "\r"/utf8, "\n"/utf8, _/bitstring>> when Found =:= Boundary ->
                    {ok, {multipart_body, Body, false, Rest}};

                <<"--"/utf8, Found@1:Boundary_bytes/binary, "-"/utf8, "-"/utf8, Rest@1/bitstring>> when Found@1 =:= Boundary ->
                    {ok, {multipart_body, Body, true, Rest@1}};

                <<_, _, _:Boundary_bytes/binary, _, _, _/bitstring>> ->
                    parse_body_loop(Rest, Boundary, Boundary_bytes, <<Body/bitstring, "\r\n"/utf8>>);

                _ ->
                    more_please_body(Body, Data, fun(Data@1) ->
                        parse_body_loop(Data@1, Boundary, Boundary_bytes, <<>>)
                    end)
            end;

        <<Char, Data@1/bitstring>> ->
            parse_body_loop(Data@1, Boundary, Boundary_bytes, <<Body/bitstring, Char>>);

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => ~"unreachable",
                file => ~"src/gleam/http.gleam",
                module => ~"gleam/http",
                function => ~"parse_body_loop",
                line => 543
            })
    end.

-spec do_parse_multipart_body(bitstring(), bitstring(), integer()) -> {ok, multipart_body()} | {error, nil}.
do_parse_multipart_body(Data, Boundary, Boundary_bytes) ->
    case Data of
        <<"--"/utf8, Found:Boundary_bytes/binary, _/binary>> when Found =:= Boundary ->
            {ok, {multipart_body, <<>>, false, Data}};

        _ ->
            parse_body_loop(Data, Boundary, Boundary_bytes, <<>>)
    end.

-spec parse_multipart_body(bitstring(), binary()) -> {ok, multipart_body()} | {error, nil}.
-doc(~" Parse the body for part of a multipart message, as defined in RFC 2045. The
 body is everything until the next boundary. This function is generally to be
 called after calling `parse_multipart_headers` for a given part.

 This function will accept input of any size, it is up to the caller to limit
 it if needed.

 To enable streaming parsing of multipart messages, this function will return
 a continuation if there is not enough data to fully parse the body, along
 with the data that has been parsed so far. Further information is available
 in the documentation for `MultipartBody`.
").
parse_multipart_body(Data, Boundary) ->
    Boundary@1 = gleam_stdlib:identity(Boundary),
    Boundary_bytes = erlang:byte_size(Boundary@1),
    do_parse_multipart_body(Data, Boundary@1, Boundary_bytes).

-spec parse_rfc_2045_parameter_unquoted_value(binary(), binary(), binary()) -> {{binary(), binary()}, binary()}.
parse_rfc_2045_parameter_unquoted_value(Header, Name, Value) ->
    case gleam_stdlib:string_pop_grapheme(Header) of
        {error, nil} ->
            {{Name, Value}, Header};

        {ok, {~";", Rest}} ->
            {{Name, Value}, Rest};

        {ok, {~" ", Rest}} ->
            {{Name, Value}, Rest};

        {ok, {~"\t", Rest}} ->
            {{Name, Value}, Rest};

        {ok, {Grapheme, Rest@1}} ->
            parse_rfc_2045_parameter_unquoted_value(Rest@1, Name, <<Value/binary, Grapheme/binary>>)
    end.

-spec parse_rfc_2045_parameter_quoted_value(binary(), binary(), binary()) -> {ok, {{binary(), binary()}, binary()}} | {error, nil}.
parse_rfc_2045_parameter_quoted_value(Header, Name, Value) ->
    case gleam_stdlib:string_pop_grapheme(Header) of
        {error, nil} ->
            {error, nil};

        {ok, {~"\"", Rest}} ->
            {ok, {{Name, Value}, Rest}};

        {ok, {~"\\", Rest@1}} ->
            gleam@result:'try'(gleam_stdlib:string_pop_grapheme(Rest@1), fun(_use0) ->
                {Grapheme, Rest@2} = _use0,
                parse_rfc_2045_parameter_quoted_value(Rest@2, Name, <<Value/binary, Grapheme/binary>>)
            end);

        {ok, {Grapheme, Rest@2}} ->
            parse_rfc_2045_parameter_quoted_value(Rest@2, Name, <<Value/binary, Grapheme/binary>>)
    end.

-spec parse_rfc_2045_parameter_value(binary(), binary()) -> {ok, {{binary(), binary()}, binary()}} | {error, nil}.
parse_rfc_2045_parameter_value(Header, Name) ->
    case gleam_stdlib:string_pop_grapheme(Header) of
        {error, nil} ->
            {error, nil};

        {ok, {~"\"", Rest}} ->
            parse_rfc_2045_parameter_quoted_value(Rest, Name, ~"");

        {ok, {Grapheme, Rest@1}} ->
            {ok, parse_rfc_2045_parameter_unquoted_value(Rest@1, Name, Grapheme)}
    end.

-spec parse_rfc_2045_parameter(binary(), binary()) -> {ok, {{binary(), binary()}, binary()}} | {error, nil}.
parse_rfc_2045_parameter(Header, Name) ->
    gleam@result:'try'(gleam_stdlib:string_pop_grapheme(Header), fun(_use0) ->
        {Grapheme, Rest} = _use0,
        case Grapheme of
            ~"=" ->
                parse_rfc_2045_parameter_value(Rest, Name);

            _ ->
                parse_rfc_2045_parameter(Rest, <<Name/binary, (string:lowercase(Grapheme))/binary>>)
        end
    end).

-spec parse_rfc_2045_parameters(binary(), list({binary(), binary()})) -> {ok, list({binary(), binary()})} | {error, nil}.
parse_rfc_2045_parameters(Header, Parameters) ->
    case gleam_stdlib:string_pop_grapheme(Header) of
        {error, nil} ->
            {ok, lists:reverse(Parameters)};

        {ok, {~";", Rest}} ->
            parse_rfc_2045_parameters(Rest, Parameters);

        {ok, {~" ", Rest}} ->
            parse_rfc_2045_parameters(Rest, Parameters);

        {ok, {~"\t", Rest}} ->
            parse_rfc_2045_parameters(Rest, Parameters);

        {ok, {Grapheme, Rest@1}} ->
            Acc = string:lowercase(Grapheme),
            gleam@result:'try'(parse_rfc_2045_parameter(Rest@1, Acc), fun(_use0) ->
                {Parameter, Rest@2} = _use0,
                parse_rfc_2045_parameters(Rest@2, [Parameter | Parameters])
            end)
    end.

-spec parse_content_disposition_type(binary(), binary()) -> {ok, content_disposition()} | {error, nil}.
parse_content_disposition_type(Header, Name) ->
    case gleam_stdlib:string_pop_grapheme(Header) of
        {error, nil} ->
            {ok, {content_disposition, Name, []}};

        {ok, {~" ", Rest}} ->
            Result = parse_rfc_2045_parameters(Rest, []),
            gleam@result:map(Result, fun(Parameters) ->
                {content_disposition, Name, Parameters}
            end);

        {ok, {~"\t", Rest}} ->
            Result = parse_rfc_2045_parameters(Rest, []),
            gleam@result:map(Result, fun(Parameters) ->
                {content_disposition, Name, Parameters}
            end);

        {ok, {~";", Rest}} ->
            Result = parse_rfc_2045_parameters(Rest, []),
            gleam@result:map(Result, fun(Parameters) ->
                {content_disposition, Name, Parameters}
            end);

        {ok, {Grapheme, Rest@1}} ->
            parse_content_disposition_type(Rest@1, <<Name/binary, (string:lowercase(Grapheme))/binary>>)
    end.

-spec parse_content_disposition(binary()) -> {ok, content_disposition()} | {error, nil}.
parse_content_disposition(Header) ->
    parse_content_disposition_type(Header, ~"").

