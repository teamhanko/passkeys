-module(gleam@uri).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([parse/1, parse_query/1, percent_encode/1, query_to_string/1, percent_decode/1, path_segments/1, to_string/1, origin/1, merge/2]).
-export_type([uri/0]).
-moduledoc(~" Utilities for working with URIs

 This module provides functions for working with URIs (for example, parsing
 URIs or encoding query strings). The functions in this module are implemented
 according to [RFC 3986](https://tools.ietf.org/html/rfc3986).

 Query encoding (Form encoding) is defined in the
 [W3C specification](https://www.w3.org/TR/html52/sec-forms.html#urlencoded-form-data).").

-type uri() :: {uri, gleam@option:option(binary()), gleam@option:option(binary()), gleam@option:option(binary()), gleam@option:option(integer()), binary(), gleam@option:option(binary()), gleam@option:option(binary())}.

-file("src/gleam/uri.gleam", 503).
-spec parse_fragment(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_fragment(Rest, Pieces) ->
    {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), {some, Rest}}}.

-file("src/gleam/uri.gleam", 475).
-spec parse_query_with_question_mark_loop(binary(), binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_query_with_question_mark_loop(Original, Uri_string, Pieces, Size) ->
    case Uri_string of
        <<"#"/utf8, Rest/binary>> when Size =:= 0 ->
            parse_fragment(Rest, Pieces);

        <<"#"/utf8, Rest@1/binary>> ->
            Query = binary:part(Original, 0, Size),
            Pieces@1 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), {some, Query}, erlang:element(8, Pieces)},
            parse_fragment(Rest@1, Pieces@1);

        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), {some, Original}, erlang:element(8, Pieces)}};

        _ ->
            {_, Rest@2} = gleam_stdlib:string_pop_codeunit(Uri_string),
            parse_query_with_question_mark_loop(Original, Rest@2, Pieces, Size + 1)
    end.

-file("src/gleam/uri.gleam", 468).
-spec parse_query_with_question_mark(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_query_with_question_mark(Uri_string, Pieces) ->
    parse_query_with_question_mark_loop(Uri_string, Uri_string, Pieces, 0).

-file("src/gleam/uri.gleam", 434).
-spec parse_path_loop(binary(), binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_path_loop(Original, Uri_string, Pieces, Size) ->
    case Uri_string of
        <<"?"/utf8, Rest/binary>> ->
            Path = binary:part(Original, 0, Size),
            Pieces@1 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), Path, erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_query_with_question_mark(Rest, Pieces@1);

        <<"#"/utf8, Rest@1/binary>> ->
            Path@1 = binary:part(Original, 0, Size),
            Pieces@2 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), Path@1, erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_fragment(Rest@1, Pieces@2);

        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), Original, erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        _ ->
            {_, Rest@2} = gleam_stdlib:string_pop_codeunit(Uri_string),
            parse_path_loop(Original, Rest@2, Pieces, Size + 1)
    end.

-file("src/gleam/uri.gleam", 430).
-spec parse_path(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_path(Uri_string, Pieces) ->
    parse_path_loop(Uri_string, Uri_string, Pieces, 0).

-file("src/gleam/uri.gleam", 385).
-spec parse_port_loop(binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_port_loop(Uri_string, Pieces, Port) ->
    case Uri_string of
        <<"0"/utf8, Rest/binary>> ->
            parse_port_loop(Rest, Pieces, Port * 10);

        <<"1"/utf8, Rest@1/binary>> ->
            parse_port_loop(Rest@1, Pieces, (Port * 10) + 1);

        <<"2"/utf8, Rest@2/binary>> ->
            parse_port_loop(Rest@2, Pieces, (Port * 10) + 2);

        <<"3"/utf8, Rest@3/binary>> ->
            parse_port_loop(Rest@3, Pieces, (Port * 10) + 3);

        <<"4"/utf8, Rest@4/binary>> ->
            parse_port_loop(Rest@4, Pieces, (Port * 10) + 4);

        <<"5"/utf8, Rest@5/binary>> ->
            parse_port_loop(Rest@5, Pieces, (Port * 10) + 5);

        <<"6"/utf8, Rest@6/binary>> ->
            parse_port_loop(Rest@6, Pieces, (Port * 10) + 6);

        <<"7"/utf8, Rest@7/binary>> ->
            parse_port_loop(Rest@7, Pieces, (Port * 10) + 7);

        <<"8"/utf8, Rest@8/binary>> ->
            parse_port_loop(Rest@8, Pieces, (Port * 10) + 8);

        <<"9"/utf8, Rest@9/binary>> ->
            parse_port_loop(Rest@9, Pieces, (Port * 10) + 9);

        <<"?"/utf8, Rest@10/binary>> ->
            Pieces@1 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), {some, Port}, erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_query_with_question_mark(Rest@10, Pieces@1);

        <<"#"/utf8, Rest@11/binary>> ->
            Pieces@2 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), {some, Port}, erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_fragment(Rest@11, Pieces@2);

        <<"/"/utf8, _/binary>> ->
            Pieces@3 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), {some, Port}, erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_path(Uri_string, Pieces@3);

        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), {some, Port}, erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        _ ->
            {error, nil}
    end.

-file("src/gleam/uri.gleam", 350).
-spec parse_port(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_port(Uri_string, Pieces) ->
    case Uri_string of
        <<":0"/utf8, Rest/binary>> ->
            parse_port_loop(Rest, Pieces, 0);

        <<":1"/utf8, Rest@1/binary>> ->
            parse_port_loop(Rest@1, Pieces, 1);

        <<":2"/utf8, Rest@2/binary>> ->
            parse_port_loop(Rest@2, Pieces, 2);

        <<":3"/utf8, Rest@3/binary>> ->
            parse_port_loop(Rest@3, Pieces, 3);

        <<":4"/utf8, Rest@4/binary>> ->
            parse_port_loop(Rest@4, Pieces, 4);

        <<":5"/utf8, Rest@5/binary>> ->
            parse_port_loop(Rest@5, Pieces, 5);

        <<":6"/utf8, Rest@6/binary>> ->
            parse_port_loop(Rest@6, Pieces, 6);

        <<":7"/utf8, Rest@7/binary>> ->
            parse_port_loop(Rest@7, Pieces, 7);

        <<":8"/utf8, Rest@8/binary>> ->
            parse_port_loop(Rest@8, Pieces, 8);

        <<":9"/utf8, Rest@9/binary>> ->
            parse_port_loop(Rest@9, Pieces, 9);

        ~":" ->
            {ok, Pieces};

        ~"" ->
            {ok, Pieces};

        <<"?"/utf8, Rest@10/binary>> ->
            parse_query_with_question_mark(Rest@10, Pieces);

        <<":?"/utf8, Rest@10/binary>> ->
            parse_query_with_question_mark(Rest@10, Pieces);

        <<"#"/utf8, Rest@11/binary>> ->
            parse_fragment(Rest@11, Pieces);

        <<":#"/utf8, Rest@11/binary>> ->
            parse_fragment(Rest@11, Pieces);

        <<"/"/utf8, _/binary>> ->
            parse_path(Uri_string, Pieces);

        <<":"/utf8, Rest@12/binary>> ->
            case Rest@12 of
                <<"/"/utf8, _/binary>> ->
                    parse_path(Rest@12, Pieces);

                _ ->
                    {error, nil}
            end;

        _ ->
            {error, nil}
    end.

-file("src/gleam/uri.gleam", 306).
-spec parse_host_outside_of_brackets_loop(binary(), binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_host_outside_of_brackets_loop(Original, Uri_string, Pieces, Size) ->
    case Uri_string of
        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Original}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        <<":"/utf8, _/binary>> ->
            Host = binary:part(Original, 0, Size),
            Pieces@1 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_port(Uri_string, Pieces@1);

        <<"/"/utf8, _/binary>> ->
            Host@1 = binary:part(Original, 0, Size),
            Pieces@2 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host@1}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_path(Uri_string, Pieces@2);

        <<"?"/utf8, Rest/binary>> ->
            Host@2 = binary:part(Original, 0, Size),
            Pieces@3 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host@2}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_query_with_question_mark(Rest, Pieces@3);

        <<"#"/utf8, Rest@1/binary>> ->
            Host@3 = binary:part(Original, 0, Size),
            Pieces@4 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host@3}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_fragment(Rest@1, Pieces@4);

        _ ->
            {_, Rest@2} = gleam_stdlib:string_pop_codeunit(Uri_string),
            parse_host_outside_of_brackets_loop(Original, Rest@2, Pieces, Size + 1)
    end.

-file("src/gleam/uri.gleam", 299).
-spec parse_host_outside_of_brackets(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_host_outside_of_brackets(Uri_string, Pieces) ->
    parse_host_outside_of_brackets_loop(Uri_string, Uri_string, Pieces, 0).

-file("src/gleam/uri.gleam", 286).
-spec is_valid_host_within_brackets_char(integer()) -> boolean().
is_valid_host_within_brackets_char(Char) ->
    (((((48 >= Char) andalso (Char =< 57)) orelse ((65 >= Char) andalso (Char =< 90))) orelse ((97 >= Char) andalso (Char =< 122))) orelse (Char =:= 58)) orelse (Char =:= 46).

-file("src/gleam/uri.gleam", 226).
-spec parse_host_within_brackets_loop(binary(), binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_host_within_brackets_loop(Original, Uri_string, Pieces, Size) ->
    case Uri_string of
        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Uri_string}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        <<"]"/utf8, Rest/binary>> when Size =:= 0 ->
            parse_port(Rest, Pieces);

        <<"]"/utf8, Rest@1/binary>> ->
            Host = binary:part(Original, 0, Size + 1),
            Pieces@1 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_port(Rest@1, Pieces@1);

        <<"/"/utf8, _/binary>> when Size =:= 0 ->
            parse_path(Uri_string, Pieces);

        <<"/"/utf8, _/binary>> ->
            Host@1 = binary:part(Original, 0, Size),
            Pieces@2 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host@1}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_path(Uri_string, Pieces@2);

        <<"?"/utf8, Rest@2/binary>> when Size =:= 0 ->
            parse_query_with_question_mark(Rest@2, Pieces);

        <<"?"/utf8, Rest@3/binary>> ->
            Host@2 = binary:part(Original, 0, Size),
            Pieces@3 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host@2}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_query_with_question_mark(Rest@3, Pieces@3);

        <<"#"/utf8, Rest@4/binary>> when Size =:= 0 ->
            parse_fragment(Rest@4, Pieces);

        <<"#"/utf8, Rest@5/binary>> ->
            Host@3 = binary:part(Original, 0, Size),
            Pieces@4 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, Host@3}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_fragment(Rest@5, Pieces@4);

        _ ->
            {Char, Rest@6} = gleam_stdlib:string_pop_codeunit(Uri_string),
            case is_valid_host_within_brackets_char(Char) of
                true ->
                    parse_host_within_brackets_loop(Original, Rest@6, Pieces, Size + 1);

                false ->
                    parse_host_outside_of_brackets_loop(Original, Original, Pieces, 0)
            end
    end.

-file("src/gleam/uri.gleam", 219).
-spec parse_host_within_brackets(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_host_within_brackets(Uri_string, Pieces) ->
    parse_host_within_brackets_loop(Uri_string, Uri_string, Pieces, 0).

-file("src/gleam/uri.gleam", 196).
-spec parse_host(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_host(Uri_string, Pieces) ->
    case Uri_string of
        <<"["/utf8, _/binary>> ->
            parse_host_within_brackets(Uri_string, Pieces);

        <<":"/utf8, _/binary>> ->
            Pieces@1 = {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, ~""}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_port(Uri_string, Pieces@1);

        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, ~""}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        _ ->
            parse_host_outside_of_brackets(Uri_string, Pieces)
    end.

-file("src/gleam/uri.gleam", 164).
-spec parse_userinfo_loop(binary(), binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_userinfo_loop(Original, Uri_string, Pieces, Size) ->
    case Uri_string of
        <<"@"/utf8, Rest/binary>> when Size =:= 0 ->
            parse_host(Rest, Pieces);

        <<"@"/utf8, Rest@1/binary>> ->
            Userinfo = binary:part(Original, 0, Size),
            Pieces@1 = {uri, erlang:element(2, Pieces), {some, Userinfo}, erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_host(Rest@1, Pieces@1);

        ~"" ->
            parse_host(Original, Pieces);

        <<"/"/utf8, _/binary>> ->
            parse_host(Original, Pieces);

        <<"?"/utf8, _/binary>> ->
            parse_host(Original, Pieces);

        <<"#"/utf8, _/binary>> ->
            parse_host(Original, Pieces);

        _ ->
            {_, Rest@2} = gleam_stdlib:string_pop_codeunit(Uri_string),
            parse_userinfo_loop(Original, Rest@2, Pieces, Size + 1)
    end.

-file("src/gleam/uri.gleam", 160).
-spec parse_authority_pieces(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_authority_pieces(String, Pieces) ->
    parse_userinfo_loop(String, String, Pieces, 0).

-file("src/gleam/uri.gleam", 147).
-spec parse_authority_with_slashes(binary(), uri()) -> {ok, uri()} | {error, nil}.
parse_authority_with_slashes(Uri_string, Pieces) ->
    case Uri_string of
        ~"//" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), {some, ~""}, erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        <<"//"/utf8, Rest/binary>> ->
            parse_authority_pieces(Rest, Pieces);

        _ ->
            parse_path(Uri_string, Pieces)
    end.

-file("src/gleam/uri.gleam", 88).
-spec parse_scheme_loop(binary(), binary(), uri(), integer()) -> {ok, uri()} | {error, nil}.
parse_scheme_loop(Original, Uri_string, Pieces, Size) ->
    case Uri_string of
        <<"/"/utf8, _/binary>> when Size =:= 0 ->
            parse_authority_with_slashes(Uri_string, Pieces);

        <<"/"/utf8, _/binary>> ->
            Scheme = binary:part(Original, 0, Size),
            Pieces@1 = {uri, {some, string:lowercase(Scheme)}, erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_authority_with_slashes(Uri_string, Pieces@1);

        <<"?"/utf8, Rest/binary>> when Size =:= 0 ->
            parse_query_with_question_mark(Rest, Pieces);

        <<"?"/utf8, Rest@1/binary>> ->
            Scheme@1 = binary:part(Original, 0, Size),
            Pieces@2 = {uri, {some, string:lowercase(Scheme@1)}, erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_query_with_question_mark(Rest@1, Pieces@2);

        <<"#"/utf8, Rest@2/binary>> when Size =:= 0 ->
            parse_fragment(Rest@2, Pieces);

        <<"#"/utf8, Rest@3/binary>> ->
            Scheme@2 = binary:part(Original, 0, Size),
            Pieces@3 = {uri, {some, string:lowercase(Scheme@2)}, erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_fragment(Rest@3, Pieces@3);

        <<":"/utf8, _/binary>> when Size =:= 0 ->
            {error, nil};

        <<":"/utf8, Rest@4/binary>> ->
            Scheme@3 = binary:part(Original, 0, Size),
            Pieces@4 = {uri, {some, string:lowercase(Scheme@3)}, erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), erlang:element(6, Pieces), erlang:element(7, Pieces), erlang:element(8, Pieces)},
            parse_authority_with_slashes(Rest@4, Pieces@4);

        ~"" ->
            {ok, {uri, erlang:element(2, Pieces), erlang:element(3, Pieces), erlang:element(4, Pieces), erlang:element(5, Pieces), Original, erlang:element(7, Pieces), erlang:element(8, Pieces)}};

        _ ->
            {_, Rest@5} = gleam_stdlib:string_pop_codeunit(Uri_string),
            parse_scheme_loop(Original, Rest@5, Pieces, Size + 1)
    end.

-file("src/gleam/uri.gleam", 78).
-spec parse(binary()) -> {ok, uri()} | {error, nil}.
-doc(~" Parses a compliant URI string into the `Uri` type.
 If the string is not a valid URI string then an error is returned.

 The opposite operation is `uri.to_string`.

 ## Examples

 ```gleam
 assert uri.parse(\"https://example.com:1234/a/b?query=true#fragment\")
   == Ok(Uri(
     scheme: Some(\"https\"),
     userinfo: None,
     host: Some(\"example.com\"),
     port: Some(1234),
     path: \"/a/b\",
     query: Some(\"query=true\"),
     fragment: Some(\"fragment\"),
   ))
 ```
").
parse(Uri_string) ->
    gleam_stdlib:uri_parse(Uri_string).

-file("src/gleam/uri.gleam", 533).
-spec parse_query(binary()) -> {ok, list({binary(), binary()})} | {error, nil}.
-doc(~" Parses an URL-encoded query string into a list of key value pairs.
 Returns an error for invalid encoding.

 The opposite operation is `uri.query_to_string`.

 ## Examples

 ```gleam
 assert uri.parse_query(\"a=1&b=2\") == Ok([#(\"a\", \"1\"), #(\"b\", \"2\")])
 ```
").
parse_query(Query) ->
    gleam_stdlib:parse_query(Query).

-file("src/gleam/uri.gleam", 570).
-spec percent_encode(binary()) -> binary().
-doc(~" Encodes a string into a percent encoded representation.

 ## Examples

 ```gleam
 assert uri.percent_encode(\"100% great\") == \"100%25%20great\"
 ```
").
percent_encode(Value) ->
    gleam_stdlib:percent_encode(Value).

-file("src/gleam/uri.gleam", 555).
-spec percent_encode_query(binary()) -> binary().
percent_encode_query(Part) ->
    _pipe = gleam_stdlib:percent_encode(Part),
    gleam@string:replace(_pipe, ~"+", ~"%2B").

-file("src/gleam/uri.gleam", 551).
-spec query_pair({binary(), binary()}) -> binary().
query_pair(Pair) ->
    <<<<(percent_encode_query(erlang:element(1, Pair)))/binary, "="/utf8>>/binary, (percent_encode_query(erlang:element(2, Pair)))/binary>>.

-file("src/gleam/uri.gleam", 545).
-spec query_to_string(list({binary(), binary()})) -> binary().
-doc(~" Encodes a list of key value pairs as a URI query string.

 The opposite operation is `uri.parse_query`.

 ## Examples

 ```gleam
 assert uri.query_to_string([#(\"a\", \"1\"), #(\"b\", \"2\")]) == \"a=1&b=2\"
 ```
").
query_to_string(Query) ->
    _pipe = Query,
    _pipe@1 = gleam@list:map(_pipe, fun query_pair/1),
    gleam@string:join(_pipe@1, ~"&").

-file("src/gleam/uri.gleam", 582).
-spec percent_decode(binary()) -> {ok, binary()} | {error, nil}.
-doc(~" Decodes a percent encoded string.

 ## Examples

 ```gleam
 assert uri.percent_decode(\"100%25%20great+fun\") == Ok(\"100% great+fun\")
 ```
").
percent_decode(Value) ->
    gleam_stdlib:percent_decode(Value).

-file("src/gleam/uri.gleam", 603).
-spec remove_dot_segments_loop(list(binary()), list(binary())) -> list(binary()).
remove_dot_segments_loop(Input, Accumulator) ->
    case Input of
        [] ->
            lists:reverse(Accumulator);

        [Segment | Rest] ->
            Accumulator@1 = case {Segment, Accumulator} of
                {~"", Accumulator@2} ->
                    Accumulator@2;

                {~".", Accumulator@3} ->
                    Accumulator@3;

                {~"..", []} ->
                    [];

                {~"..", [_ | Accumulator@4]} ->
                    Accumulator@4;

                {Segment@1, Accumulator@5} ->
                    [Segment@1 | Accumulator@5]
            end,
            remove_dot_segments_loop(Rest, Accumulator@1)
    end.

-file("src/gleam/uri.gleam", 599).
-spec remove_dot_segments(list(binary())) -> list(binary()).
remove_dot_segments(Input) ->
    remove_dot_segments_loop(Input, []).

-file("src/gleam/uri.gleam", 595).
-spec path_segments(binary()) -> list(binary()).
-doc(~" Splits the path section of a URI into its constituent segments.

 Removes empty segments and resolves dot-segments as specified in
 [section 5.2](https://www.ietf.org/rfc/rfc3986.html#section-5.2) of the RFC.

 ## Examples

 ```gleam
 assert uri.path_segments(\"/users/1\") == [\"users\", \"1\"]
 ```
").
path_segments(Path) ->
    remove_dot_segments(gleam@string:split(Path, ~"/")).

-file("src/gleam/uri.gleam", 633).
-spec to_string(uri()) -> binary().
-doc(~" Encodes a `Uri` value as a URI string.

 The opposite operation is `uri.parse`.

 ## Examples

 ```gleam
 let uri = Uri(..empty, scheme: Some(\"https\"), host: Some(\"example.com\"))
 assert uri.to_string(uri) == \"https://example.com\"
 ```
").
to_string(Uri) ->
    Out = case erlang:element(2, Uri) of
        {some, Scheme} ->
            <<Scheme/binary, ":"/utf8>>;

        none ->
            ~""
    end,
    Out@1 = case erlang:element(4, Uri) of
        none ->
            <<Out/binary, (erlang:element(6, Uri))/binary>>;

        {some, Host} ->
            Out@2 = <<Out/binary, "//"/utf8>>,
            Out@3 = case erlang:element(3, Uri) of
                {some, Userinfo} ->
                    <<<<Out@2/binary, Userinfo/binary>>/binary, "@"/utf8>>;

                none ->
                    Out@2
            end,
            Out@4 = <<Out@3/binary, Host/binary>>,
            Out@5 = case erlang:element(5, Uri) of
                {some, Port} ->
                    <<<<Out@4/binary, ":"/utf8>>/binary, (erlang:integer_to_binary(Port))/binary>>;

                none ->
                    Out@4
            end,
            Out@6 = case erlang:element(6, Uri) of
                ~"" ->
                    Out@5;

                <<"/"/utf8, _/binary>> ->
                    <<Out@5/binary, (erlang:element(6, Uri))/binary>>;

                _ ->
                    <<<<Out@5/binary, "/"/utf8>>/binary, (erlang:element(6, Uri))/binary>>
            end,
            Out@6
    end,
    Out@7 = case erlang:element(7, Uri) of
        {some, Query} ->
            <<<<Out@1/binary, "?"/utf8>>/binary, Query/binary>>;

        none ->
            Out@1
    end,
    Out@8 = case erlang:element(8, Uri) of
        {some, Fragment} ->
            <<<<Out@7/binary, "#"/utf8>>/binary, Fragment/binary>>;

        none ->
            Out@7
    end,
    Out@8.

-file("src/gleam/uri.gleam", 695).
-spec origin(uri()) -> {ok, binary()} | {error, nil}.
-doc(~" Fetches the origin of a URI.

 Returns the origin of a uri as defined in
 [RFC 6454](https://tools.ietf.org/html/rfc6454)

 The supported URI schemes are `http` and `https`.
 URLs without a scheme will return `Error`.

 ## Examples

 ```gleam
 let assert Ok(uri) = uri.parse(\"https://example.com/path?foo#bar\")
 assert uri.origin(uri) == Ok(\"https://example.com\")
 ```
").
origin(Uri) ->
    {uri, Scheme, _, Host, Port, _, _, _} = Uri,
    case {Host, Scheme} of
        {{some, H}, {some, ~"https"}} when Port =:= {some, 443} ->
            {ok, <<"https://"/utf8, H/binary>>};

        {{some, H@1}, {some, ~"http"}} when Port =:= {some, 80} ->
            {ok, <<"http://"/utf8, H@1/binary>>};

        {{some, H@2}, {some, S}} when (S =:= ~"http") orelse (S =:= ~"https") ->
            case Port of
                {some, P} ->
                    {ok, <<<<<<<<S/binary, "://"/utf8>>/binary, H@2/binary>>/binary, ":"/utf8>>/binary, (erlang:integer_to_binary(P))/binary>>};

                none ->
                    {ok, <<<<S/binary, "://"/utf8>>/binary, H@2/binary>>}
            end;

        {_, _} ->
            {error, nil}
    end.

-file("src/gleam/uri.gleam", 778).
-spec join_segments(list(binary())) -> binary().
join_segments(Segments) ->
    gleam@string:join([~"" | Segments], ~"/").

-file("src/gleam/uri.gleam", 774).
-spec drop_last(list(DDO)) -> list(DDO).
drop_last(Elements) ->
    gleam@list:take(Elements, erlang:length(Elements) - 1).

-file("src/gleam/uri.gleam", 716).
-spec merge(uri(), uri()) -> {ok, uri()} | {error, nil}.
-doc(~" Resolves a URI with respect to the given base URI.

 The base URI must be an absolute URI or this function will return an error.
 The algorithm for merging URIs is described in
 [RFC 3986](https://tools.ietf.org/html/rfc3986#section-5.2).
").
merge(Base, Relative) ->
    case Base of
        {uri, {some, _}, _, {some, _}, _, _, _, _} ->
            case Relative of
                {uri, _, _, {some, _}, _, _, _, _} ->
                    Path = begin
                        _pipe = erlang:element(6, Relative),
                        _pipe@1 = gleam@string:split(_pipe, ~"/"),
                        _pipe@2 = remove_dot_segments(_pipe@1),
                        join_segments(_pipe@2)
                    end,
                    Resolved = {uri, gleam@option:'or'(erlang:element(2, Relative), erlang:element(2, Base)), none, erlang:element(4, Relative), gleam@option:'or'(erlang:element(5, Relative), erlang:element(5, Base)), Path, erlang:element(7, Relative), erlang:element(8, Relative)},
                    {ok, Resolved};

                _ ->
                    {New_path, New_query} = case erlang:element(6, Relative) of
                        ~"" ->
                            {erlang:element(6, Base), gleam@option:'or'(erlang:element(7, Relative), erlang:element(7, Base))};

                        _ ->
                            Path_segments = case gleam_stdlib:string_starts_with(erlang:element(6, Relative), ~"/") of
                                true ->
                                    gleam@string:split(erlang:element(6, Relative), ~"/");

                                false ->
                                    _pipe@3 = erlang:element(6, Base),
                                    _pipe@4 = gleam@string:split(_pipe@3, ~"/"),
                                    _pipe@5 = drop_last(_pipe@4),
                                    lists:append(_pipe@5, gleam@string:split(erlang:element(6, Relative), ~"/"))
                            end,
                            Path@1 = begin
                                _pipe@6 = Path_segments,
                                _pipe@7 = remove_dot_segments(_pipe@6),
                                join_segments(_pipe@7)
                            end,
                            {Path@1, erlang:element(7, Relative)}
                    end,
                    Resolved@1 = {uri, erlang:element(2, Base), none, erlang:element(4, Base), erlang:element(5, Base), New_path, New_query, erlang:element(8, Relative)},
                    {ok, Resolved@1}
            end;

        _ ->
            {error, nil}
    end.

