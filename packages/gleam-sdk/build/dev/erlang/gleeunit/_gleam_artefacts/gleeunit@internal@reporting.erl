-module(gleeunit@internal@reporting).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([new_state/0, finished/1, test_passed/1, test_failed/4, eunit_missing/0, test_skipped/3]).
-export_type([state/0]).
-moduledoc(false).

-type state() :: {state, integer(), integer(), integer()}.

-file("src/gleeunit/internal/reporting.gleam", 15).
-spec new_state() -> state().
-doc(false).
new_state() ->
    {state, 0, 0, 0}.

-file("src/gleeunit/internal/reporting.gleam", 223).
-spec red(binary()) -> binary().
-doc(false).
red(Text) ->
    <<<<"\x{001b}[31m"/utf8, Text/binary>>/binary, "\x{001b}[39m"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 215).
-spec yellow(binary()) -> binary().
-doc(false).
yellow(Text) ->
    <<<<"\x{001b}[33m"/utf8, Text/binary>>/binary, "\x{001b}[39m"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 219).
-spec green(binary()) -> binary().
-doc(false).
green(Text) ->
    <<<<"\x{001b}[32m"/utf8, Text/binary>>/binary, "\x{001b}[39m"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 19).
-spec finished(state()) -> integer().
-doc(false).
finished(State) ->
    case State of
        {state, 0, 0, 0} ->
            gleam_stdlib:println(~"\nNo tests found!"),
            1;

        {state, _, 0, 0} ->
            Message = <<<<"\n"/utf8, (erlang:integer_to_binary(erlang:element(2, State)))/binary>>/binary, " passed, no failures"/utf8>>,
            gleam_stdlib:println(green(Message)),
            0;

        {state, _, _, 0} ->
            Message@1 = <<<<<<<<"\n"/utf8, (erlang:integer_to_binary(erlang:element(2, State)))/binary>>/binary, " passed, "/utf8>>/binary, (erlang:integer_to_binary(erlang:element(3, State)))/binary>>/binary, " failures"/utf8>>,
            gleam_stdlib:println(red(Message@1)),
            1;

        {state, _, 0, _} ->
            Message@2 = <<<<<<<<"\n"/utf8, (erlang:integer_to_binary(erlang:element(2, State)))/binary>>/binary, " passed, 0 failures, "/utf8>>/binary, (erlang:integer_to_binary(erlang:element(4, State)))/binary>>/binary, " skipped"/utf8>>,
            gleam_stdlib:println(yellow(Message@2)),
            1;

        {state, _, _, _} ->
            Message@3 = <<<<<<<<<<<<"\n"/utf8, (erlang:integer_to_binary(erlang:element(2, State)))/binary>>/binary, " passed, "/utf8>>/binary, (erlang:integer_to_binary(erlang:element(3, State)))/binary>>/binary, " failures, "/utf8>>/binary, (erlang:integer_to_binary(erlang:element(4, State)))/binary>>/binary, " skipped"/utf8>>,
            gleam_stdlib:println(red(Message@3)),
            1
    end.

-file("src/gleeunit/internal/reporting.gleam", 66).
-spec test_passed(state()) -> state().
-doc(false).
test_passed(State) ->
    gleam_stdlib:print(green(~".")),
    {state, erlang:element(2, State) + 1, erlang:element(3, State), erlang:element(4, State)}.

-file("src/gleeunit/internal/reporting.gleam", 227).
-spec grey(binary()) -> binary().
-doc(false).
grey(Text) ->
    <<<<"\x{001b}[90m"/utf8, Text/binary>>/binary, "\x{001b}[39m"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 100).
-spec format_unknown(binary(), binary(), gleam@dynamic:dynamic_()) -> binary().
-doc(false).
format_unknown(Module, Function, Error) ->
    erlang:list_to_binary([<<(grey(<<<<Module/binary, "."/utf8>>/binary, Function/binary>>))/binary, "\n"/utf8>>, ~"An unexpected error occurred:\n", ~"\n", <<<<"  "/utf8, (gleam@string:inspect(Error))/binary>>/binary, "\n"/utf8>>]).

-file("src/gleeunit/internal/reporting.gleam", 211).
-spec cyan(binary()) -> binary().
-doc(false).
cyan(Text) ->
    <<<<"\x{001b}[36m"/utf8, Text/binary>>/binary, "\x{001b}[39m"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 191).
-spec code_snippet(gleam@option:option(bitstring()), integer(), integer()) -> binary().
-doc(false).
code_snippet(Src, Start, End) ->
    _pipe = begin
        gleam@result:'try'(gleam@option:to_result(Src, nil), fun(Src@1) ->
            gleam@result:'try'(gleam_stdlib:bit_array_slice(Src@1, Start, End - Start), fun(Snippet) ->
                gleam@result:'try'(gleam@bit_array:to_string(Snippet), fun(Snippet@1) ->
                    Snippet@2 = <<<<<<(cyan(~" code"))/binary, ": "/utf8>>/binary, Snippet@1/binary>>/binary, "\n"/utf8>>,
                    {ok, Snippet@2}
                end)
            end)
        end)
    end,
    gleam@result:unwrap(_pipe, ~"").

-file("src/gleeunit/internal/reporting.gleam", 207).
-spec bold(binary()) -> binary().
-doc(false).
bold(Text) ->
    <<<<"\x{001b}[1m"/utf8, Text/binary>>/binary, "\x{001b}[22m"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 183).
-spec inspect_value(gleeunit@internal@gleam_panic:asserted_expression()) -> binary().
-doc(false).
inspect_value(Value) ->
    case erlang:element(4, Value) of
        unevaluated ->
            grey(~"unevaluated");

        {literal, Value@1} ->
            gleam@string:inspect(Value@1);

        {expression, Value@2} ->
            gleam@string:inspect(Value@2)
    end.

-file("src/gleeunit/internal/reporting.gleam", 179).
-spec assert_value(binary(), gleeunit@internal@gleam_panic:asserted_expression()) -> binary().
-doc(false).
assert_value(Name, Value) ->
    <<<<<<(cyan(Name))/binary, ": "/utf8>>/binary, (inspect_value(Value))/binary>>/binary, "\n"/utf8>>.

-file("src/gleeunit/internal/reporting.gleam", 160).
-spec assert_info(gleeunit@internal@gleam_panic:assert_kind()) -> binary().
-doc(false).
assert_info(Kind) ->
    case Kind of
        {binary_operator, _, Left, Right} ->
            erlang:list_to_binary([assert_value(~" left", Left), assert_value(~"right", Right)]);

        {function_call, Arguments} ->
            _pipe = Arguments,
            _pipe@1 = gleam@list:index_map(_pipe, fun(E, I) ->
                Number = gleam@string:pad_start(erlang:integer_to_binary(I), 5, ~" "),
                assert_value(Number, E)
            end),
            erlang:list_to_binary(_pipe@1);

        {other_expression, _} ->
            ~""
    end.

-file("src/gleeunit/internal/reporting.gleam", 113).
-spec format_gleam_error(gleeunit@internal@gleam_panic:gleam_panic(), binary(), binary(), gleam@option:option(bitstring())) -> binary().
-doc(false).
format_gleam_error(Error, Module, Function, Src) ->
    Location = grey(<<<<(erlang:element(3, Error))/binary, ":"/utf8>>/binary, (erlang:integer_to_binary(erlang:element(6, Error)))/binary>>),
    case erlang:element(7, Error) of
        panic ->
            erlang:list_to_binary([<<<<<<(bold(red(~"panic")))/binary, " "/utf8>>/binary, Location/binary>>/binary, "\n"/utf8>>, <<<<<<<<<<(cyan(~" test"))/binary, ": "/utf8>>/binary, Module/binary>>/binary, "."/utf8>>/binary, Function/binary>>/binary, "\n"/utf8>>, <<<<<<(cyan(~" info"))/binary, ": "/utf8>>/binary, (erlang:element(2, Error))/binary>>/binary, "\n"/utf8>>]);

        todo ->
            erlang:list_to_binary([<<<<<<(bold(yellow(~"todo")))/binary, " "/utf8>>/binary, Location/binary>>/binary, "\n"/utf8>>, <<<<<<<<<<(cyan(~" test"))/binary, ": "/utf8>>/binary, Module/binary>>/binary, "."/utf8>>/binary, Function/binary>>/binary, "\n"/utf8>>, <<<<<<(cyan(~" info"))/binary, ": "/utf8>>/binary, (erlang:element(2, Error))/binary>>/binary, "\n"/utf8>>]);

        {assert, Start, End, _, Kind} ->
            erlang:list_to_binary([<<<<<<(bold(red(~"assert")))/binary, " "/utf8>>/binary, Location/binary>>/binary, "\n"/utf8>>, <<<<<<<<<<(cyan(~" test"))/binary, ": "/utf8>>/binary, Module/binary>>/binary, "."/utf8>>/binary, Function/binary>>/binary, "\n"/utf8>>, code_snippet(Src, Start, End), assert_info(Kind), <<<<<<(cyan(~" info"))/binary, ": "/utf8>>/binary, (erlang:element(2, Error))/binary>>/binary, "\n"/utf8>>]);

        {let_assert, Start@1, End@1, _, _, Value} ->
            erlang:list_to_binary([<<<<<<(bold(red(~"let assert")))/binary, " "/utf8>>/binary, Location/binary>>/binary, "\n"/utf8>>, <<<<<<<<<<(cyan(~" test"))/binary, ": "/utf8>>/binary, Module/binary>>/binary, "."/utf8>>/binary, Function/binary>>/binary, "\n"/utf8>>, code_snippet(Src, Start@1, End@1), <<<<<<(cyan(~"value"))/binary, ": "/utf8>>/binary, (gleam@string:inspect(Value))/binary>>/binary, "\n"/utf8>>, <<<<<<(cyan(~" info"))/binary, ": "/utf8>>/binary, (erlang:element(2, Error))/binary>>/binary, "\n"/utf8>>])
    end.

-file("src/gleeunit/internal/reporting.gleam", 71).
-spec test_failed(state(), binary(), binary(), gleam@dynamic:dynamic_()) -> state().
-doc(false).
test_failed(State, Module, Function, Error) ->
    Message = case gleeunit_gleam_panic_ffi:from_dynamic(Error) of
        {ok, Error@1} ->
            Src = gleam@option:from_result(file:read_file(erlang:element(3, Error@1))),
            format_gleam_error(Error@1, Module, Function, Src);

        {error, _} ->
            format_unknown(Module, Function, Error)
    end,
    gleam_stdlib:print(<<"\n"/utf8, Message/binary>>),
    {state, erlang:element(2, State), erlang:element(3, State) + 1, erlang:element(4, State)}.

-file("src/gleeunit/internal/reporting.gleam", 89).
-spec eunit_missing() -> {ok, any()} | {error, nil}.
-doc(false).
eunit_missing() ->
    Message = <<(bold(red(~"Error")))/binary, ": EUnit libraries not found.

Your Erlang installation seems to be incomplete. If you installed Erlang using
a package manager ensure that you have installed the full Erlang
distribution instead of a stripped-down version.
"/utf8>>,
    gleam_stdlib:print_error(Message),
    {error, nil}.

-file("src/gleeunit/internal/reporting.gleam", 202).
-spec test_skipped(state(), binary(), binary()) -> state().
-doc(false).
test_skipped(State, Module, Function) ->
    gleam_stdlib:print(<<<<<<<<"\n"/utf8, Module/binary>>/binary, "."/utf8>>/binary, Function/binary>>/binary, (yellow(~" skipped"))/binary>>),
    {state, erlang:element(2, State), erlang:element(3, State), erlang:element(4, State) + 1}.

