-module(gleeunit@should).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([equal/2, not_equal/2, be_ok/1, be_error/1, be_some/1, be_none/1, be_true/1, be_false/1, fail/0]).
-moduledoc(~" Use the `assert` keyword instead of this module.").

-file("src/gleeunit/should.gleam", 6).
-spec equal(EVQ, EVQ) -> nil.
equal(A, B) ->
    case A =:= B of
        true ->
            nil;

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => erlang:list_to_binary([~"\n", gleam@string:inspect(A), ~"\nshould equal\n", gleam@string:inspect(B)]),
                file => ~"src/gleeunit/should.gleam",
                module => ~"gleeunit/should",
                function => ~"equal",
                line => 10
            })
    end.

-file("src/gleeunit/should.gleam", 19).
-spec not_equal(EVR, EVR) -> nil.
not_equal(A, B) ->
    case A /= B of
        true ->
            nil;

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => erlang:list_to_binary([~"\n", gleam@string:inspect(A), ~"\nshould not equal\n", gleam@string:inspect(B)]),
                file => ~"src/gleeunit/should.gleam",
                module => ~"gleeunit/should",
                function => ~"not_equal",
                line => 23
            })
    end.

-file("src/gleeunit/should.gleam", 32).
-spec be_ok({ok, EVS} | {error, any()}) -> EVS.
be_ok(A) ->
    case A of
        {ok, Value} ->
            Value;

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => erlang:list_to_binary([~"\n", gleam@string:inspect(A), ~"\nshould be ok"]),
                file => ~"src/gleeunit/should.gleam",
                module => ~"gleeunit/should",
                function => ~"be_ok",
                line => 35
            })
    end.

-file("src/gleeunit/should.gleam", 39).
-spec be_error({ok, any()} | {error, EVX}) -> EVX.
be_error(A) ->
    case A of
        {error, Error} ->
            Error;

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => erlang:list_to_binary([~"\n", gleam@string:inspect(A), ~"\nshould be error"]),
                file => ~"src/gleeunit/should.gleam",
                module => ~"gleeunit/should",
                function => ~"be_error",
                line => 42
            })
    end.

-file("src/gleeunit/should.gleam", 46).
-spec be_some(gleam@option:option(EWA)) -> EWA.
be_some(A) ->
    case A of
        {some, Value} ->
            Value;

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => erlang:list_to_binary([~"\n", gleam@string:inspect(A), ~"\nshould be some"]),
                file => ~"src/gleeunit/should.gleam",
                module => ~"gleeunit/should",
                function => ~"be_some",
                line => 49
            })
    end.

-file("src/gleeunit/should.gleam", 53).
-spec be_none(gleam@option:option(any())) -> nil.
be_none(A) ->
    case A of
        none ->
            nil;

        _ ->
            erlang:error(#{
                gleam_error => panic,
                message => erlang:list_to_binary([~"\n", gleam@string:inspect(A), ~"\nshould be none"]),
                file => ~"src/gleeunit/should.gleam",
                module => ~"gleeunit/should",
                function => ~"be_none",
                line => 56
            })
    end.

-file("src/gleeunit/should.gleam", 60).
-spec be_true(boolean()) -> nil.
be_true(Actual) ->
    _pipe = Actual,
    equal(_pipe, true).

-file("src/gleeunit/should.gleam", 65).
-spec be_false(boolean()) -> nil.
be_false(Actual) ->
    _pipe = Actual,
    equal(_pipe, false).

-file("src/gleeunit/should.gleam", 70).
-spec fail() -> nil.
fail() ->
    be_true(false).

