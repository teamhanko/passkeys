-module(gleeunit@should).
-compile([no_auto_import, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-define(FILEPATH, "src/gleeunit/should.gleam").
-export([equal/2, not_equal/2, be_ok/1, be_error/1, be_some/1, be_none/1, be_true/1, be_false/1, fail/0]).

-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.

?MODULEDOC(" Use the `assert` keyword instead of this module.\n").

-file("src/gleeunit/should.gleam", 6).
-spec equal(DOK, DOK) -> nil.
equal(A, B) ->
    case A =:= B of
        true ->
            nil;

        _ ->
            erlang:error(#{gleam_error => panic,
                    message => erlang:list_to_binary(
                        [<<"\n"/utf8>>,
                            gleam@string:inspect(A),
                            <<"\nshould equal\n"/utf8>>,
                            gleam@string:inspect(B)]
                    ),
                    file => <<?FILEPATH/utf8>>,
                    module => <<"gleeunit/should"/utf8>>,
                    function => <<"equal"/utf8>>,
                    line => 10})
    end.

-file("src/gleeunit/should.gleam", 19).
-spec not_equal(DOL, DOL) -> nil.
not_equal(A, B) ->
    case A /= B of
        true ->
            nil;

        _ ->
            erlang:error(#{gleam_error => panic,
                    message => erlang:list_to_binary(
                        [<<"\n"/utf8>>,
                            gleam@string:inspect(A),
                            <<"\nshould not equal\n"/utf8>>,
                            gleam@string:inspect(B)]
                    ),
                    file => <<?FILEPATH/utf8>>,
                    module => <<"gleeunit/should"/utf8>>,
                    function => <<"not_equal"/utf8>>,
                    line => 23})
    end.

-file("src/gleeunit/should.gleam", 32).
-spec be_ok({ok, DOM} | {error, any()}) -> DOM.
be_ok(A) ->
    case A of
        {ok, Value} ->
            Value;

        _ ->
            erlang:error(#{gleam_error => panic,
                    message => erlang:list_to_binary(
                        [<<"\n"/utf8>>,
                            gleam@string:inspect(A),
                            <<"\nshould be ok"/utf8>>]
                    ),
                    file => <<?FILEPATH/utf8>>,
                    module => <<"gleeunit/should"/utf8>>,
                    function => <<"be_ok"/utf8>>,
                    line => 35})
    end.

-file("src/gleeunit/should.gleam", 39).
-spec be_error({ok, any()} | {error, DOR}) -> DOR.
be_error(A) ->
    case A of
        {error, Error} ->
            Error;

        _ ->
            erlang:error(#{gleam_error => panic,
                    message => erlang:list_to_binary(
                        [<<"\n"/utf8>>,
                            gleam@string:inspect(A),
                            <<"\nshould be error"/utf8>>]
                    ),
                    file => <<?FILEPATH/utf8>>,
                    module => <<"gleeunit/should"/utf8>>,
                    function => <<"be_error"/utf8>>,
                    line => 42})
    end.

-file("src/gleeunit/should.gleam", 46).
-spec be_some(gleam@option:option(DOU)) -> DOU.
be_some(A) ->
    case A of
        {some, Value} ->
            Value;

        _ ->
            erlang:error(#{gleam_error => panic,
                    message => erlang:list_to_binary(
                        [<<"\n"/utf8>>,
                            gleam@string:inspect(A),
                            <<"\nshould be some"/utf8>>]
                    ),
                    file => <<?FILEPATH/utf8>>,
                    module => <<"gleeunit/should"/utf8>>,
                    function => <<"be_some"/utf8>>,
                    line => 49})
    end.

-file("src/gleeunit/should.gleam", 53).
-spec be_none(gleam@option:option(any())) -> nil.
be_none(A) ->
    case A of
        none ->
            nil;

        _ ->
            erlang:error(#{gleam_error => panic,
                    message => erlang:list_to_binary(
                        [<<"\n"/utf8>>,
                            gleam@string:inspect(A),
                            <<"\nshould be none"/utf8>>]
                    ),
                    file => <<?FILEPATH/utf8>>,
                    module => <<"gleeunit/should"/utf8>>,
                    function => <<"be_none"/utf8>>,
                    line => 56})
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
