-module(gleeunit@internal@gleam_panic).
-compile([no_auto_import, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-define(FILEPATH, "src/gleeunit/internal/gleam_panic.gleam").
-export([from_dynamic/1]).
-export_type([gleam_panic/0, panic_kind/0, assert_kind/0, asserted_expression/0, expression_kind/0]).

-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.

?MODULEDOC(false).

-type gleam_panic() :: {gleam_panic,
        binary(),
        binary(),
        binary(),
        binary(),
        integer(),
        panic_kind()}.

-type panic_kind() :: todo |
    panic |
    {let_assert,
        integer(),
        integer(),
        integer(),
        integer(),
        gleam@dynamic:dynamic_()} |
    {assert, integer(), integer(), integer(), assert_kind()}.

-type assert_kind() :: {binary_operator,
        binary(),
        asserted_expression(),
        asserted_expression()} |
    {function_call, list(asserted_expression())} |
    {other_expression, asserted_expression()}.

-type asserted_expression() :: {asserted_expression,
        integer(),
        integer(),
        expression_kind()}.

-type expression_kind() :: {literal, gleam@dynamic:dynamic_()} |
    {expression, gleam@dynamic:dynamic_()} |
    unevaluated.

-file("src/gleeunit/internal/gleam_panic.gleam", 49).
?DOC(false).
-spec from_dynamic(gleam@dynamic:dynamic_()) -> {ok, gleam_panic()} |
    {error, nil}.
from_dynamic(Data) ->
    gleeunit_gleam_panic_ffi:from_dynamic(Data).
