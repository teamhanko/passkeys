-module(gleam@function).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([identity/1]).

-file("src/gleam/function.gleam", 3).
-spec identity(CLW) -> CLW.
-doc(~" Takes a single argument and always returns its input value.
").
identity(X) ->
    X.

