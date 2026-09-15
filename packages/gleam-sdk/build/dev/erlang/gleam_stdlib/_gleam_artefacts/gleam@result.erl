-module(gleam@result).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([is_ok/1, is_error/1, map/2, map_error/2, flatten/1, 'try'/2, unwrap/2, lazy_unwrap/2, unwrap_error/2, 'or'/2, lazy_or/2, all/1, partition/1, replace/2, replace_error/2, values/1, try_recover/2]).
-moduledoc(~" Result represents the result of something that may succeed or not.
 `Ok` means it was successful, `Error` means it was not successful.").

-file("src/gleam/result.gleam", 18).
-spec is_ok({ok, any()} | {error, any()}) -> boolean().
-doc(~" Checks whether the result is an `Ok` value.

 ## Examples

 ```gleam
 assert result.is_ok(Ok(1))
 ```

 ```gleam
 assert !result.is_ok(Error(Nil))
 ```
").
is_ok(Result) ->
    case Result of
        {error, _} ->
            false;

        {ok, _} ->
            true
    end.

-file("src/gleam/result.gleam", 37).
-spec is_error({ok, any()} | {error, any()}) -> boolean().
-doc(~" Checks whether the result is an `Error` value.

 ## Examples

 ```gleam
 assert !result.is_error(Ok(1))
 ```

 ```gleam
 assert result.is_error(Error(Nil))
 ```
").
is_error(Result) ->
    case Result of
        {ok, _} ->
            false;

        {error, _} ->
            true
    end.

-file("src/gleam/result.gleam", 60).
-spec map({ok, CMW} | {error, CMX}, fun((CMW) -> CNA)) -> {ok, CNA} | {error, CMX}.
-doc(~" Updates a value held within the `Ok` of a result by calling a given function
 on it.

 If the result is an `Error` rather than `Ok` the function is not called and the
 result stays the same.

 ## Examples

 ```gleam
 assert result.map(over: Ok(1), with: fn(x) { x + 1 }) == Ok(2)
 ```

 ```gleam
 assert result.map(over: Error(1), with: fn(x) { x + 1 }) == Error(1)
 ```
").
map(Result, Fun) ->
    case Result of
        {ok, X} ->
            {ok, Fun(X)};

        {error, E} ->
            {error, E}
    end.

-file("src/gleam/result.gleam", 83).
-spec map_error({ok, CND} | {error, CNE}, fun((CNE) -> CNH)) -> {ok, CND} | {error, CNH}.
-doc(~" Updates a value held within the `Error` of a result by calling a given function
 on it.

 If the result is `Ok` rather than `Error` the function is not called and the
 result stays the same.

 ## Examples

 ```gleam
 assert result.map_error(over: Error(1), with: fn(x) { x + 1 }) == Error(2)
 ```

 ```gleam
 assert result.map_error(over: Ok(1), with: fn(x) { x + 1 }) == Ok(1)
 ```
").
map_error(Result, Fun) ->
    case Result of
        {ok, X} ->
            {ok, X};

        {error, Error} ->
            {error, Fun(Error)}
    end.

-file("src/gleam/result.gleam", 109).
-spec flatten({ok, {ok, CNK} | {error, CNL}} | {error, CNL}) -> {ok, CNK} | {error, CNL}.
-doc(~" Merges a nested `Result` into a single layer.

 ## Examples

 ```gleam
 assert result.flatten(Ok(Ok(1))) == Ok(1)
 ```

 ```gleam
 assert result.flatten(Ok(Error(\"\"))) == Error(\"\")
 ```

 ```gleam
 assert result.flatten(Error(Nil)) == Error(Nil)
 ```
").
flatten(Result) ->
    case Result of
        {ok, X} ->
            X;

        {error, Error} ->
            {error, Error}
    end.

-file("src/gleam/result.gleam", 143).
-spec 'try'({ok, CNS} | {error, CNT}, fun((CNS) -> {ok, CNW} | {error, CNT})) -> {ok, CNW} | {error, CNT}.
-doc(~" \"Updates\" an `Ok` result by passing its value to a function that yields a result,
 and returning the yielded result. (This may \"replace\" the `Ok` with an `Error`.)

 If the input is an `Error` rather than an `Ok`, the function is not called and
 the original `Error` is returned.

 This function is the equivalent of calling `map` followed by `flatten`, and
 it is useful for chaining together multiple functions that may fail.

 ## Examples

 ```gleam
 assert result.try(Ok(1), fn(x) { Ok(x + 1) }) == Ok(2)
 ```

 ```gleam
 assert result.try(Ok(1), fn(x) { Ok(#(\"a\", x)) }) == Ok(#(\"a\", 1))
 ```

 ```gleam
 assert result.try(Ok(1), fn(_) { Error(\"Oh no\") }) == Error(\"Oh no\")
 ```

 ```gleam
 assert result.try(Error(Nil), fn(x) { Ok(x + 1) }) == Error(Nil)
 ```
").
'try'(Result, Fun) ->
    case Result of
        {ok, X} ->
            Fun(X);

        {error, E} ->
            {error, E}
    end.

-file("src/gleam/result.gleam", 166).
-spec unwrap({ok, COB} | {error, any()}, COB) -> COB.
-doc(~" Extracts the `Ok` value from a result, returning a default value if the result
 is an `Error`.

 ## Examples

 ```gleam
 assert result.unwrap(Ok(1), 0) == 1
 ```

 ```gleam
 assert result.unwrap(Error(\"\"), 0) == 0
 ```
").
unwrap(Result, Default) ->
    case Result of
        {ok, V} ->
            V;

        {error, _} ->
            Default
    end.

-file("src/gleam/result.gleam", 186).
-spec lazy_unwrap({ok, COF} | {error, any()}, fun(() -> COF)) -> COF.
-doc(~" Extracts the `Ok` value from a result, evaluating the default function if the result
 is an `Error`.

 ## Examples

 ```gleam
 assert result.lazy_unwrap(Ok(1), fn() { 0 }) == 1
 ```

 ```gleam
 assert result.lazy_unwrap(Error(\"\"), fn() { 0 }) == 0
 ```
").
lazy_unwrap(Result, Default) ->
    case Result of
        {ok, V} ->
            V;

        {error, _} ->
            Default()
    end.

-file("src/gleam/result.gleam", 206).
-spec unwrap_error({ok, any()} | {error, COK}, COK) -> COK.
-doc(~" Extracts the `Error` value from a result, returning a default value if the result
 is an `Ok`.

 ## Examples

 ```gleam
 assert result.unwrap_error(Error(1), 0) == 1
 ```

 ```gleam
 assert result.unwrap_error(Ok(\"\"), 0) == 0
 ```
").
unwrap_error(Result, Default) ->
    case Result of
        {ok, _} ->
            Default;

        {error, E} ->
            E
    end.

-file("src/gleam/result.gleam", 233).
-spec 'or'({ok, CON} | {error, COO}, {ok, CON} | {error, COO}) -> {ok, CON} | {error, COO}.
-doc(~" Returns the first value if it is `Ok`, otherwise returns the second value.

 ## Examples

 ```gleam
 assert result.or(Ok(1), Ok(2)) == Ok(1)
 ```

 ```gleam
 assert result.or(Ok(1), Error(\"Error 2\")) == Ok(1)
 ```

 ```gleam
 assert result.or(Error(\"Error 1\"), Ok(2)) == Ok(2)
 ```

 ```gleam
 assert result.or(Error(\"Error 1\"), Error(\"Error 2\")) == Error(\"Error 2\")
 ```
").
'or'(First, Second) ->
    case First of
        {ok, _} ->
            First;

        {error, _} ->
            Second
    end.

-file("src/gleam/result.gleam", 263).
-spec lazy_or({ok, COV} | {error, COW}, fun(() -> {ok, COV} | {error, COW})) -> {ok, COV} | {error, COW}.
-doc(~" Returns the first value if it is `Ok`, otherwise evaluates the given function for a fallback value.

 If you need access to the initial error value, use `result.try_recover`.

 ## Examples

 ```gleam
 assert result.lazy_or(Ok(1), fn() { Ok(2) }) == Ok(1)
 ```

 ```gleam
 assert result.lazy_or(Ok(1), fn() { Error(\"Error 2\") }) == Ok(1)
 ```

 ```gleam
 assert result.lazy_or(Error(\"Error 1\"), fn() { Ok(2) }) == Ok(2)
 ```

 ```gleam
 assert result.lazy_or(Error(\"Error 1\"), fn() { Error(\"Error 2\") })
   == Error(\"Error 2\")
 ```
").
lazy_or(First, Second) ->
    case First of
        {ok, _} ->
            First;

        {error, _} ->
            Second()
    end.

-file("src/gleam/result.gleam", 287).
-spec all(list({ok, CPD} | {error, CPE})) -> {ok, list(CPD)} | {error, CPE}.
-doc(~" Combines a list of results into a single result.
 If all elements in the list are `Ok` then returns an `Ok` holding the list of values.
 If any element is `Error` then returns the first error.

 ## Examples

 ```gleam
 assert result.all([Ok(1), Ok(2)]) == Ok([1, 2])
 ```

 ```gleam
 assert result.all([Ok(1), Error(\"e\")]) == Error(\"e\")
 ```
").
all(Results) ->
    gleam@list:try_map(Results, fun(Result) ->
        Result
    end).

-file("src/gleam/result.gleam", 307).
-spec partition_loop(list({ok, CPS} | {error, CPT}), list(CPS), list(CPT)) -> {list(CPS), list(CPT)}.
partition_loop(Results, Oks, Errors) ->
    case Results of
        [] ->
            {Oks, Errors};

        [{ok, A} | Rest] ->
            partition_loop(Rest, [A | Oks], Errors);

        [{error, E} | Rest@1] ->
            partition_loop(Rest@1, Oks, [E | Errors])
    end.

-file("src/gleam/result.gleam", 303).
-spec partition(list({ok, CPL} | {error, CPM})) -> {list(CPL), list(CPM)}.
-doc(~" Given a list of results, returns a pair where the first element is a list
 of all the values inside `Ok` and the second element is a list with all the
 values inside `Error`. The values in both lists appear in reverse order with
 respect to their position in the original list of results.

 ## Examples

 ```gleam
 assert result.partition([Ok(1), Error(\"a\"), Error(\"b\"), Ok(2)])
   == #([2, 1], [\"b\", \"a\"])
 ```
").
partition(Results) ->
    partition_loop(Results, [], []).

-file("src/gleam/result.gleam", 327).
-spec replace({ok, any()} | {error, CQB}, CQE) -> {ok, CQE} | {error, CQB}.
-doc(~" Replace the value within a result

 ## Examples

 ```gleam
 assert result.replace(Ok(1), Nil) == Ok(Nil)
 ```

 ```gleam
 assert result.replace(Error(1), Nil) == Error(1)
 ```
").
replace(Result, Value) ->
    case Result of
        {ok, _} ->
            {ok, Value};

        {error, Error} ->
            {error, Error}
    end.

-file("src/gleam/result.gleam", 346).
-spec replace_error({ok, CQH} | {error, any()}, CQL) -> {ok, CQH} | {error, CQL}.
-doc(~" Replace the error within a result

 ## Examples

 ```gleam
 assert result.replace_error(Error(1), Nil) == Error(Nil)
 ```

 ```gleam
 assert result.replace_error(Ok(1), Nil) == Ok(1)
 ```
").
replace_error(Result, Error) ->
    case Result of
        {ok, X} ->
            {ok, X};

        {error, _} ->
            {error, Error}
    end.

-file("src/gleam/result.gleam", 361).
-spec values(list({ok, CQO} | {error, any()})) -> list(CQO).
-doc(~" Given a list of results, returns only the values inside `Ok`.

 ## Examples

 ```gleam
 assert result.values([Ok(1), Error(\"a\"), Ok(3)]) == [1, 3]
 ```
").
values(Results) ->
    gleam@list:filter_map(Results, fun(Result) ->
        Result
    end).

-file("src/gleam/result.gleam", 397).
-spec try_recover({ok, CQU} | {error, CQV}, fun((CQV) -> {ok, CQU} | {error, CQY})) -> {ok, CQU} | {error, CQY}.
-doc(~" Updates a value held within the `Error` of a result by calling a given function
 on it, where the given function also returns a result. The two results are
 then merged together into one result.

 If the result is an `Ok` rather than `Error` the function is not called and the
 result stays the same.

 This function is useful for chaining together computations that may fail
 and trying to recover from possible errors.

 If you do not need access to the initial error value, use `result.lazy_or`.

 ## Examples

 ```gleam
 assert Ok(1)
   |> result.try_recover(with: fn(_) { Error(\"failed to recover\") })
   == Ok(1)
 ```

 ```gleam
 assert Error(1)
   |> result.try_recover(with: fn(error) { Ok(error + 1) })
   == Ok(2)
 ```

 ```gleam
 assert Error(1)
   |> result.try_recover(with: fn(error) { Error(\"failed to recover\") })
   == Error(\"failed to recover\")
 ```
").
try_recover(Result, Fun) ->
    case Result of
        {ok, Value} ->
            {ok, Value};

        {error, Error} ->
            Fun(Error)
    end.

