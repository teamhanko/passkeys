-module(gleam@option).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([all/1, is_some/1, is_none/1, to_result/2, from_result/1, unwrap/2, lazy_unwrap/2, map/2, flatten/1, then/2, 'or'/2, lazy_or/2, values/1]).
-export_type([option/1]).

-type option(EL) :: {some, EL} | none.

-file("src/gleam/option.gleam", 57).
-spec reverse_and_prepend(list(FA), list(FA)) -> list(FA).
reverse_and_prepend(Prefix, Suffix) ->
    case Prefix of
        [] ->
            Suffix;

        [First | Rest] ->
            reverse_and_prepend(Rest, [First | Suffix])
    end.

-file("src/gleam/option.gleam", 42).
-spec all_loop(list(option(ER)), list(ER)) -> option(list(ER)).
all_loop(List, Acc) ->
    case List of
        [] ->
            {some, lists:reverse(Acc)};

        [none | _] ->
            none;

        [{some, First} | Rest] ->
            all_loop(Rest, [First | Acc])
    end.

-file("src/gleam/option.gleam", 38).
-spec all(list(option(EM))) -> option(list(EM)).
-doc(~" Combines a list of `Option`s into a single `Option`.
 If all elements in the list are `Some` then returns a `Some` holding the list of values.
 If any element is `None` then returns `None`.

 ## Examples

 ```gleam
 assert option.all([Some(1), Some(2)]) == Some([1, 2])
 ```

 ```gleam
 assert option.all([Some(1), None]) == None
 ```
").
all(List) ->
    all_loop(List, []).

-file("src/gleam/option.gleam", 76).
-spec is_some(option(any())) -> boolean().
-doc(~" Checks whether the `Option` is a `Some` value.

 ## Examples

 ```gleam
 assert option.is_some(Some(1))
 ```

 ```gleam
 assert !option.is_some(None)
 ```
").
is_some(Option) ->
    Option /= none.

-file("src/gleam/option.gleam", 92).
-spec is_none(option(any())) -> boolean().
-doc(~" Checks whether the `Option` is a `None` value.

 ## Examples

 ```gleam
 assert !option.is_none(Some(1))
 ```

 ```gleam
 assert option.is_none(None)
 ```
").
is_none(Option) ->
    Option =:= none.

-file("src/gleam/option.gleam", 108).
-spec to_result(option(FI), FL) -> {ok, FI} | {error, FL}.
-doc(~" Converts an `Option` type to a `Result` type.

 ## Examples

 ```gleam
 assert option.to_result(Some(1), \"some_error\") == Ok(1)
 ```

 ```gleam
 assert option.to_result(None, \"some_error\") == Error(\"some_error\")
 ```
").
to_result(Option, E) ->
    case Option of
        {some, A} ->
            {ok, A};

        none ->
            {error, E}
    end.

-file("src/gleam/option.gleam", 127).
-spec from_result({ok, FO} | {error, any()}) -> option(FO).
-doc(~" Converts a `Result` type to an `Option` type.

 ## Examples

 ```gleam
 assert option.from_result(Ok(1)) == Some(1)
 ```

 ```gleam
 assert option.from_result(Error(\"some_error\")) == None
 ```
").
from_result(Result) ->
    case Result of
        {ok, A} ->
            {some, A};

        {error, _} ->
            none
    end.

-file("src/gleam/option.gleam", 146).
-spec unwrap(option(FT), FT) -> FT.
-doc(~" Extracts the value from an `Option`, returning a default value if there is none.

 ## Examples

 ```gleam
 assert option.unwrap(Some(1), 0) == 1
 ```

 ```gleam
 assert option.unwrap(None, 0) == 0
 ```
").
unwrap(Option, Default) ->
    case Option of
        {some, X} ->
            X;

        none ->
            Default
    end.

-file("src/gleam/option.gleam", 165).
-spec lazy_unwrap(option(FV), fun(() -> FV)) -> FV.
-doc(~" Extracts the value from an `Option`, evaluating the default function if the option is `None`.

 ## Examples

 ```gleam
 assert option.lazy_unwrap(Some(1), fn() { 0 }) == 1
 ```

 ```gleam
 assert option.lazy_unwrap(None, fn() { 0 }) == 0
 ```
").
lazy_unwrap(Option, Default) ->
    case Option of
        {some, X} ->
            X;

        none ->
            Default()
    end.

-file("src/gleam/option.gleam", 188).
-spec map(option(FX), fun((FX) -> FZ)) -> option(FZ).
-doc(~" Updates a value held within the `Some` of an `Option` by calling a given function
 on it.

 If the `Option` is a `None` rather than `Some`, the function is not called and the
 `Option` stays the same.

 ## Examples

 ```gleam
 assert option.map(over: Some(1), with: fn(x) { x + 1 }) == Some(2)
 ```

 ```gleam
 assert option.map(over: None, with: fn(x) { x + 1 }) == None
 ```
").
map(Option, Fun) ->
    case Option of
        {some, X} ->
            {some, Fun(X)};

        none ->
            none
    end.

-file("src/gleam/option.gleam", 211).
-spec flatten(option(option(GB))) -> option(GB).
-doc(~" Merges a nested `Option` into a single layer.

 ## Examples

 ```gleam
 assert option.flatten(Some(Some(1))) == Some(1)
 ```

 ```gleam
 assert option.flatten(Some(None)) == None
 ```

 ```gleam
 assert option.flatten(None) == None
 ```
").
flatten(Option) ->
    case Option of
        {some, X} ->
            X;

        none ->
            none
    end.

-file("src/gleam/option.gleam", 246).
-spec then(option(GF), fun((GF) -> option(GH))) -> option(GH).
-doc(~" Updates a value held within the `Some` of an `Option` by calling a given function
 on it, where the given function also returns an `Option`. The two options are
 then merged together into one `Option`.

 If the `Option` is a `None` rather than `Some` the function is not called and the
 option stays the same.

 This function is the equivalent of calling `map` followed by `flatten`, and
 it is useful for chaining together multiple functions that return `Option`.

 ## Examples

 ```gleam
 assert option.then(Some(1), fn(x) { Some(x + 1) }) == Some(2)
 ```

 ```gleam
 assert option.then(Some(1), fn(x) { Some(#(\"a\", x)) }) == Some(#(\"a\", 1))
 ```

 ```gleam
 assert option.then(Some(1), fn(_) { None }) == None
 ```

 ```gleam
 assert option.then(None, fn(x) { Some(x + 1) }) == None
 ```
").
then(Option, Fun) ->
    case Option of
        {some, X} ->
            Fun(X);

        none ->
            none
    end.

-file("src/gleam/option.gleam", 273).
-spec 'or'(option(GK), option(GK)) -> option(GK).
-doc(~" Returns the first value if it is `Some`, otherwise returns the second value.

 ## Examples

 ```gleam
 assert option.or(Some(1), Some(2)) == Some(1)
 ```

 ```gleam
 assert option.or(Some(1), None) == Some(1)
 ```

 ```gleam
 assert option.or(None, Some(2)) == Some(2)
 ```

 ```gleam
 assert option.or(None, None) == None
 ```
").
'or'(First, Second) ->
    case First of
        {some, _} ->
            First;

        none ->
            Second
    end.

-file("src/gleam/option.gleam", 300).
-spec lazy_or(option(GO), fun(() -> option(GO))) -> option(GO).
-doc(~" Returns the first value if it is `Some`, otherwise evaluates the given function for a fallback value.

 ## Examples

 ```gleam
 assert option.lazy_or(Some(1), fn() { Some(2) }) == Some(1)
 ```

 ```gleam
 assert option.lazy_or(Some(1), fn() { None }) == Some(1)
 ```

 ```gleam
 assert option.lazy_or(None, fn() { Some(2) }) == Some(2)
 ```

 ```gleam
 assert option.lazy_or(None, fn() { None }) == None
 ```
").
lazy_or(First, Second) ->
    case First of
        {some, _} ->
            First;

        none ->
            Second()
    end.

-file("src/gleam/option.gleam", 320).
-spec values_loop(list(option(GW)), list(GW)) -> list(GW).
values_loop(List, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [none | Rest] ->
            values_loop(Rest, Acc);

        [{some, First} | Rest@1] ->
            values_loop(Rest@1, [First | Acc])
    end.

-file("src/gleam/option.gleam", 316).
-spec values(list(option(GS))) -> list(GS).
-doc(~" Given a list of `Option`s,
 returns only the values inside `Some`.

 ## Examples

 ```gleam
 assert option.values([Some(1), None, Some(3)]) == [1, 3]
 ```
").
values(Options) ->
    values_loop(Options, []).

