-module(gleam@int).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([absolute_value/1, to_float/1, power/2, square_root/1, parse/1, base_parse/2, to_string/1, to_base_string/2, to_base2/1, to_base8/1, to_base16/1, to_base36/1, max/2, min/2, clamp/3, compare/2, is_even/1, is_odd/1, negate/1, sum/1, product/1, random/1, divide/2, remainder/2, modulo/2, floor_divide/2, add/2, multiply/2, subtract/2, bitwise_and/2, bitwise_not/1, bitwise_or/2, bitwise_exclusive_or/2, bitwise_shift_left/2, bitwise_shift_right/2, range/4]).
-moduledoc(~" Functions for working with integers.

 ## Division by zero

 In Erlang division by zero results in a crash, however Gleam does not have
 partial functions and operators in core so instead division by zero returns
 zero, a behaviour taken from Pony, Coq, and Lean.

 This may seem unexpected at first, but it is no less mathematically valid
 than crashing or returning a special value. Division by zero is undefined
 in mathematics.").

-file("src/gleam/int.gleam", 28).
-spec absolute_value(integer()) -> integer().
-doc(~" Returns the absolute value of the input.

 ## Examples

 ```gleam
 assert int.absolute_value(-12) == 12
 ```

 ```gleam
 assert int.absolute_value(10) == 10
 ```
").
absolute_value(X) ->
    case X >= 0 of
        true ->
            X;

        false ->
            X * -1
    end.

-file("src/gleam/int.gleam", 254).
-spec to_float(integer()) -> float().
-doc(~" Takes an int and returns its value as a float.

 ## Examples

 ```gleam
 assert int.to_float(5) == 5.0
 ```

 ```gleam
 assert int.to_float(0) == 0.0
 ```

 ```gleam
 assert int.to_float(-3) == -3.0
 ```
").
to_float(X) ->
    erlang:float(X).

-file("src/gleam/int.gleam", 60).
-spec power(integer(), float()) -> {ok, float()} | {error, nil}.
-doc(~" Returns the result of the base being raised to the power of the
 exponent, as a `Float`.

 ## Examples

 ```gleam
 assert int.power(2, -1.0) == Ok(0.5)
 ```

 ```gleam
 assert int.power(2, 2.0) == Ok(4.0)
 ```

 ```gleam
 assert int.power(8, 1.5) == Ok(22.627416997969522)
 ```

 ```gleam
 assert 4 |> int.power(of: 2.0) == Ok(16.0)
 ```

 ```gleam
 assert int.power(-1, 0.5) == Error(Nil)
 ```
").
power(Base, Exponent) ->
    _pipe = Base,
    _pipe@1 = erlang:float(_pipe),
    gleam@float:power(_pipe@1, Exponent).

-file("src/gleam/int.gleam", 78).
-spec square_root(integer()) -> {ok, float()} | {error, nil}.
-doc(~" Returns the square root of the input as a `Float`.

 ## Examples

 ```gleam
 assert int.square_root(4) == Ok(2.0)
 ```

 ```gleam
 assert int.square_root(-16) == Error(Nil)
 ```
").
square_root(X) ->
    _pipe = X,
    _pipe@1 = erlang:float(_pipe),
    gleam@float:square_root(_pipe@1).

-file("src/gleam/int.gleam", 98).
-spec parse(binary()) -> {ok, integer()} | {error, nil}.
-doc(~" Parses a given string as an int if possible.

 ## Examples

 ```gleam
 assert int.parse(\"2\") == Ok(2)
 ```

 ```gleam
 assert int.parse(\"ABC\") == Error(Nil)
 ```
").
parse(String) ->
    gleam_stdlib:parse_int(String).

-file("src/gleam/int.gleam", 128).
-spec base_parse(binary(), integer()) -> {ok, integer()} | {error, nil}.
-doc(~" Parses a given string as an int in a given base, returning an error if the
 input was not a valid number for the given base.

 Supports only bases 2 to 36, for values outside of which this function
 returns an `Error(Nil)`.

 ## Examples

 ```gleam
 assert int.base_parse(\"10\", 2) == Ok(2)
 ```

 ```gleam
 assert int.base_parse(\"30\", 16) == Ok(48)
 ```

 ```gleam
 assert int.base_parse(\"1C\", 36) == Ok(48)
 ```

 ```gleam
 assert int.base_parse(\"48\", 1) == Error(Nil)
 ```

 ```gleam
 assert int.base_parse(\"48\", 37) == Error(Nil)
 ```
").
base_parse(String, Base) ->
    case (Base >= 2) andalso (Base =< 36) of
        true ->
            gleam_stdlib:int_from_base_string(String, Base);

        false ->
            {error, nil}
    end.

-file("src/gleam/int.gleam", 149).
-spec to_string(integer()) -> binary().
-doc(~" Prints a given int to a string.

 ## Examples

 ```gleam
 assert int.to_string(2) == \"2\"
 ```
").
to_string(X) ->
    erlang:integer_to_binary(X).

-file("src/gleam/int.gleam", 177).
-spec to_base_string(integer(), integer()) -> {ok, binary()} | {error, nil}.
-doc(~" Prints a given int to a string using the base number provided.
 Supports only bases 2 to 36, for values outside of which this function returns an `Error(Nil)`.
 For common bases (2, 8, 16, 36), use the `to_baseN` functions.

 ## Examples

 ```gleam
 assert int.to_base_string(2, 2) == Ok(\"10\")
 ```

 ```gleam
 assert int.to_base_string(48, 16) == Ok(\"30\")
 ```

 ```gleam
 assert int.to_base_string(48, 36) == Ok(\"1C\")
 ```

 ```gleam
 assert int.to_base_string(48, 1) == Error(Nil)
 ```

 ```gleam
 assert int.to_base_string(48, 37) == Error(Nil)
 ```
").
to_base_string(X, Base) ->
    case (Base >= 2) andalso (Base =< 36) of
        true ->
            {ok, erlang:integer_to_binary(X, Base)};

        false ->
            {error, nil}
    end.

-file("src/gleam/int.gleam", 196).
-spec to_base2(integer()) -> binary().
-doc(~" Prints a given int to a string using base-2.

 ## Examples

 ```gleam
 assert int.to_base2(2) == \"10\"
 ```
").
to_base2(X) ->
    erlang:integer_to_binary(X, 2).

-file("src/gleam/int.gleam", 208).
-spec to_base8(integer()) -> binary().
-doc(~" Prints a given int to a string using base-8.

 ## Examples

 ```gleam
 assert int.to_base8(15) == \"17\"
 ```
").
to_base8(X) ->
    erlang:integer_to_binary(X, 8).

-file("src/gleam/int.gleam", 220).
-spec to_base16(integer()) -> binary().
-doc(~" Prints a given int to a string using base-16.

 ## Examples

 ```gleam
 assert int.to_base16(48) == \"30\"
 ```
").
to_base16(X) ->
    erlang:integer_to_binary(X, 16).

-file("src/gleam/int.gleam", 232).
-spec to_base36(integer()) -> binary().
-doc(~" Prints a given int to a string using base-36.

 ## Examples

 ```gleam
 assert int.to_base36(48) == \"1C\"
 ```
").
to_base36(X) ->
    erlang:integer_to_binary(X, 36).

-file("src/gleam/int.gleam", 329).
-spec max(integer(), integer()) -> integer().
-doc(~" Compares two ints, returning the larger of the two.

 ## Examples

 ```gleam
 assert int.max(2, 3) == 3
 ```
").
max(A, B) ->
    case A > B of
        true ->
            A;

        false ->
            B
    end.

-file("src/gleam/int.gleam", 314).
-spec min(integer(), integer()) -> integer().
-doc(~" Compares two ints, returning the smaller of the two.

 ## Examples

 ```gleam
 assert int.min(2, 3) == 2
 ```
").
min(A, B) ->
    case A < B of
        true ->
            A;

        false ->
            B
    end.

-file("src/gleam/int.gleam", 272).
-spec clamp(integer(), integer(), integer()) -> integer().
-doc(~" Restricts an int between two bounds.

 Note: If the `min` argument is larger than the `max` argument then they
 will be swapped, so the minimum bound is always lower than the maximum
 bound.

 ## Examples

 ```gleam
 assert int.clamp(40, min: 50, max: 60) == 50
 ```

 ```gleam
 assert int.clamp(40, min: 50, max: 30) == 40
 ```
").
clamp(X, Min_bound, Max_bound) ->
    case Min_bound >= Max_bound of
        true ->
            _pipe = X,
            _pipe@1 = min(_pipe, Min_bound),
            max(_pipe@1, Max_bound);

        false ->
            _pipe@2 = X,
            _pipe@3 = min(_pipe@2, Max_bound),
            max(_pipe@3, Min_bound)
    end.

-file("src/gleam/int.gleam", 295).
-spec compare(integer(), integer()) -> gleam@order:order().
-doc(~" Compares two ints, returning an order.

 ## Examples

 ```gleam
 assert int.compare(2, 3) == Lt
 ```

 ```gleam
 assert int.compare(4, 3) == Gt
 ```

 ```gleam
 assert int.compare(3, 3) == Eq
 ```
").
compare(A, B) ->
    case A =:= B of
        true ->
            eq;

        false ->
            case A < B of
                true ->
                    lt;

                false ->
                    gt
            end
    end.

-file("src/gleam/int.gleam", 348).
-spec is_even(integer()) -> boolean().
-doc(~" Returns whether the value provided is even.

 ## Examples

 ```gleam
 assert int.is_even(2)
 ```

 ```gleam
 assert !int.is_even(3)
 ```
").
is_even(X) ->
    (X rem 2) =:= 0.

-file("src/gleam/int.gleam", 364).
-spec is_odd(integer()) -> boolean().
-doc(~" Returns whether the value provided is odd.

 ## Examples

 ```gleam
 assert int.is_odd(3)
 ```

 ```gleam
 assert !int.is_odd(2)
 ```
").
is_odd(X) ->
    (X rem 2) /= 0.

-file("src/gleam/int.gleam", 376).
-spec negate(integer()) -> integer().
-doc(~" Returns the negative of the value provided.

 ## Examples

 ```gleam
 assert int.negate(1) == -1
 ```
").
negate(X) ->
    -1 * X.

-file("src/gleam/int.gleam", 392).
-spec sum_loop(list(integer()), integer()) -> integer().
sum_loop(Numbers, Initial) ->
    case Numbers of
        [First | Rest] ->
            sum_loop(Rest, First + Initial);

        [] ->
            Initial
    end.

-file("src/gleam/int.gleam", 388).
-spec sum(list(integer())) -> integer().
-doc(~" Sums a list of ints.

 ## Example

 ```gleam
 assert int.sum([1, 2, 3]) == 6
 ```
").
sum(Numbers) ->
    sum_loop(Numbers, 0).

-file("src/gleam/int.gleam", 411).
-spec product_loop(list(integer()), integer()) -> integer().
product_loop(Numbers, Initial) ->
    case Numbers of
        [First | Rest] ->
            product_loop(Rest, First * Initial);

        [] ->
            Initial
    end.

-file("src/gleam/int.gleam", 407).
-spec product(list(integer())) -> integer().
-doc(~" Multiplies a list of ints and returns the product.

 ## Example

 ```gleam
 assert int.product([2, 3, 4]) == 24
 ```
").
product(Numbers) ->
    product_loop(Numbers, 1).

-file("src/gleam/int.gleam", 439).
-spec random(integer()) -> integer().
-doc(~" Generates a random int between zero and the given maximum.

 The lower number is inclusive, the upper number is exclusive.

 ## Examples

 ```gleam
 int.random(10)
 // -> 4
 ```

 ```gleam
 int.random(1)
 // -> 0
 ```

 ```gleam
 int.random(-1)
 // -> -1
 ```
").
random(Max) ->
    _pipe = rand:uniform() * erlang:float(Max),
    _pipe@1 = math:floor(_pipe),
    erlang:round(_pipe@1).

-file("src/gleam/int.gleam", 468).
-spec divide(integer(), integer()) -> {ok, integer()} | {error, nil}.
-doc(~" Performs a truncated integer division.

 Returns division of the inputs as a `Result`: If the given divisor equals
 `0`, this function returns an `Error`.

 ## Examples

 ```gleam
 assert int.divide(0, 1) == Ok(0)
 ```

 ```gleam
 assert int.divide(1, 0) == Error(Nil)
 ```

 ```gleam
 assert int.divide(5, 2) == Ok(2)
 ```

 ```gleam
 assert int.divide(-99, 2) == Ok(-49)
 ```
").
divide(Dividend, Divisor) ->
    case Divisor of
        0 ->
            {error, nil};

        Divisor@1 ->
            {ok, case Divisor@1 of
                0 ->
                    0;

                _value ->
                    Dividend div _value
            end}
    end.

-file("src/gleam/int.gleam", 513).
-spec remainder(integer(), integer()) -> {ok, integer()} | {error, nil}.
-doc(~" Computes the remainder of an integer division of inputs as a `Result`.

 Returns division of the inputs as a `Result`: If the given divisor equals
 `0`, this function returns an `Error`.

 Most of the time you will want to use the `%` operator instead of this
 function.

 ## Examples

 ```gleam
 assert int.remainder(3, 2) == Ok(1)
 ```

 ```gleam
 assert int.remainder(1, 0) == Error(Nil)
 ```

 ```gleam
 assert int.remainder(10, -1) == Ok(0)
 ```

 ```gleam
 assert int.remainder(13, by: 3) == Ok(1)
 ```

 ```gleam
 assert int.remainder(-13, by: 3) == Ok(-1)
 ```

 ```gleam
 assert int.remainder(13, by: -3) == Ok(1)
 ```

 ```gleam
 assert int.remainder(-13, by: -3) == Ok(-1)
 ```
").
remainder(Dividend, Divisor) ->
    case Divisor of
        0 ->
            {error, nil};

        Divisor@1 ->
            {ok, case Divisor@1 of
                0 ->
                    0;

                _value ->
                    Dividend rem _value
            end}
    end.

-file("src/gleam/int.gleam", 554).
-spec modulo(integer(), integer()) -> {ok, integer()} | {error, nil}.
-doc(~" Computes the modulo of an integer division of inputs as a `Result`.

 Returns division of the inputs as a `Result`: If the given divisor equals
 `0`, this function returns an `Error`.

 Note that this is different from `int.remainder` and `%` in that the
 computed value will always have the same sign as the `divisor`.

 ## Examples

 ```gleam
 assert int.modulo(3, 2) == Ok(1)
 ```

 ```gleam
 assert int.modulo(1, 0) == Error(Nil)
 ```

 ```gleam
 assert int.modulo(10, -1) == Ok(0)
 ```

 ```gleam
 assert int.modulo(13, by: 3) == Ok(1)
 ```

 ```gleam
 assert int.modulo(-13, by: 3) == Ok(2)
 ```

 ```gleam
 assert int.modulo(13, by: -3) == Ok(-2)
 ```
").
modulo(Dividend, Divisor) ->
    case Divisor of
        0 ->
            {error, nil};

        _ ->
            Remainder = case Divisor of
                0 ->
                    0;

                _value ->
                    Dividend rem _value
            end,
            case (Remainder * Divisor) < 0 of
                true ->
                    {ok, Remainder + Divisor};

                false ->
                    {ok, Remainder}
            end
    end.

-file("src/gleam/int.gleam", 594).
-spec floor_divide(integer(), integer()) -> {ok, integer()} | {error, nil}.
-doc(~" Performs a *floored* integer division, which means that the result will
 always be rounded towards negative infinity.

 If you want to perform truncated integer division (rounding towards zero),
 use `int.divide()` or the `/` operator instead.

 Returns division of the inputs as a `Result`: If the given divisor equals
 `0`, this function returns an `Error`.

 ## Examples

 ```gleam
 assert int.floor_divide(1, 0) == Error(Nil)
 ```

 ```gleam
 assert int.floor_divide(5, 2) == Ok(2)
 ```

 ```gleam
 assert int.floor_divide(6, -4) == Ok(-2)
 ```

 ```gleam
 assert int.floor_divide(-99, 2) == Ok(-50)
 ```
").
floor_divide(Dividend, Divisor) ->
    case Divisor of
        0 ->
            {error, nil};

        Divisor@1 ->
            case ((Dividend * Divisor@1) < 0) andalso (case Divisor@1 of
                0 ->
                    0;

                _value ->
                    Dividend rem _value
            end /= 0) of
                true ->
                    {ok, case Divisor@1 of
                        0 ->
                            0;

                        _value@1 ->
                            Dividend div _value@1
                    end - 1};

                false ->
                    {ok, case Divisor@1 of
                        0 ->
                            0;

                        _value@2 ->
                            Dividend div _value@2
                    end}
            end
    end.

-file("src/gleam/int.gleam", 626).
-spec add(integer(), integer()) -> integer().
-doc(~" Adds two integers together.

 It's the function equivalent of the `+` operator.
 This function is useful in higher order functions or pipes.

 ## Examples

 ```gleam
 assert int.add(1, 2) == 3
 ```

 ```gleam
 import gleam/list

 assert list.fold([1, 2, 3], 0, int.add) == 6
 ```

 ```gleam
 assert 3 |> int.add(2) == 5
 ```
").
add(A, B) ->
    A + B.

-file("src/gleam/int.gleam", 651).
-spec multiply(integer(), integer()) -> integer().
-doc(~" Multiplies two integers together.

 It's the function equivalent of the `*` operator.
 This function is useful in higher order functions or pipes.

 ## Examples

 ```gleam
 assert int.multiply(2, 4) == 8
 ```

 ```gleam
 import gleam/list

 assert list.fold([2, 3, 4], 1, int.multiply) == 24
 ```

 ```gleam
 assert 3 |> int.multiply(2) == 6
 ```
").
multiply(A, B) ->
    A * B.

-file("src/gleam/int.gleam", 680).
-spec subtract(integer(), integer()) -> integer().
-doc(~" Subtracts one int from another.

 It's the function equivalent of the `-` operator.
 This function is useful in higher order functions or pipes.

 ## Examples

 ```gleam
 assert int.subtract(3, 1) == 2
 ```

 ```gleam
 import gleam/list

 assert list.fold([1, 2, 3], 10, int.subtract) == 4
 ```

 ```gleam
 assert 3 |> int.subtract(2) == 1
 ```

 ```gleam
 assert 3 |> int.subtract(2, _) == -1
 ```
").
subtract(A, B) ->
    A - B.

-file("src/gleam/int.gleam", 699).
-spec bitwise_and(integer(), integer()) -> integer().
-doc(~" Calculates the bitwise AND of its arguments.

 Most the time you should use the bit array syntaxes instead of manipulating
 bits as ints with bitwise functions.

 ## Target specific behaviour

 The exact behaviour of this function depends on the target platform.
 On Erlang it is equivalent to bitwise operations on ints, on JavaScript it
 is equivalent to bitwise operations on big-ints. If you need to avoid the
 overhead of big-ints on JavaScript use bit arrays or another package that
 provides faster bitwise operations.
").
bitwise_and(X, Y) ->
    erlang:'band'(X, Y).

-file("src/gleam/int.gleam", 716).
-spec bitwise_not(integer()) -> integer().
-doc(~" Calculates the bitwise NOT of its argument.

 Most the time you should use the bit array syntaxes instead of manipulating
 bits as ints with bitwise functions.

 ## Target specific behaviour

 The exact behaviour of this function depends on the target platform.
 On Erlang it is equivalent to bitwise operations on ints, on JavaScript it
 is equivalent to bitwise operations on big-ints. If you need to avoid the
 overhead of big-ints on JavaScript use bit arrays or another package that
 provides faster bitwise operations.
").
bitwise_not(X) ->
    erlang:'bnot'(X).

-file("src/gleam/int.gleam", 733).
-spec bitwise_or(integer(), integer()) -> integer().
-doc(~" Calculates the bitwise OR of its arguments.

 Most the time you should use the bit array syntaxes instead of manipulating
 bits as ints with bitwise functions.

 ## Target specific behaviour

 The exact behaviour of this function depends on the target platform.
 On Erlang it is equivalent to bitwise operations on ints, on JavaScript it
 is equivalent to bitwise operations on big-ints. If you need to avoid the
 overhead of big-ints on JavaScript use bit arrays or another package that
 provides faster bitwise operations.
").
bitwise_or(X, Y) ->
    erlang:'bor'(X, Y).

-file("src/gleam/int.gleam", 750).
-spec bitwise_exclusive_or(integer(), integer()) -> integer().
-doc(~" Calculates the bitwise XOR of its arguments.

 Most the time you should use the bit array syntaxes instead of manipulating
 bits as ints with bitwise functions.

 ## Target specific behaviour

 The exact behaviour of this function depends on the target platform.
 On Erlang it is equivalent to bitwise operations on ints, on JavaScript it
 is equivalent to bitwise operations on big-ints. If you need to avoid the
 overhead of big-ints on JavaScript use bit arrays or another package that
 provides faster bitwise operations.
").
bitwise_exclusive_or(X, Y) ->
    erlang:'bxor'(X, Y).

-file("src/gleam/int.gleam", 767).
-spec bitwise_shift_left(integer(), integer()) -> integer().
-doc(~" Calculates the result of an arithmetic left bitshift.

 Most the time you should use the bit array syntaxes instead of manipulating
 bits as ints with bitwise functions.

 ## Target specific behaviour

 The exact behaviour of this function depends on the target platform.
 On Erlang it is equivalent to bitwise operations on ints, on JavaScript it
 is equivalent to bitwise operations on big-ints. If you need to avoid the
 overhead of big-ints on JavaScript use bit arrays or another package that
 provides faster bitwise operations.
").
bitwise_shift_left(X, Y) ->
    erlang:'bsl'(X, Y).

-file("src/gleam/int.gleam", 784).
-spec bitwise_shift_right(integer(), integer()) -> integer().
-doc(~" Calculates the result of an arithmetic right bitshift.

 Most the time you should use the bit array syntaxes instead of manipulating
 bits as ints with bitwise functions.

 ## Target specific behaviour

 The exact behaviour of this function depends on the target platform.
 On Erlang it is equivalent to bitwise operations on ints, on JavaScript it
 is equivalent to bitwise operations on big-ints. If you need to avoid the
 overhead of big-ints on JavaScript use bit arrays or another package that
 provides faster bitwise operations.
").
bitwise_shift_right(X, Y) ->
    erlang:'bsr'(X, Y).

-file("src/gleam/int.gleam", 816).
-spec range_loop(integer(), integer(), integer(), CM, fun((CM, integer()) -> CM)) -> CM.
range_loop(Current, Stop, Increment, Acc, Reducer) ->
    case Current =:= Stop of
        true ->
            Acc;

        false ->
            Acc@1 = Reducer(Acc, Current),
            Current@1 = Current + Increment,
            range_loop(Current@1, Stop, Increment, Acc@1, Reducer)
    end.

-file("src/gleam/int.gleam", 803).
-spec range(integer(), integer(), CL, fun((CL, integer()) -> CL)) -> CL.
-doc(~" Run a function for each int between ints `from` and `to`.

 `from` is inclusive, and `to` is exclusive.

 ## Examples

 ```gleam
 assert int.range(from: 0, to: 3, with: \"\", run: fn(acc, i) {
     acc <> int.to_string(i)
   })
   == \"012\"
 ```

 ```gleam
 assert int.range(from: 1, to: -2, with: [], run: list.prepend) == [-1, 0, 1]
 ```
").
range(Start, Stop, Acc, Reducer) ->
    Increment = case Start < Stop of
        true ->
            1;

        false ->
            -1
    end,
    range_loop(Start, Stop, Increment, Acc, Reducer).

