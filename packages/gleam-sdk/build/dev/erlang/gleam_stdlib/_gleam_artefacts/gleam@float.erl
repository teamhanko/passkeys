-module(gleam@float).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([parse/1, to_string/1, max/2, min/2, clamp/3, compare/2, absolute_value/1, loosely_compare/3, loosely_equals/3, ceiling/1, floor/1, negate/1, round/1, truncate/1, to_precision/2, power/2, square_root/1, sum/1, product/1, random/0, modulo/2, divide/2, add/2, multiply/2, subtract/2, logarithm/1, exponential/1]).
-moduledoc(~" Functions for working with floats.

 ## Float representation

 Floats are represented as 64 bit floating point numbers on both the Erlang
 and JavaScript runtimes. The floating point behaviour is native to their
 respective runtimes, so their exact behaviour will be slightly different on
 the two runtimes.

 ### Infinity and NaN

 Under the JavaScript runtime, exceeding the maximum (or minimum)
 representable value for a floating point value will result in Infinity (or
 -Infinity). Should you try to divide two infinities you will get NaN as a
 result.

 When running on BEAM, exceeding the maximum (or minimum) representable
 value for a floating point value will raise an error.

 ## Division by zero

 Gleam runs on the Erlang virtual machine, which does not follow the IEEE
 754 standard for floating point arithmetic and does not have an `Infinity`
 value.  In Erlang division by zero results in a crash, however Gleam does
 not have partial functions and operators in core so instead division by zero
 returns zero, a behaviour taken from Pony, Coq, and Lean.

 This may seem unexpected at first, but it is no less mathematically valid
 than crashing or returning a special value. Division by zero is undefined
 in mathematics.").

-file("src/gleam/float.gleam", 49).
-spec parse(binary()) -> {ok, float()} | {error, nil}.
-doc(~" Attempts to parse a string as a `Float`, returning `Error(Nil)` if it was
 not possible.

 ## Examples

 ```gleam
 assert float.parse(\"2.3\") == Ok(2.3)
 ```

 ```gleam
 assert float.parse(\"ABC\") == Error(Nil)
 ```
").
parse(String) ->
    gleam_stdlib:parse_float(String).

-file("src/gleam/float.gleam", 61).
-spec to_string(float()) -> binary().
-doc(~" Returns the string representation of the provided `Float`.

 ## Examples

 ```gleam
 assert float.to_string(2.3) == \"2.3\"
 ```
").
to_string(X) ->
    gleam_stdlib:float_to_string(X).

-file("src/gleam/float.gleam", 192).
-spec max(float(), float()) -> float().
-doc(~" Compares two `Float`s, returning the larger of the two.

 ## Examples

 ```gleam
 assert float.max(2.0, 2.3) == 2.3
 ```
").
max(A, B) ->
    case A > B of
        true ->
            A;

        false ->
            B
    end.

-file("src/gleam/float.gleam", 177).
-spec min(float(), float()) -> float().
-doc(~" Compares two `Float`s, returning the smaller of the two.

 ## Examples

 ```gleam
 assert float.min(2.0, 2.3) == 2.0
 ```
").
min(A, B) ->
    case A < B of
        true ->
            A;

        false ->
            B
    end.

-file("src/gleam/float.gleam", 80).
-spec clamp(float(), float(), float()) -> float().
-doc(~" Restricts a float between two bounds.

 Note: If the `min` argument is larger than the `max` argument then they
 will be swapped, so the minimum bound is always lower than the maximum
 bound.


 ## Examples

 ```gleam
 assert float.clamp(1.2, min: 1.4, max: 1.6) == 1.4
 ```

 ```gleam
 assert float.clamp(1.2, min: 1.4, max: 0.6) == 1.2
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

-file("src/gleam/float.gleam", 100).
-spec compare(float(), float()) -> gleam@order:order().
-doc(~" Compares two `Float`s, returning an `Order`:
 `Lt` for lower than, `Eq` for equals, or `Gt` for greater than.

 ## Examples

 ```gleam
 assert float.compare(2.0, 2.3) == Lt
 ```

 To handle
 [Floating Point Imprecision](https://en.wikipedia.org/wiki/Floating-point_arithmetic#Accuracy_problems)
 you may use [`loosely_compare`](#loosely_compare) instead.
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

-file("src/gleam/float.gleam", 302).
-spec absolute_value(float()) -> float().
-doc(~" Returns the absolute value of the input as a `Float`.

 ## Examples

 ```gleam
 assert float.absolute_value(-12.5) == 12.5
 ```

 ```gleam
 assert float.absolute_value(10.2) == 10.2
 ```
").
absolute_value(X) ->
    case X >= +0.0 of
        true ->
            X;

        false ->
            +0.0 - X
    end.

-file("src/gleam/float.gleam", 129).
-spec loosely_compare(float(), float(), float()) -> gleam@order:order().
-doc(~" Compares two `Float`s within a tolerance, returning an `Order`:
 `Lt` for lower than, `Eq` for equals, or `Gt` for greater than.

 This function allows Float comparison while handling
 [Floating Point Imprecision](https://en.wikipedia.org/wiki/Floating-point_arithmetic#Accuracy_problems).

 Notice: For `Float`s the tolerance won't be exact:
 `5.3 - 5.0` is not exactly `0.3`.

 ## Examples

 ```gleam
 assert float.loosely_compare(5.0, with: 5.3, tolerating: 0.5) == Eq
 ```

 If you want to check only for equality you may use
 [`loosely_equals`](#loosely_equals) instead.
").
loosely_compare(A, B, Tolerance) ->
    Difference = absolute_value(A - B),
    case Difference =< Tolerance of
        true ->
            eq;

        false ->
            compare(A, B)
    end.

-file("src/gleam/float.gleam", 160).
-spec loosely_equals(float(), float(), float()) -> boolean().
-doc(~" Checks for equality of two `Float`s within a tolerance,
 returning a `Bool`.

 This function allows Float comparison while handling
 [Floating Point Imprecision](https://en.wikipedia.org/wiki/Floating-point_arithmetic#Accuracy_problems).

 Notice: For `Float`s the tolerance won't be exact:
 `5.3 - 5.0` is not exactly `0.3`.

 ## Examples

 ```gleam
 assert float.loosely_equals(5.0, with: 5.3, tolerating: 0.5)
 ```

 ```gleam
 assert !float.loosely_equals(5.0, with: 5.1, tolerating: 0.1)
 ```
").
loosely_equals(A, B, Tolerance) ->
    Difference = absolute_value(A - B),
    Difference =< Tolerance.

-file("src/gleam/float.gleam", 209).
-spec ceiling(float()) -> float().
-doc(~" Rounds the value to the next highest whole number as a `Float`.

 ## Examples

 ```gleam
 assert float.ceiling(2.3) == 3.0
 ```
").
ceiling(X) ->
    math:ceil(X).

-file("src/gleam/float.gleam", 221).
-spec floor(float()) -> float().
-doc(~" Rounds the value to the next lowest whole number as a `Float`.

 ## Examples

 ```gleam
 assert float.floor(2.3) == 2.0
 ```
").
floor(X) ->
    math:floor(X).

-file("src/gleam/float.gleam", 376).
-spec negate(float()) -> float().
-doc(~" Returns the negative of the value provided.

 ## Examples

 ```gleam
 assert float.negate(1.0) == -1.0
 ```
").
negate(X) ->
    -1.0 * X.

-file("src/gleam/float.gleam", 236).
-spec round(float()) -> integer().
-doc(~" Rounds the value to the nearest whole number as an `Int`.

 ## Examples

 ```gleam
 assert float.round(2.3) == 2
 ```

 ```gleam
 assert float.round(2.5) == 3
 ```
").
round(X) ->
    erlang:round(X).

-file("src/gleam/float.gleam", 256).
-spec truncate(float()) -> integer().
-doc(~" Returns the value as an `Int`, truncating all decimal digits.

 ## Examples

 ```gleam
 assert float.truncate(2.4343434847383438) == 2
 ```
").
truncate(X) ->
    erlang:trunc(X).

-file("src/gleam/float.gleam", 273).
-spec to_precision(float(), integer()) -> float().
-doc(~" Converts the value to a given precision as a `Float`.
 The precision is the number of allowed decimal places.
 Negative precisions are allowed and force rounding
 to the nearest tenth, hundredth, thousandth etc.

 ## Examples

 ```gleam
 assert float.to_precision(2.43434348473, 2) == 2.43
 ```

 ```gleam
 assert float.to_precision(547_890.453444, -3) == 548_000.0
 ```
").
to_precision(X, Precision) ->
    case Precision =< 0 of
        true ->
            Factor = math:pow(10.0, erlang:float(- Precision)),
            erlang:float(erlang:round(case Factor of
                +0.0 ->
                    +0.0;

                -0.0 ->
                    -0.0;

                _value ->
                    X / _value
            end)) * Factor;

        false ->
            Factor@1 = math:pow(10.0, erlang:float(Precision)),
            case Factor@1 of
                +0.0 ->
                    +0.0;

                -0.0 ->
                    -0.0;

                _value@1 ->
                    erlang:float(erlang:round(X * Factor@1)) / _value@1
            end
    end.

-file("src/gleam/float.gleam", 334).
-spec power(float(), float()) -> {ok, float()} | {error, nil}.
-doc(~" Returns the result of the base being raised to the power of the
 exponent, as a `Float`.

 ## Examples

 ```gleam
 assert float.power(2.0, -1.0) == Ok(0.5)
 ```

 ```gleam
 assert float.power(2.0, 2.0) == Ok(4.0)
 ```

 ```gleam
 assert float.power(8.0, 1.5) == Ok(22.627416997969522)
 ```

 ```gleam
 assert 4.0 |> float.power(of: 2.0) == Ok(16.0)
 ```

 ```gleam
 assert float.power(-1.0, 0.5) == Error(Nil)
 ```
").
power(Base, Exponent) ->
    Fractional = (math:ceil(Exponent) - Exponent) > +0.0,
    case ((Base < +0.0) andalso Fractional) orelse ((Base =:= +0.0) andalso (Exponent < +0.0)) of
        true ->
            {error, nil};

        false ->
            {ok, math:pow(Base, Exponent)}
    end.

-file("src/gleam/float.gleam", 364).
-spec square_root(float()) -> {ok, float()} | {error, nil}.
-doc(~" Returns the square root of the input as a `Float`.

 ## Examples

 ```gleam
 assert float.square_root(4.0) == Ok(2.0)
 ```

 ```gleam
 assert float.square_root(-16.0) == Error(Nil)
 ```
").
square_root(X) ->
    power(X, 0.5).

-file("src/gleam/float.gleam", 392).
-spec sum_loop(list(float()), float()) -> float().
sum_loop(Numbers, Initial) ->
    case Numbers of
        [First | Rest] ->
            sum_loop(Rest, First + Initial);

        [] ->
            Initial
    end.

-file("src/gleam/float.gleam", 388).
-spec sum(list(float())) -> float().
-doc(~" Sums a list of `Float`s.

 ## Example

 ```gleam
 assert float.sum([1.0, 2.2, 3.3]) == 6.5
 ```
").
sum(Numbers) ->
    sum_loop(Numbers, +0.0).

-file("src/gleam/float.gleam", 411).
-spec product_loop(list(float()), float()) -> float().
product_loop(Numbers, Initial) ->
    case Numbers of
        [First | Rest] ->
            product_loop(Rest, First * Initial);

        [] ->
            Initial
    end.

-file("src/gleam/float.gleam", 407).
-spec product(list(float())) -> float().
-doc(~" Multiplies a list of `Float`s and returns the product.

 ## Example

 ```gleam
 assert float.product([2.5, 3.2, 4.2]) == 33.6
 ```
").
product(Numbers) ->
    product_loop(Numbers, 1.0).

-file("src/gleam/float.gleam", 433).
-spec random() -> float().
-doc(~" Generates a random float between the given zero (inclusive) and one
 (exclusive).

 On Erlang this updates the random state in the process dictionary.
 See: <https://www.erlang.org/doc/man/rand.html#uniform-0>

 ## Examples

 ```gleam
 float.random()
 // -> 0.646355926896028
 ```
").
random() ->
    rand:uniform().

-file("src/gleam/float.gleam", 460).
-spec modulo(float(), float()) -> {ok, float()} | {error, nil}.
-doc(~" Computes the modulo of a float division of inputs as a `Result`.

 Returns division of the inputs as a `Result`: If the given divisor equals
 `0`, this function returns an `Error`.

 The computed value will always have the same sign as the `divisor`.

 ## Examples

 ```gleam
 assert float.modulo(13.3, by: 3.3) == Ok(0.1)
 ```

 ```gleam
 assert float.modulo(-13.3, by: 3.3) == Ok(3.2)
 ```

 ```gleam
 assert float.modulo(13.3, by: -3.3) == Ok(-3.2)
 ```

 ```gleam
 assert float.modulo(-13.3, by: -3.3) == Ok(-0.1)
 ```
").
modulo(Dividend, Divisor) ->
    case Divisor of
        +0.0 ->
            {error, nil};

        _ ->
            {ok, Dividend - (math:floor(case Divisor of
                +0.0 ->
                    +0.0;

                -0.0 ->
                    -0.0;

                _value ->
                    Dividend / _value
            end) * Divisor)}
    end.

-file("src/gleam/float.gleam", 479).
-spec divide(float(), float()) -> {ok, float()} | {error, nil}.
-doc(~" Returns division of the inputs as a `Result`.

 ## Examples

 ```gleam
 assert float.divide(0.0, 1.0) == Ok(0.0)
 ```

 ```gleam
 assert float.divide(1.0, 0.0) == Error(Nil)
 ```
").
divide(A, B) ->
    case B of
        +0.0 ->
            {error, nil};

        B@1 ->
            {ok, case B@1 of
                +0.0 ->
                    +0.0;

                -0.0 ->
                    -0.0;

                _value ->
                    A / _value
            end}
    end.

-file("src/gleam/float.gleam", 507).
-spec add(float(), float()) -> float().
-doc(~" Adds two floats together.

 It's the function equivalent of the `+.` operator.
 This function is useful in higher order functions or pipes.

 ## Examples

 ```gleam
 assert float.add(1.0, 2.0) == 3.0
 ```

 ```gleam
 import gleam/list

 assert list.fold([1.0, 2.0, 3.0], 0.0, float.add) == 6.0
 ```

 ```gleam
 assert 3.0 |> float.add(2.0) == 5.0
 ```
").
add(A, B) ->
    A + B.

-file("src/gleam/float.gleam", 532).
-spec multiply(float(), float()) -> float().
-doc(~" Multiplies two floats together.

 It's the function equivalent of the `*.` operator.
 This function is useful in higher order functions or pipes.

 ## Examples

 ```gleam
 assert float.multiply(2.0, 4.0) == 8.0
 ```

 ```gleam
 import gleam/list

 assert list.fold([2.0, 3.0, 4.0], 1.0, float.multiply) == 24.0
 ```

 ```gleam
 assert 3.0 |> float.multiply(2.0) == 6.0
 ```
").
multiply(A, B) ->
    A * B.

-file("src/gleam/float.gleam", 561).
-spec subtract(float(), float()) -> float().
-doc(~" Subtracts one float from another.

 It's the function equivalent of the `-.` operator.
 This function is useful in higher order functions or pipes.

 ## Examples

 ```gleam
 assert float.subtract(3.0, 1.0) == 2.0
 ```

 ```gleam
 import gleam/list

 assert list.fold([1.0, 2.0, 3.0], 10.0, float.subtract) == 4.0
 ```

 ```gleam
 assert 3.0 |> float.subtract(2.0) == 1.0
 ```

 ```gleam
 assert 3.0 |> float.subtract(2.0, _) == -1.0
 ```
").
subtract(A, B) ->
    A - B.

-file("src/gleam/float.gleam", 586).
-spec logarithm(float()) -> {ok, float()} | {error, nil}.
-doc(~" Returns the natural logarithm (base e) of the given `Float` as a `Result`. If the
 input is less than or equal to 0, returns `Error(Nil)`.

 ## Examples

 ```gleam
 assert float.logarithm(1.0) == Ok(0.0)
 ```

 ```gleam
 assert float.logarithm(2.718281828459045) == Ok(1.0)
 ```

 ```gleam
 assert float.logarithm(0.0) == Error(Nil)
 ```

 ```gleam
 assert float.logarithm(-1.0) == Error(Nil)
 ```
").
logarithm(X) ->
    case X =< +0.0 of
        true ->
            {error, nil};

        false ->
            {ok, math:log(X)}
    end.

-file("src/gleam/float.gleam", 621).
-spec exponential(float()) -> float().
-doc(~" Returns e (Euler's number) raised to the power of the given exponent, as
 a `Float`.

 ## Examples

 ```gleam
 assert float.exponential(0.0) == 1.0
 ```

 ```gleam
 assert float.exponential(1.0) == 2.718281828459045
 ```

 ```gleam
 assert float.exponential(-1.0) == 0.36787944117144233
 ```
").
exponential(X) ->
    math:exp(X).

