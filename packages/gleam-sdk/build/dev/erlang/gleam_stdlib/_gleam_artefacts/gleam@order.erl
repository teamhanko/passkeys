-module(gleam@order).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([negate/1, to_int/1, compare/2, reverse/1, break_tie/2, lazy_break_tie/2]).
-export_type([order/0]).

-type order() :: lt | eq | gt.

-file("src/gleam/order.gleam", 32).
-spec negate(order()) -> order().
-doc(~" Inverts an order, so less-than becomes greater-than and greater-than
 becomes less-than.

 ## Examples

 ```gleam
 assert order.negate(Lt) == Gt
 ```

 ```gleam
 assert order.negate(Eq) == Eq
 ```

 ```gleam
 assert order.negate(Gt) == Lt
 ```
").
negate(Order) ->
    case Order of
        lt ->
            gt;

        eq ->
            eq;

        gt ->
            lt
    end.

-file("src/gleam/order.gleam", 56).
-spec to_int(order()) -> integer().
-doc(~" Produces a numeric representation of the order.

 ## Examples

 ```gleam
 assert order.to_int(Lt) == -1
 ```

 ```gleam
 assert order.to_int(Eq) == 0
 ```

 ```gleam
 assert order.to_int(Gt) == 1
 ```
").
to_int(Order) ->
    case Order of
        lt ->
            -1;

        eq ->
            0;

        gt ->
            1
    end.

-file("src/gleam/order.gleam", 72).
-spec compare(order(), order()) -> order().
-doc(~" Compares two `Order` values to one another, producing a new `Order`.

 ## Examples

 ```gleam
 assert order.compare(Eq, with: Lt) == Gt
 ```
").
compare(A, B) ->
    case {A, B} of
        {X, Y} when X =:= Y ->
            eq;

        {lt, _} ->
            lt;

        {eq, gt} ->
            lt;

        {_, _} ->
            gt
    end.

-file("src/gleam/order.gleam", 92).
-spec reverse(fun((I, I) -> order())) -> fun((I, I) -> order()).
-doc(~" Inverts an ordering function, so less-than becomes greater-than and greater-than
 becomes less-than.

 ## Examples

 ```gleam
 import gleam/int
 import gleam/list

 assert list.sort([1, 5, 4], by: order.reverse(int.compare)) == [5, 4, 1]
 ```
").
reverse(Orderer) ->
    fun(A, B) ->
        Orderer(B, A)
    end.

-file("src/gleam/order.gleam", 112).
-spec break_tie(order(), order()) -> order().
-doc(~" Return a fallback `Order` in case the first argument is `Eq`.

 ## Examples

 ```gleam
 import gleam/int

 assert order.break_tie(in: int.compare(1, 1), with: Lt) == Lt
 ```

 ```gleam
 import gleam/int

 assert order.break_tie(in: int.compare(1, 0), with: Eq) == Gt
 ```
").
break_tie(Order, Other) ->
    case Order of
        lt ->
            Order;

        gt ->
            Order;

        eq ->
            Other
    end.

-file("src/gleam/order.gleam", 139).
-spec lazy_break_tie(order(), fun(() -> order())) -> order().
-doc(~" Invokes a fallback function returning an `Order` in case the first argument
 is `Eq`.

 This can be useful when the fallback comparison might be expensive and it
 needs to be delayed until strictly necessary.

 ## Examples

 ```gleam
 import gleam/int

 assert order.lazy_break_tie(in: int.compare(1, 1), with: fn() { Lt }) == Lt
 ```

 ```gleam
 import gleam/int

 assert order.lazy_break_tie(in: int.compare(1, 0), with: fn() { Eq }) == Gt
 ```
").
lazy_break_tie(Order, Comparison) ->
    case Order of
        lt ->
            Order;

        gt ->
            Order;

        eq ->
            Comparison()
    end.

