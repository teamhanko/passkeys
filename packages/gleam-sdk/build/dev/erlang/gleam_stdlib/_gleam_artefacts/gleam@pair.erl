-module(gleam@pair).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([first/1, second/1, swap/1, map_first/2, map_second/2, new/2]).

-file("src/gleam/pair.gleam", 9).
-spec first({CLZ, any()}) -> CLZ.
-doc(~" Returns the first element in a pair.

 ## Examples

 ```gleam
 assert pair.first(#(1, 2)) == 1
 ```
").
first(Pair) ->
    {A, _} = Pair,
    A.

-file("src/gleam/pair.gleam", 22).
-spec second({any(), CMC}) -> CMC.
-doc(~" Returns the second element in a pair.

 ## Examples

 ```gleam
 assert pair.second(#(1, 2)) == 2
 ```
").
second(Pair) ->
    {_, A} = Pair,
    A.

-file("src/gleam/pair.gleam", 35).
-spec swap({CMD, CME}) -> {CME, CMD}.
-doc(~" Returns a new pair with the elements swapped.

 ## Examples

 ```gleam
 assert pair.swap(#(1, 2)) == #(2, 1)
 ```
").
swap(Pair) ->
    {A, B} = Pair,
    {B, A}.

-file("src/gleam/pair.gleam", 49).
-spec map_first({CMF, CMG}, fun((CMF) -> CMH)) -> {CMH, CMG}.
-doc(~" Returns a new pair with the first element having had `with` applied to
 it.

 ## Examples

 ```gleam
 assert #(1, 2) |> pair.map_first(fn(n) { n * 2 }) == #(2, 2)
 ```
").
map_first(Pair, Fun) ->
    {A, B} = Pair,
    {Fun(A), B}.

-file("src/gleam/pair.gleam", 63).
-spec map_second({CMI, CMJ}, fun((CMJ) -> CMK)) -> {CMI, CMK}.
-doc(~" Returns a new pair with the second element having had `with` applied to
 it.

 ## Examples

 ```gleam
 assert #(1, 2) |> pair.map_second(fn(n) { n * 2 }) == #(1, 4)
 ```
").
map_second(Pair, Fun) ->
    {A, B} = Pair,
    {A, Fun(B)}.

-file("src/gleam/pair.gleam", 77).
-spec new(CML, CMM) -> {CML, CMM}.
-doc(~" Returns a new pair with the given elements. This can also be done using the dedicated
 syntax instead: `new(1, 2) == #(1, 2)`.

 ## Examples

 ```gleam
 assert pair.new(1, 2) == #(1, 2)
 ```
").
new(First, Second) ->
    {First, Second}.

