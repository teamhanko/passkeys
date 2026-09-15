-module(gleam@set).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([new/0, size/1, is_empty/1, insert/2, contains/2, delete/2, to_list/1, from_list/1, fold/3, filter/2, map/2, drop/2, take/2, union/2, intersection/2, difference/2, is_subset/2, is_disjoint/2, symmetric_difference/2, each/2]).
-export_type([set/1]).

-opaque set(CVL) :: {set, gleam@dict:dict(CVL, list(nil))}.

-file("src/gleam/set.gleam", 32).
-spec new() -> set(any()).
-doc(~" Creates a new empty set.
").
new() ->
    {set, maps:new()}.

-file("src/gleam/set.gleam", 50).
-spec size(set(any())) -> integer().
-doc(~" Gets the number of members in a set.

 This function runs in constant time.

 ## Examples

 ```gleam
 assert set.new()
   |> set.insert(1)
   |> set.insert(2)
   |> set.size
   == 2
 ```
").
size(Set) ->
    maps:size(erlang:element(2, Set)).

-file("src/gleam/set.gleam", 66).
-spec is_empty(set(any())) -> boolean().
-doc(~" Determines whether or not the set is empty.

 ## Examples

 ```gleam
 assert set.new() |> set.is_empty
 ```

 ```gleam
 assert !{ set.new() |> set.insert(1) |> set.is_empty }
 ```
").
is_empty(Set) ->
    Set =:= new().

-file("src/gleam/set.gleam", 84).
-spec insert(set(CVT), CVT) -> set(CVT).
-doc(~" Inserts a member into the set.

 This function runs in logarithmic time.

 ## Examples

 ```gleam
 assert set.new()
   |> set.insert(1)
   |> set.insert(2)
   |> set.size
   == 2
 ```
").
insert(Set, Member) ->
    {set, gleam@dict:insert(erlang:element(2, Set), Member, [])}.

-file("src/gleam/set.gleam", 108).
-spec contains(set(CVW), CVW) -> boolean().
-doc(~" Checks whether a set contains a given member.

 This function runs in logarithmic time.

 ## Examples

 ```gleam
 assert set.new()
   |> set.insert(2)
   |> set.contains(2)
 ```

 ```gleam
 assert !{
   set.new()
   |> set.insert(2)
   |> set.contains(1)
 }
 ```
").
contains(Set, Member) ->
    _pipe = erlang:element(2, Set),
    _pipe@1 = gleam_stdlib:map_get(_pipe, Member),
    gleam@result:is_ok(_pipe@1).

-file("src/gleam/set.gleam", 130).
-spec delete(set(CVY), CVY) -> set(CVY).
-doc(~" Removes a member from a set. If the set does not contain the member then
 the set is returned unchanged.

 This function runs in logarithmic time.

 ## Examples

 ```gleam
 assert !{
   set.new()
   |> set.insert(2)
   |> set.delete(2)
   |> set.contains(2)
 }
 ```
").
delete(Set, Member) ->
    {set, gleam@dict:delete(erlang:element(2, Set), Member)}.

-file("src/gleam/set.gleam", 147).
-spec to_list(set(CWB)) -> list(CWB).
-doc(~" Converts the set into a list of the contained members.

 The list has no specific ordering, any unintentional ordering may change in
 future versions of Gleam or Erlang.

 This function runs in linear time.

 ## Examples

 ```gleam
 assert set.new() |> set.insert(2) |> set.to_list == [2]
 ```
").
to_list(Set) ->
    maps:keys(erlang:element(2, Set)).

-file("src/gleam/set.gleam", 168).
-spec from_list(list(CWE)) -> set(CWE).
-doc(~" Creates a new set of the members in a given list.

 This function runs in loglinear time.

 ## Examples

 ```gleam
 import gleam/int
 import gleam/list

 assert [1, 1, 2, 4, 3, 2]
   |> set.from_list
   |> set.to_list
   |> list.sort(by: int.compare)
   == [1, 2, 3, 4]
 ```
").
from_list(Members) ->
    Dict = gleam@list:fold(Members, maps:new(), fun(M, K) ->
        gleam@dict:insert(M, K, [])
    end),
    {set, Dict}.

-file("src/gleam/set.gleam", 191).
-spec fold(set(CWH), CWJ, fun((CWJ, CWH) -> CWJ)) -> CWJ.
-doc(~" Combines all entries into a single value by calling a given function on each
 one.

 Sets are not ordered so the values are not returned in any specific order.
 Do not write code that relies on the order entries are used by this
 function as it may change in later versions of Gleam or Erlang.

 ## Examples

 ```gleam
 assert set.from_list([1, 3, 9])
   |> set.fold(0, fn(accumulator, member) { accumulator + member })
   == 13
 ```
").
fold(Set, Initial, Reducer) ->
    gleam@dict:fold(erlang:element(2, Set), Initial, fun(A, K, _) ->
        Reducer(A, K)
    end).

-file("src/gleam/set.gleam", 215).
-spec filter(set(CWK), fun((CWK) -> boolean())) -> set(CWK).
-doc(~" Creates a new set from an existing set, minus any members that a given
 function returns `False` for.

 This function runs in loglinear time.

 ## Examples

 ```gleam
 import gleam/int

 assert set.from_list([1, 4, 6, 3, 675, 44, 67])
   |> set.filter(keeping: int.is_even)
   |> set.to_list
   == [4, 6, 44]
 ```
").
filter(Set, Predicate) ->
    {set, gleam@dict:filter(erlang:element(2, Set), fun(M, _) ->
        Predicate(M)
    end)}.

-file("src/gleam/set.gleam", 234).
-spec map(set(CWN), fun((CWN) -> CWP)) -> set(CWP).
-doc(~" Creates a new set from a given set with the result of applying the given
 function to each member.

 ## Examples

 ```gleam
 assert set.from_list([1, 2, 3, 4])
   |> set.map(with: fn(x) { x * 2 })
   |> set.to_list
   == [2, 4, 6, 8]
 ```
").
map(Set, Fun) ->
    fold(Set, new(), fun(Acc, Member) ->
        insert(Acc, Fun(Member))
    end).

-file("src/gleam/set.gleam", 252).
-spec drop(set(CWR), list(CWR)) -> set(CWR).
-doc(~" Creates a new set from a given set with all the same entries except any
 entry found on the given list.

 ## Examples

 ```gleam
 assert set.from_list([1, 2, 3, 4])
   |> set.drop([1, 3])
   |> set.to_list
   == [2, 4]
 ```
").
drop(Set, Disallowed) ->
    gleam@list:fold(Disallowed, Set, fun delete/2).

-file("src/gleam/set.gleam", 273).
-spec take(set(CWV), list(CWV)) -> set(CWV).
-doc(~" Creates a new set from a given set, only including any members which are in
 a given list.

 This function runs in loglinear time.

 ## Examples

 ```gleam
 assert set.from_list([1, 2, 3])
   |> set.take([1, 3, 5])
   |> set.to_list
   == [1, 3]
 ```
").
take(Set, Desired) ->
    {set, gleam@dict:take(erlang:element(2, Set), Desired)}.

-file("src/gleam/set.gleam", 296).
-spec order(set(CXD), set(CXD)) -> {set(CXD), set(CXD)}.
order(First, Second) ->
    case maps:size(erlang:element(2, First)) > maps:size(erlang:element(2, Second)) of
        true ->
            {First, Second};

        false ->
            {Second, First}
    end.

-file("src/gleam/set.gleam", 291).
-spec union(set(CWZ), set(CWZ)) -> set(CWZ).
-doc(~" Creates a new set that contains all members of both given sets.

 This function runs in loglinear time.

 ## Examples

 ```gleam
 assert set.union(set.from_list([1, 2]), set.from_list([2, 3])) |> set.to_list
   == [1, 2, 3]
 ```
").
union(First, Second) ->
    {Larger, Smaller} = order(First, Second),
    fold(Smaller, Larger, fun insert/2).

-file("src/gleam/set.gleam", 318).
-spec intersection(set(CXI), set(CXI)) -> set(CXI).
-doc(~" Creates a new set that contains members that are present in both given sets.

 This function runs in loglinear time.

 ## Examples

 ```gleam
 assert set.intersection(set.from_list([1, 2]), set.from_list([2, 3]))
   |> set.to_list
   == [2]
 ```
").
intersection(First, Second) ->
    {Larger, Smaller} = order(First, Second),
    take(Larger, to_list(Smaller)).

-file("src/gleam/set.gleam", 337).
-spec difference(set(CXM), set(CXM)) -> set(CXM).
-doc(~" Creates a new set that contains members that are present in the first set
 but not the second.

 ## Examples

 ```gleam
 assert set.difference(set.from_list([1, 2]), set.from_list([2, 3, 4]))
   |> set.to_list
   == [1]
 ```
").
difference(First, Second) ->
    drop(First, to_list(Second)).

-file("src/gleam/set.gleam", 356).
-spec is_subset(set(CXQ), set(CXQ)) -> boolean().
-doc(~" Determines if a set is fully contained by another.

 ## Examples

 ```gleam
 assert set.is_subset(set.from_list([1]), set.from_list([1, 2]))
 ```

 ```gleam
 assert !set.is_subset(set.from_list([1, 2, 3]), set.from_list([3, 4, 5]))
 ```
").
is_subset(First, Second) ->
    intersection(First, Second) =:= First.

-file("src/gleam/set.gleam", 372).
-spec is_disjoint(set(CXT), set(CXT)) -> boolean().
-doc(~" Determines if two sets contain no common members

 ## Examples

 ```gleam
 assert set.is_disjoint(set.from_list([1, 2, 3]), set.from_list([4, 5, 6]))
 ```

 ```gleam
 assert !set.is_disjoint(set.from_list([1, 2, 3]), set.from_list([3, 4, 5]))
 ```
").
is_disjoint(First, Second) ->
    intersection(First, Second) =:= new().

-file("src/gleam/set.gleam", 390).
-spec symmetric_difference(set(CXW), set(CXW)) -> set(CXW).
-doc(~" Creates a new set that contains members that are present in either set, but
 not both.

 ## Examples

 ```gleam
 assert set.symmetric_difference(
     set.from_list([1, 2, 3]),
     set.from_list([3, 4]),
   )
   |> set.to_list
   == [1, 2, 4]
 ```
").
symmetric_difference(First, Second) ->
    difference(union(First, Second), intersection(First, Second)).

-file("src/gleam/set.gleam", 419).
-spec each(set(CYA), fun((CYA) -> any())) -> nil.
-doc(~" Calls a function for each member in a set, discarding the return
 value.

 Useful for producing a side effect for every item of a set.

 The order of elements in the iteration is an implementation detail that
 should not be relied upon.

 ## Examples

 ```gleam
 let set = set.from_list([\"apple\", \"banana\", \"cherry\"])

 assert set.each(set, io.println) == Nil
 // apple
 // banana
 // cherry
 ```
").
each(Set, Fun) ->
    fold(Set, nil, fun(Nil, Member) ->
        Fun(Member),
        Nil
    end).

