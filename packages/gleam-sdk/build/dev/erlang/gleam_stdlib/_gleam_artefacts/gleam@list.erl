-module(gleam@list).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([length/1, count/2, reverse/1, is_empty/1, contains/2, first/1, rest/1, group/2, filter/2, filter_map/2, map/2, map2/3, map_fold/3, index_map/2, try_map/2, drop/2, take/2, new/0, wrap/1, append/2, prepend/2, flatten/1, flat_map/2, fold/3, fold_right/3, index_fold/3, try_fold/3, fold_until/3, find/2, find_map/2, all/2, any/2, zip/2, strict_zip/2, unzip/1, intersperse/2, unique/1, sort/2, repeat/2, split/2, split_while/2, key_find/2, key_filter/2, key_pop/2, key_set/3, each/2, try_each/2, partition/2, permutations/1, window/2, window_by_2/1, drop_while/2, take_while/2, chunk/2, sized_chunk/2, reduce/2, scan/3, last/1, combinations/2, combination_pairs/1, transpose/1, interleave/1, shuffle/1, max/2, sample/2]).
-export_type([continue_or_stop/1, sorting/0]).
-moduledoc(~" Lists are an ordered sequence of elements and are one of the most common
 data types in Gleam.

 New elements can be added and removed from the front of a list in
 constant time, while adding and removing from the end requires traversing
 and copying the whole list, so keep this in mind when designing your
 programs.

 There is a dedicated syntax for prefixing to a list:

 ```gleam
 let new_list = [1, 2, ..existing_list]
 ```

 And a matching syntax for getting the first elements of a list:

 ```gleam
 case list {
   [first_element, ..rest] -> first_element
   _ -> \"this pattern matches when the list is empty\"
 }
 ```
").

-type continue_or_stop(AAE) :: {continue, AAE} | {stop, AAE}.

-type sorting() :: ascending | descending.

-file("src/gleam/list.gleam", 57).
-spec length_loop(list(any()), integer()) -> integer().
length_loop(List, Count) ->
    case List of
        [_ | List@1] ->
            length_loop(List@1, Count + 1);

        [] ->
            Count
    end.

-file("src/gleam/list.gleam", 53).
-spec length(list(any())) -> integer().
-doc(~" Counts the number of elements in a given list.

 This function has to traverse the list to determine the number of elements,
 so it runs in linear time.

 This function is natively implemented by the virtual machine and is highly
 optimised.

 ## Examples

 ```gleam
 assert list.length([]) == 0
 ```

 ```gleam
 assert list.length([1]) == 1
 ```

 ```gleam
 assert list.length([1, 2]) == 2
 ```
").
length(List) ->
    erlang:length(List).

-file("src/gleam/list.gleam", 87).
-spec count_loop(list(AAL), fun((AAL) -> boolean()), integer()) -> integer().
count_loop(List, Predicate, Acc) ->
    case List of
        [] ->
            Acc;

        [First | Rest] ->
            case Predicate(First) of
                true ->
                    count_loop(Rest, Predicate, Acc + 1);

                false ->
                    count_loop(Rest, Predicate, Acc)
            end
    end.

-file("src/gleam/list.gleam", 83).
-spec count(list(AAJ), fun((AAJ) -> boolean())) -> integer().
-doc(~" Counts the number of elements in a given list satisfying a given predicate.

 This function has to traverse the list to determine the number of elements,
 so it runs in linear time.

 ## Examples

 ```gleam
 assert list.count([], fn(a) { a > 0 }) == 0
 ```

 ```gleam
 assert list.count([1], fn(a) { a > 0 }) == 1
 ```

 ```gleam
 assert list.count([1, 2, 3], int.is_odd) == 2
 ```
").
count(List, Predicate) ->
    count_loop(List, Predicate, 0).

-file("src/gleam/list.gleam", 122).
-spec reverse(list(AAN)) -> list(AAN).
-doc(~" Creates a new list from a given list containing the same elements but in the
 opposite order.

 This function has to traverse the list to create the new reversed list, so
 it runs in linear time.

 This function is natively implemented by the virtual machine and is highly
 optimised.

 ## Examples

 ```gleam
 assert list.reverse([]) == []
 ```

 ```gleam
 assert list.reverse([1]) == [1]
 ```

 ```gleam
 assert list.reverse([1, 2]) == [2, 1]
 ```
").
reverse(List) ->
    lists:reverse(List).

-file("src/gleam/list.gleam", 156).
-spec is_empty(list(any())) -> boolean().
-doc(~" Determines whether or not the list is empty.

 This function runs in constant time.

 ## Examples

 ```gleam
 assert list.is_empty([])
 ```

 ```gleam
 assert !list.is_empty([1])
 ```

 ```gleam
 assert !list.is_empty([1, 1])
 ```
").
is_empty(List) ->
    List =:= [].

-file("src/gleam/list.gleam", 187).
-spec contains(list(AAW), AAW) -> boolean().
-doc(~" Determines whether or not a given element exists within a given list.

 This function traverses the list to find the element, so it runs in linear
 time.

 ## Examples

 ```gleam
 assert !list.contains([], any: 0)
 ```

 ```gleam
 assert [0] |> list.contains(any: 0)
 ```

 ```gleam
 assert !list.contains([1], any: 0)
 ```

 ```gleam
 assert !list.contains([1, 1], any: 0)
 ```

 ```gleam
 assert [1, 0] |> list.contains(any: 0)
 ```
").
contains(List, Elem) ->
    case List of
        [] ->
            false;

        [First | _] when First =:= Elem ->
            true;

        [_ | Rest] ->
            contains(Rest, Elem)
    end.

-file("src/gleam/list.gleam", 211).
-spec first(list(AAY)) -> {ok, AAY} | {error, nil}.
-doc(~" Gets the first element from the start of the list, if there is one.

 ## Examples

 ```gleam
 assert list.first([]) == Error(Nil)
 ```

 ```gleam
 assert list.first([0]) == Ok(0)
 ```

 ```gleam
 assert list.first([1, 2]) == Ok(1)
 ```
").
first(List) ->
    case List of
        [] ->
            {error, nil};

        [First | _] ->
            {ok, First}
    end.

-file("src/gleam/list.gleam", 237).
-spec rest(list(ABC)) -> {ok, list(ABC)} | {error, nil}.
-doc(~" Returns the list minus the first element. If the list is empty, `Error(Nil)` is
 returned.

 This function runs in constant time and does not make a copy of the list.

 ## Examples

 ```gleam
 assert list.rest([]) == Error(Nil)
 ```

 ```gleam
 assert list.rest([0]) == Ok([])
 ```

 ```gleam
 assert list.rest([1, 2]) == Ok([2])
 ```
").
rest(List) ->
    case List of
        [] ->
            {error, nil};

        [_ | Rest] ->
            {ok, Rest}
    end.

-file("src/gleam/list.gleam", 275).
-spec group(list(ABH), fun((ABH) -> ABJ)) -> gleam@dict:dict(ABJ, list(ABH)).
-doc(~" Groups the elements from the given list by the given key function.

 Does not preserve the initial value order.

 ## Examples

 ```gleam
 import gleam/dict

 assert [Ok(3), Error(\"Wrong\"), Ok(200), Ok(73)]
   |> list.group(by: fn(i) {
     case i {
       Ok(_) -> \"Successful\"
       Error(_) -> \"Failed\"
     }
   })
   |> dict.to_list
   == [
     #(\"Failed\", [Error(\"Wrong\")]),
     #(\"Successful\", [Ok(73), Ok(200), Ok(3)]),
   ]
 ```

 ```gleam
 import gleam/dict

 assert list.group([1, 2, 3, 4, 5], by: fn(i) { i - i / 3 * 3 })
   |> dict.to_list
   == [#(0, [3]), #(1, [4, 1]), #(2, [5, 2])]
 ```
").
group(List, Key) ->
    gleam@dict:group(Key, List).

-file("src/gleam/list.gleam", 296).
-spec filter_loop(list(ABQ), fun((ABQ) -> boolean()), list(ABQ)) -> list(ABQ).
filter_loop(List, Fun, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            New_acc = case Fun(First) of
                true ->
                    [First | Acc];

                false ->
                    Acc
            end,
            filter_loop(Rest, Fun, New_acc)
    end.

-file("src/gleam/list.gleam", 292).
-spec filter(list(ABN), fun((ABN) -> boolean())) -> list(ABN).
-doc(~" Returns a new list containing only the elements from the first list for
 which the given functions returns `True`.

 ## Examples

 ```gleam
 assert list.filter([2, 4, 6, 1], fn(x) { x > 2 }) == [4, 6]
 ```

 ```gleam
 assert list.filter([2, 4, 6, 1], fn(x) { x > 6 }) == []
 ```
").
filter(List, Predicate) ->
    filter_loop(List, Predicate, []).

-file("src/gleam/list.gleam", 326).
-spec filter_map_loop(list(ACB), fun((ACB) -> {ok, ACD} | {error, any()}), list(ACD)) -> list(ACD).
filter_map_loop(List, Fun, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            New_acc = case Fun(First) of
                {ok, First@1} ->
                    [First@1 | Acc];

                {error, _} ->
                    Acc
            end,
            filter_map_loop(Rest, Fun, New_acc)
    end.

-file("src/gleam/list.gleam", 322).
-spec filter_map(list(ABU), fun((ABU) -> {ok, ABW} | {error, any()})) -> list(ABW).
-doc(~" Returns a new list containing only the elements from the first list for
 which the given functions returns `Ok(_)`.

 ## Examples

 ```gleam
 assert list.filter_map([2, 4, 6, 1], Error) == []
 ```

 ```gleam
 assert list.filter_map([2, 4, 6, 1], fn(x) { Ok(x + 1) }) == [3, 5, 7, 2]
 ```
").
filter_map(List, Fun) ->
    filter_map_loop(List, Fun, []).

-file("src/gleam/list.gleam", 355).
-spec map_loop(list(ACN), fun((ACN) -> ACP), list(ACP)) -> list(ACP).
map_loop(List, Fun, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            map_loop(Rest, Fun, [Fun(First) | Acc])
    end.

-file("src/gleam/list.gleam", 351).
-spec map(list(ACJ), fun((ACJ) -> ACL)) -> list(ACL).
-doc(~" Returns a new list containing the results of applying the supplied function to each element.

 ## Examples

 ```gleam
 assert list.map([2, 4, 6], fn(x) { x * 2 }) == [4, 8, 12]
 ```
").
map(List, Fun) ->
    map_loop(List, Fun, []).

-file("src/gleam/list.gleam", 385).
-spec map2_loop(list(ACY), list(ADA), fun((ACY, ADA) -> ADC), list(ADC)) -> list(ADC).
map2_loop(List1, List2, Fun, Acc) ->
    case {List1, List2} of
        {[], _} ->
            lists:reverse(Acc);

        {_, []} ->
            lists:reverse(Acc);

        {[A | As_], [B | Bs]} ->
            map2_loop(As_, Bs, Fun, [Fun(A, B) | Acc])
    end.

-file("src/gleam/list.gleam", 377).
-spec map2(list(ACS), list(ACU), fun((ACS, ACU) -> ACW)) -> list(ACW).
-doc(~" Combines two lists into a single list using the given function.

 If a list is longer than the other, the extra elements are dropped.

 ## Examples

 ```gleam
 assert list.map2([1, 2, 3], [4, 5, 6], fn(x, y) { x + y }) == [5, 7, 9]
 ```

 ```gleam
 assert list.map2([1, 2], [\"a\", \"b\", \"c\"], fn(i, x) { #(i, x) })
   == [#(1, \"a\"), #(2, \"b\")]
 ```
").
map2(List1, List2, Fun) ->
    map2_loop(List1, List2, Fun, []).

-file("src/gleam/list.gleam", 416).
-spec map_fold_loop(list(ADK), fun((ADM, ADK) -> {ADM, ADN}), ADM, list(ADN)) -> {ADM, list(ADN)}.
map_fold_loop(List, Fun, Acc, List_acc) ->
    case List of
        [] ->
            {Acc, lists:reverse(List_acc)};

        [First | Rest] ->
            {Acc@1, First@1} = Fun(Acc, First),
            map_fold_loop(Rest, Fun, Acc@1, [First@1 | List_acc])
    end.

-file("src/gleam/list.gleam", 408).
-spec map_fold(list(ADF), ADH, fun((ADH, ADF) -> {ADH, ADI})) -> {ADH, list(ADI)}.
-doc(~" Similar to `map` but also lets you pass around an accumulated value.

 ## Examples

 ```gleam
 assert list.map_fold(over: [1, 2, 3], from: 100, with: fn(memo, i) {
     #(memo + i, i * 2)
   })
   == #(106, [2, 4, 6])
 ```
").
map_fold(List, Initial, Fun) ->
    map_fold_loop(List, Fun, Initial, []).

-file("src/gleam/list.gleam", 448).
-spec index_map_loop(list(ADU), fun((ADU, integer()) -> ADW), integer(), list(ADW)) -> list(ADW).
index_map_loop(List, Fun, Index, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            Acc@1 = [Fun(First, Index) | Acc],
            index_map_loop(Rest, Fun, Index + 1, Acc@1)
    end.

-file("src/gleam/list.gleam", 444).
-spec index_map(list(ADQ), fun((ADQ, integer()) -> ADS)) -> list(ADS).
-doc(~" Similar to `map`, but the supplied function will also be passed the index
 of the element being mapped as an additional argument.

 The index starts at 0, so the first element is 0, the second is 1, and so
 on.

 ## Examples

 ```gleam
 assert list.index_map([\"a\", \"b\"], fn(x, i) { #(i, x) })
   == [#(0, \"a\"), #(1, \"b\")]
 ```
").
index_map(List, Fun) ->
    index_map_loop(List, Fun, 0, []).

-file("src/gleam/list.gleam", 498).
-spec try_map_loop(list(AEI), fun((AEI) -> {ok, AEK} | {error, AEL}), list(AEK)) -> {ok, list(AEK)} | {error, AEL}.
try_map_loop(List, Fun, Acc) ->
    case List of
        [] ->
            {ok, lists:reverse(Acc)};

        [First | Rest] ->
            case Fun(First) of
                {ok, First@1} ->
                    try_map_loop(Rest, Fun, [First@1 | Acc]);

                {error, Error} ->
                    {error, Error}
            end
    end.

-file("src/gleam/list.gleam", 491).
-spec try_map(list(ADZ), fun((ADZ) -> {ok, AEB} | {error, AEC})) -> {ok, list(AEB)} | {error, AEC}.
-doc(~" Takes a function that returns a `Result` and applies it to each element in a
 given list in turn.

 If the function returns `Ok(new_value)` for all elements in the list then a
 list of the new values is returned.

 If the function returns `Error(reason)` for any of the elements then it is
 returned immediately. None of the elements in the list are processed after
 one returns an `Error`.

 ## Examples

 ```gleam
 assert list.try_map([1, 2, 3], fn(x) { Ok(x + 2) }) == Ok([3, 4, 5])
 ```

 ```gleam
 assert list.try_map([1, 2, 3], fn(_) { Error(0) }) == Error(0)
 ```

 ```gleam
 assert list.try_map([[1], [2, 3]], list.first) == Ok([1, 2])
 ```

 ```gleam
 assert list.try_map([[1], [], [2]], list.first) == Error(Nil)
 ```
").
try_map(List, Fun) ->
    try_map_loop(List, Fun, []).

-file("src/gleam/list.gleam", 531).
-spec drop(list(AES), integer()) -> list(AES).
-doc(~" Returns a list that is the given list with up to the given number of
 elements removed from the front of the list.

 If the list has less than the number of elements an empty list is
 returned.

 This function runs in linear time but does not copy the list.

 ## Examples

 ```gleam
 assert list.drop([1, 2, 3, 4], 2) == [3, 4]
 ```

 ```gleam
 assert list.drop([1, 2, 3, 4], 9) == []
 ```
").
drop(List, N) ->
    case N =< 0 of
        true ->
            List;

        false ->
            case List of
                [] ->
                    [];

                [_ | Rest] ->
                    drop(Rest, N - 1)
            end
    end.

-file("src/gleam/list.gleam", 564).
-spec take_loop(list(AEY), integer(), list(AEY)) -> list(AEY).
take_loop(List, N, Acc) ->
    case N =< 0 of
        true ->
            lists:reverse(Acc);

        false ->
            case List of
                [] ->
                    lists:reverse(Acc);

                [First | Rest] ->
                    take_loop(Rest, N - 1, [First | Acc])
            end
    end.

-file("src/gleam/list.gleam", 560).
-spec take(list(AEV), integer()) -> list(AEV).
-doc(~" Returns a list containing the first given number of elements from the given
 list.

 If the list has less than the number of elements then the full list is
 returned.

 This function runs in linear time.

 ## Examples

 ```gleam
 assert list.take([1, 2, 3, 4], 2) == [1, 2]
 ```

 ```gleam
 assert list.take([1, 2, 3, 4], 9) == [1, 2, 3, 4]
 ```
").
take(List, N) ->
    take_loop(List, N, []).

-file("src/gleam/list.gleam", 583).
-spec new() -> list(any()).
-doc(~" Returns a new empty list.

 ## Examples

 ```gleam
 assert list.new() == []
 ```
").
new() ->
    [].

-file("src/gleam/list.gleam", 604).
-spec wrap(AFE) -> list(AFE).
-doc(~" Returns the given item wrapped in a list.

 ## Examples

 ```gleam
 assert list.wrap(1) == [1]
 ```

 ```gleam
 assert list.wrap([\"a\", \"b\", \"c\"]) == [[\"a\", \"b\", \"c\"]]
 ```

 ```gleam
 assert list.wrap([[]]) == [[[]]]
 ```

").
wrap(Item) ->
    [Item].

-file("src/gleam/list.gleam", 624).
-spec append_loop(list(AFK), list(AFK)) -> list(AFK).
append_loop(First, Second) ->
    case First of
        [] ->
            Second;

        [First@1 | Rest] ->
            append_loop(Rest, [First@1 | Second])
    end.

-file("src/gleam/list.gleam", 620).
-spec append(list(AFG), list(AFG)) -> list(AFG).
-doc(~" Joins one list onto the end of another.

 This function runs in linear time, and it traverses and copies the first
 list.

 ## Examples

 ```gleam
 assert list.append([1, 2], [3]) == [1, 2, 3]
 ```
").
append(First, Second) ->
    lists:append(First, Second).

-file("src/gleam/list.gleam", 644).
-spec prepend(list(AFO), AFO) -> list(AFO).
-doc(~" Prefixes an item to a list. This can also be done using the dedicated
 syntax instead.

 ```gleam
 let existing_list = [2, 3, 4]
 assert [1, ..existing_list] == [1, 2, 3, 4]
 ```

 ```gleam
 let existing_list = [2, 3, 4]
 assert list.prepend(to: existing_list, this: 1) == [1, 2, 3, 4]
 ```
").
prepend(List, Item) ->
    [Item | List].

-file("src/gleam/list.gleam", 664).
-spec flatten_loop(list(list(AFV)), list(AFV)) -> list(AFV).
flatten_loop(Lists, Acc) ->
    case Lists of
        [] ->
            lists:reverse(Acc);

        [List | Further_lists] ->
            flatten_loop(Further_lists, lists:reverse(List, Acc))
    end.

-file("src/gleam/list.gleam", 660).
-spec flatten(list(list(AFR))) -> list(AFR).
-doc(~" Joins a list of lists into a single list.

 This function traverses all elements twice on the JavaScript target.
 This function traverses all elements once on the Erlang target.

 ## Examples

 ```gleam
 assert list.flatten([[1], [2, 3], []]) == [1, 2, 3]
 ```
").
flatten(Lists) ->
    lists:append(Lists).

-file("src/gleam/list.gleam", 680).
-spec flat_map(list(AGA), fun((AGA) -> list(AGC))) -> list(AGC).
-doc(~" Maps the list with the given function into a list of lists, and then flattens it.

 ## Examples

 ```gleam
 assert list.flat_map([2, 4, 6], fn(x) { [x, x + 1] }) == [2, 3, 4, 5, 6, 7]
 ```
").
flat_map(List, Fun) ->
    lists:append(map(List, Fun)).

-file("src/gleam/list.gleam", 692).
-spec fold(list(AGF), AGH, fun((AGH, AGF) -> AGH)) -> AGH.
-doc(~" Reduces a list of elements into a single value by calling a given function
 on each element, going from left to right.

 `fold([1, 2, 3], 0, add)` is the equivalent of
 `add(add(add(0, 1), 2), 3)`.

 This function runs in linear time.
").
fold(List, Initial, Fun) ->
    case List of
        [] ->
            Initial;

        [First | Rest] ->
            fold(Rest, Fun(Initial, First), Fun)
    end.

-file("src/gleam/list.gleam", 714).
-spec fold_right(list(AGI), AGK, fun((AGK, AGI) -> AGK)) -> AGK.
-doc(~" Reduces a list of elements into a single value by calling a given function
 on each element, going from right to left.

 `fold_right([1, 2, 3], 0, add)` is the equivalent of
 `add(add(add(0, 3), 2), 1)`.

 This function runs in linear time.

 Unlike `fold` this function is not tail recursive. Where possible use
 `fold` instead as it will use less memory.
").
fold_right(List, Initial, Fun) ->
    case List of
        [] ->
            Initial;

        [First | Rest] ->
            Fun(fold_right(Rest, Initial, Fun), First)
    end.

-file("src/gleam/list.gleam", 751).
-spec index_fold_loop(list(AGO), AGQ, fun((AGQ, AGO, integer()) -> AGQ), integer()) -> AGQ.
index_fold_loop(Over, Acc, With, Index) ->
    case Over of
        [] ->
            Acc;

        [First | Rest] ->
            index_fold_loop(Rest, With(Acc, First, Index), With, Index + 1)
    end.

-file("src/gleam/list.gleam", 743).
-spec index_fold(list(AGL), AGN, fun((AGN, AGL, integer()) -> AGN)) -> AGN.
-doc(~" Like `fold` but the folding function also receives the index of the current element.

 ## Examples

 ```gleam
 assert [\"a\", \"b\", \"c\"]
   |> list.index_fold(\"\", fn(acc, item, index) {
     acc <> int.to_string(index) <> \":\" <> item <> \" \"
   })
   == \"0:a 1:b 2:c\"
 ```

 ```gleam
 assert [10, 20, 30]
   |> list.index_fold(0, fn(acc, item, index) { acc + item * index })
   == 80
 ```
").
index_fold(List, Initial, Fun) ->
    index_fold_loop(List, Initial, Fun, 0).

-file("src/gleam/list.gleam", 783).
-spec try_fold(list(AGR), AGT, fun((AGT, AGR) -> {ok, AGT} | {error, AGU})) -> {ok, AGT} | {error, AGU}.
-doc(~" A variant of fold that might fail.

 The folding function should return `Result(accumulator, error)`.
 If the returned value is `Ok(accumulator)` try_fold will try the next value in the list.
 If the returned value is `Error(error)` try_fold will stop and return that error.

 ## Examples

 ```gleam
 assert [1, 2, 3, 4]
   |> list.try_fold(0, fn(acc, i) {
     case i < 3 {
       True -> Ok(acc + i)
       False -> Error(Nil)
     }
   })
   == Error(Nil)
 ```
").
try_fold(List, Initial, Fun) ->
    case List of
        [] ->
            {ok, Initial};

        [First | Rest] ->
            case Fun(Initial, First) of
                {ok, Result} ->
                    try_fold(Rest, Result, Fun);

                {error, _} = Error ->
                    Error
            end
    end.

-file("src/gleam/list.gleam", 822).
-spec fold_until(list(AGZ), AHB, fun((AHB, AGZ) -> continue_or_stop(AHB))) -> AHB.
-doc(~" A variant of fold that allows to stop folding earlier.

 The folding function should return `ContinueOrStop(accumulator)`.
 If the returned value is `Continue(accumulator)` fold_until will try the next value in the list.
 If the returned value is `Stop(accumulator)` fold_until will stop and return that accumulator.

 ## Examples

 ```gleam
 assert [1, 2, 3, 4]
   |> list.fold_until(0, fn(acc, i) {
     case i < 3 {
       True -> Continue(acc + i)
       False -> Stop(acc)
     }
   })
   == 3
 ```
").
fold_until(List, Initial, Fun) ->
    case List of
        [] ->
            Initial;

        [First | Rest] ->
            case Fun(Initial, First) of
                {continue, Next_accumulator} ->
                    fold_until(Rest, Next_accumulator, Fun);

                {stop, B} ->
                    B
            end
    end.

-file("src/gleam/list.gleam", 856).
-spec find(list(AHD), fun((AHD) -> boolean())) -> {ok, AHD} | {error, nil}.
-doc(~" Finds the first element in a given list for which the given function returns
 `True`.

 Returns `Error(Nil)` if no such element is found.

 ## Examples

 ```gleam
 assert list.find([1, 2, 3], fn(x) { x > 2 }) == Ok(3)
 ```

 ```gleam
 assert list.find([1, 2, 3], fn(x) { x > 4 }) == Error(Nil)
 ```

 ```gleam
 assert list.find([], fn(_) { True }) == Error(Nil)
 ```
").
find(List, Is_desired) ->
    case List of
        [] ->
            {error, nil};

        [First | Rest] ->
            case Is_desired(First) of
                true ->
                    {ok, First};

                false ->
                    find(Rest, Is_desired)
            end
    end.

-file("src/gleam/list.gleam", 889).
-spec find_map(list(AHH), fun((AHH) -> {ok, AHJ} | {error, any()})) -> {ok, AHJ} | {error, nil}.
-doc(~" Finds the first element in a given list for which the given function returns
 `Ok(new_value)`, then returns the wrapped `new_value`.

 Returns `Error(Nil)` if no such element is found.

 ## Examples

 ```gleam
 assert list.find_map([[], [2], [3]], list.first) == Ok(2)
 ```

 ```gleam
 assert list.find_map([[], []], list.first) == Error(Nil)
 ```

 ```gleam
 assert list.find_map([], list.first) == Error(Nil)
 ```
").
find_map(List, Fun) ->
    case List of
        [] ->
            {error, nil};

        [First | Rest] ->
            case Fun(First) of
                {ok, First@1} ->
                    {ok, First@1};

                {error, _} ->
                    find_map(Rest, Fun)
            end
    end.

-file("src/gleam/list.gleam", 921).
-spec all(list(AHP), fun((AHP) -> boolean())) -> boolean().
-doc(~" Returns `True` if the given function returns `True` for all the elements in
 the given list. If the function returns `False` for any of the elements it
 immediately returns `False` without checking the rest of the list.

 ## Examples

 ```gleam
 assert list.all([], fn(x) { x > 3 })
 ```

 ```gleam
 assert list.all([4, 5], fn(x) { x > 3 })
 ```

 ```gleam
 assert !list.all([4, 3], fn(x) { x > 3 })
 ```
").
all(List, Predicate) ->
    case List of
        [] ->
            true;

        [First | Rest] ->
            case Predicate(First) of
                true ->
                    all(Rest, Predicate);

                false ->
                    false
            end
    end.

-file("src/gleam/list.gleam", 954).
-spec any(list(AHR), fun((AHR) -> boolean())) -> boolean().
-doc(~" Returns `True` if the given function returns `True` for any the elements in
 the given list. If the function returns `True` for any of the elements it
 immediately returns `True` without checking the rest of the list.

 ## Examples

 ```gleam
 assert !list.any([], fn(x) { x > 3 })
 ```

 ```gleam
 assert list.any([4, 5], fn(x) { x > 3 })
 ```

 ```gleam
 assert list.any([4, 3], fn(x) { x > 4 })
 ```

 ```gleam
 assert list.any([3, 4], fn(x) { x > 3 })
 ```
").
any(List, Predicate) ->
    case List of
        [] ->
            false;

        [First | Rest] ->
            case Predicate(First) of
                true ->
                    true;

                false ->
                    any(Rest, Predicate)
            end
    end.

-file("src/gleam/list.gleam", 992).
-spec zip_loop(list(AHY), list(AIA), list({AHY, AIA})) -> list({AHY, AIA}).
zip_loop(One, Other, Acc) ->
    case {One, Other} of
        {[First_one | Rest_one], [First_other | Rest_other]} ->
            zip_loop(Rest_one, Rest_other, [{First_one, First_other} | Acc]);

        {_, _} ->
            lists:reverse(Acc)
    end.

-file("src/gleam/list.gleam", 988).
-spec zip(list(AHT), list(AHV)) -> list({AHT, AHV}).
-doc(~" Takes two lists and returns a single list of 2-element tuples.

 If one of the lists is longer than the other, the remaining elements from
 the longer list are not used.

 ## Examples

 ```gleam
 assert list.zip([], []) == []
 ```

 ```gleam
 assert list.zip([1, 2], [3]) == [#(1, 3)]
 ```

 ```gleam
 assert list.zip([1], [3, 4]) == [#(1, 3)]
 ```

 ```gleam
 assert list.zip([1, 2], [3, 4]) == [#(1, 3), #(2, 4)]
 ```
").
zip(List, Other) ->
    zip_loop(List, Other, []).

-file("src/gleam/list.gleam", 1029).
-spec strict_zip_loop(list(AIL), list(AIN), list({AIL, AIN})) -> {ok, list({AIL, AIN})} | {error, nil}.
strict_zip_loop(One, Other, Acc) ->
    case {One, Other} of
        {[], []} ->
            {ok, lists:reverse(Acc)};

        {[], _} ->
            {error, nil};

        {_, []} ->
            {error, nil};

        {[First_one | Rest_one], [First_other | Rest_other]} ->
            strict_zip_loop(Rest_one, Rest_other, [{First_one, First_other} | Acc])
    end.

-file("src/gleam/list.gleam", 1022).
-spec strict_zip(list(AIE), list(AIG)) -> {ok, list({AIE, AIG})} | {error, nil}.
-doc(~" Takes two lists and returns a single list of 2-element tuples.

 If one of the lists is longer than the other, an `Error` is returned.

 ## Examples

 ```gleam
 assert list.strict_zip([], []) == Ok([])
 ```

 ```gleam
 assert list.strict_zip([1, 2], [3]) == Error(Nil)
 ```

 ```gleam
 assert list.strict_zip([1], [3, 4]) == Error(Nil)
 ```

 ```gleam
 assert list.strict_zip([1, 2], [3, 4]) == Ok([#(1, 3), #(2, 4)])
 ```
").
strict_zip(List, Other) ->
    strict_zip_loop(List, Other, []).

-file("src/gleam/list.gleam", 1058).
-spec unzip_loop(list({AIY, AIZ}), list(AIY), list(AIZ)) -> {list(AIY), list(AIZ)}.
unzip_loop(Input, One, Other) ->
    case Input of
        [] ->
            {lists:reverse(One), lists:reverse(Other)};

        [{First_one, First_other} | Rest] ->
            unzip_loop(Rest, [First_one | One], [First_other | Other])
    end.

-file("src/gleam/list.gleam", 1054).
-spec unzip(list({AIT, AIU})) -> {list(AIT), list(AIU)}.
-doc(~" Takes a single list of 2-element tuples and returns two lists.

 ## Examples

 ```gleam
 assert list.unzip([#(1, 2), #(3, 4)]) == #([1, 3], [2, 4])
 ```

 ```gleam
 assert list.unzip([]) == #([], [])
 ```
").
unzip(Input) ->
    unzip_loop(Input, [], []).

-file("src/gleam/list.gleam", 1091).
-spec intersperse_loop(list(AJI), AJI, list(AJI)) -> list(AJI).
intersperse_loop(List, Separator, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            intersperse_loop(Rest, Separator, [First, Separator | Acc])
    end.

-file("src/gleam/list.gleam", 1084).
-spec intersperse(list(AJF), AJF) -> list(AJF).
-doc(~" Inserts a given value between each existing element in a given list.

 This function runs in linear time and copies the list.

 ## Examples

 ```gleam
 assert list.intersperse([1, 1, 1], 2) == [1, 2, 1, 2, 1]
 ```

 ```gleam
 assert list.intersperse([], 2) == []
 ```
").
intersperse(List, Elem) ->
    case List of
        [] ->
            List;

        [_] ->
            List;

        [First | Rest] ->
            intersperse_loop(Rest, Elem, [First])
    end.

-file("src/gleam/list.gleam", 1113).
-spec unique_loop(list(AJP), gleam@dict:dict(AJP, nil), list(AJP)) -> list(AJP).
unique_loop(List, Seen, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            case gleam@dict:has_key(Seen, First) of
                true ->
                    unique_loop(Rest, Seen, Acc);

                false ->
                    unique_loop(Rest, gleam@dict:insert(Seen, First, nil), [First | Acc])
            end
    end.

-file("src/gleam/list.gleam", 1109).
-spec unique(list(AJM)) -> list(AJM).
-doc(~" Removes any duplicate elements from a given list.

 This function returns in loglinear time.

 ## Examples

 ```gleam
 assert list.unique([1, 1, 1, 4, 7, 3, 3, 4]) == [1, 4, 7, 3]
 ```
").
unique(List) ->
    unique_loop(List, maps:new(), []).

-file("src/gleam/list.gleam", 1374).
-spec merge_descendings(list(ALA), list(ALA), fun((ALA, ALA) -> gleam@order:order()), list(ALA)) -> list(ALA).
-doc(~" This is exactly the same as merge_ascendings but mirrored: it merges two
 lists sorted in descending order into a single list sorted in ascending
 order according to the given comparator function.

 This reversing of the sort order is not avoidable if we want to implement
 merge as a tail recursive function. We could reverse the accumulator before
 returning it but that would end up being less efficient; so the merging
 algorithm has to play around this.
").
merge_descendings(List1, List2, Compare, Acc) ->
    case {List1, List2} of
        {[], List} ->
            lists:reverse(List, Acc);

        {List, []} ->
            lists:reverse(List, Acc);

        {[First1 | Rest1], [First2 | Rest2]} ->
            case Compare(First1, First2) of
                lt ->
                    merge_descendings(List1, Rest2, Compare, [First2 | Acc]);

                gt ->
                    merge_descendings(Rest1, List2, Compare, [First1 | Acc]);

                eq ->
                    merge_descendings(Rest1, List2, Compare, [First1 | Acc])
            end
    end.

-file("src/gleam/list.gleam", 1322).
-spec merge_descending_pairs(list(list(AKP)), fun((AKP, AKP) -> gleam@order:order()), list(list(AKP))) -> list(list(AKP)).
-doc(~" This is the same as merge_ascending_pairs but flipped for descending lists.
").
merge_descending_pairs(Sequences, Compare, Acc) ->
    case Sequences of
        [] ->
            lists:reverse(Acc);

        [Sequence] ->
            lists:reverse([lists:reverse(Sequence) | Acc]);

        [Descending1, Descending2 | Rest] ->
            Ascending = merge_descendings(Descending1, Descending2, Compare, []),
            merge_descending_pairs(Rest, Compare, [Ascending | Acc])
    end.

-file("src/gleam/list.gleam", 1347).
-spec merge_ascendings(list(AKV), list(AKV), fun((AKV, AKV) -> gleam@order:order()), list(AKV)) -> list(AKV).
-doc(~" Merges two lists sorted in ascending order into a single list sorted in
 descending order according to the given comparator function.

 This reversing of the sort order is not avoidable if we want to implement
 merge as a tail recursive function. We could reverse the accumulator before
 returning it but that would end up being less efficient; so the merging
 algorithm has to play around this.
").
merge_ascendings(List1, List2, Compare, Acc) ->
    case {List1, List2} of
        {[], List} ->
            lists:reverse(List, Acc);

        {List, []} ->
            lists:reverse(List, Acc);

        {[First1 | Rest1], [First2 | Rest2]} ->
            case Compare(First1, First2) of
                lt ->
                    merge_ascendings(Rest1, List2, Compare, [First1 | Acc]);

                gt ->
                    merge_ascendings(List1, Rest2, Compare, [First2 | Acc]);

                eq ->
                    merge_ascendings(List1, Rest2, Compare, [First2 | Acc])
            end
    end.

-file("src/gleam/list.gleam", 1300).
-spec merge_ascending_pairs(list(list(AKJ)), fun((AKJ, AKJ) -> gleam@order:order()), list(list(AKJ))) -> list(list(AKJ)).
-doc(~" Given a list of ascending lists, it merges adjacent pairs into a single
 descending list, halving their number.
 It returns a list of the remaining descending lists.
").
merge_ascending_pairs(Sequences, Compare, Acc) ->
    case Sequences of
        [] ->
            lists:reverse(Acc);

        [Sequence] ->
            lists:reverse([lists:reverse(Sequence) | Acc]);

        [Ascending1, Ascending2 | Rest] ->
            Descending = merge_ascendings(Ascending1, Ascending2, Compare, []),
            merge_ascending_pairs(Rest, Compare, [Descending | Acc])
    end.

-file("src/gleam/list.gleam", 1266).
-spec merge_all(list(list(AKF)), sorting(), fun((AKF, AKF) -> gleam@order:order())) -> list(AKF).
-doc(~" Given some some sorted sequences (assumed to be sorted in `direction`) it
 merges them all together until we're left with just a list sorted in
 ascending order.
").
merge_all(Sequences, Direction, Compare) ->
    case {Sequences, Direction} of
        {[], _} ->
            [];

        {[Sequence], ascending} ->
            Sequence;

        {[Sequence@1], descending} ->
            lists:reverse(Sequence@1);

        {_, ascending} ->
            Sequences@1 = merge_ascending_pairs(Sequences, Compare, []),
            merge_all(Sequences@1, descending, Compare);

        {_, descending} ->
            Sequences@2 = merge_descending_pairs(Sequences, Compare, []),
            merge_all(Sequences@2, ascending, Compare)
    end.

-file("src/gleam/list.gleam", 1199).
-spec sequences(list(AJY), fun((AJY, AJY) -> gleam@order:order()), list(AJY), sorting(), AJY, list(list(AJY))) -> list(list(AJY)).
-doc(~" Given a list it returns slices of it that are locally sorted in ascending
 order.

 Imagine you have this list:

 ```
   [1, 2, 3, 2, 1, 0]
    ^^^^^^^  ^^^^^^^ This is a slice in descending order
    |
    | This is a slice that is sorted in ascending order
 ```

 So the produced result will contain these two slices, each one sorted in
 ascending order: `[[1, 2, 3], [0, 1, 2]]`.

 - `growing` is an accumulator with the current slice being grown
 - `direction` is the growing direction of the slice being grown, it could
   either be ascending or strictly descending
 - `prev` is the previous element that needs to be added to the growing slice
   it is carried around to check whether we have to keep growing the current
   slice or not
 - `acc` is the accumulator containing the slices sorted in ascending order
").
sequences(List, Compare, Growing, Direction, Prev, Acc) ->
    Growing@1 = [Prev | Growing],
    case List of
        [] ->
            case Direction of
                ascending ->
                    [lists:reverse(Growing@1) | Acc];

                descending ->
                    [Growing@1 | Acc]
            end;

        [New | Rest] ->
            case {Compare(Prev, New), Direction} of
                {gt, descending} ->
                    sequences(Rest, Compare, Growing@1, Direction, New, Acc);

                {lt, ascending} ->
                    sequences(Rest, Compare, Growing@1, Direction, New, Acc);

                {eq, ascending} ->
                    sequences(Rest, Compare, Growing@1, Direction, New, Acc);

                {gt, ascending} ->
                    Acc@1 = case Direction of
                        ascending ->
                            [lists:reverse(Growing@1) | Acc];

                        descending ->
                            [Growing@1 | Acc]
                    end,
                    case Rest of
                        [] ->
                            [[New] | Acc@1];

                        [Next | Rest@1] ->
                            Direction@1 = case Compare(New, Next) of
                                lt ->
                                    ascending;

                                eq ->
                                    ascending;

                                gt ->
                                    descending
                            end,
                            sequences(Rest@1, Compare, [New], Direction@1, Next, Acc@1)
                    end;

                {lt, descending} ->
                    Acc@1 = case Direction of
                        ascending ->
                            [lists:reverse(Growing@1) | Acc];

                        descending ->
                            [Growing@1 | Acc]
                    end,
                    case Rest of
                        [] ->
                            [[New] | Acc@1];

                        [Next | Rest@1] ->
                            Direction@1 = case Compare(New, Next) of
                                lt ->
                                    ascending;

                                eq ->
                                    ascending;

                                gt ->
                                    descending
                            end,
                            sequences(Rest@1, Compare, [New], Direction@1, Next, Acc@1)
                    end;

                {eq, descending} ->
                    Acc@1 = case Direction of
                        ascending ->
                            [lists:reverse(Growing@1) | Acc];

                        descending ->
                            [Growing@1 | Acc]
                    end,
                    case Rest of
                        [] ->
                            [[New] | Acc@1];

                        [Next | Rest@1] ->
                            Direction@1 = case Compare(New, Next) of
                                lt ->
                                    ascending;

                                eq ->
                                    ascending;

                                gt ->
                                    descending
                            end,
                            sequences(Rest@1, Compare, [New], Direction@1, Next, Acc@1)
                    end
            end
    end.

-file("src/gleam/list.gleam", 1137).
-spec sort(list(AJV), fun((AJV, AJV) -> gleam@order:order())) -> list(AJV).
-doc(~" Sorts from smallest to largest based upon the ordering specified by a given
 function.

 ## Examples

 ```gleam
 import gleam/int

 assert list.sort([4, 3, 6, 5, 4, 1, 2], by: int.compare)
   == [1, 2, 3, 4, 4, 5, 6]
 ```
").
sort(List, Compare) ->
    case List of
        [] ->
            [];

        [X] ->
            [X];

        [X@1, Y | Rest] ->
            Direction = case Compare(X@1, Y) of
                lt ->
                    ascending;

                eq ->
                    ascending;

                gt ->
                    descending
            end,
            Sequences = sequences(Rest, Compare, [X@1], Direction, Y, []),
            merge_all(Sequences, ascending, Compare)
    end.

-file("src/gleam/list.gleam", 1407).
-spec repeat_loop(ALH, integer(), list(ALH)) -> list(ALH).
repeat_loop(Item, Times, Acc) ->
    case Times =< 0 of
        true ->
            Acc;

        false ->
            repeat_loop(Item, Times - 1, [Item | Acc])
    end.

-file("src/gleam/list.gleam", 1403).
-spec repeat(ALF, integer()) -> list(ALF).
-doc(~" Builds a list of a given value a given number of times.

 ## Examples

 ```gleam
 assert list.repeat(\"a\", times: 0) == []
 ```

 ```gleam
 assert list.repeat(\"a\", times: 5) == [\"a\", \"a\", \"a\", \"a\", \"a\"]
 ```
").
repeat(A, Times) ->
    repeat_loop(A, Times, []).

-file("src/gleam/list.gleam", 1437).
-spec split_loop(list(ALO), integer(), list(ALO)) -> {list(ALO), list(ALO)}.
split_loop(List, N, Taken) ->
    case N =< 0 of
        true ->
            {lists:reverse(Taken), List};

        false ->
            case List of
                [] ->
                    {lists:reverse(Taken), []};

                [First | Rest] ->
                    split_loop(Rest, N - 1, [First | Taken])
            end
    end.

-file("src/gleam/list.gleam", 1433).
-spec split(list(ALK), integer()) -> {list(ALK), list(ALK)}.
-doc(~" Splits a list in two before the given index.

 If the list is not long enough to have the given index the before list will
 be the input list, and the after list will be empty.

 ## Examples

 ```gleam
 assert list.split([6, 7, 8, 9], 0) == #([], [6, 7, 8, 9])
 ```

 ```gleam
 assert list.split([6, 7, 8, 9], 2) == #([6, 7], [8, 9])
 ```

 ```gleam
 assert list.split([6, 7, 8, 9], 4) == #([6, 7, 8, 9], [])
 ```
").
split(List, Index) ->
    split_loop(List, Index, []).

-file("src/gleam/list.gleam", 1473).
-spec split_while_loop(list(ALX), fun((ALX) -> boolean()), list(ALX)) -> {list(ALX), list(ALX)}.
split_while_loop(List, F, Acc) ->
    case List of
        [] ->
            {lists:reverse(Acc), []};

        [First | Rest] ->
            case F(First) of
                true ->
                    split_while_loop(Rest, F, [First | Acc]);

                false ->
                    {lists:reverse(Acc), List}
            end
    end.

-file("src/gleam/list.gleam", 1466).
-spec split_while(list(ALT), fun((ALT) -> boolean())) -> {list(ALT), list(ALT)}.
-doc(~" Splits a list in two before the first element that a given function returns
 `False` for.

 If the function returns `True` for all elements the first list will be the
 input list, and the second list will be empty.

 ## Examples

 ```gleam
 assert list.split_while([1, 2, 3, 4, 5], fn(x) { x <= 3 })
   == #([1, 2, 3], [4, 5])
 ```

 ```gleam
 assert list.split_while([1, 2, 3, 4, 5], fn(x) { x <= 5 })
   == #([1, 2, 3, 4, 5], [])
 ```
").
split_while(List, Predicate) ->
    split_while_loop(List, Predicate, []).

-file("src/gleam/list.gleam", 1510).
-spec key_find(list({AMC, AMD}), AMC) -> {ok, AMD} | {error, nil}.
-doc(~" Given a list of 2-element tuples, finds the first tuple that has a given
 key as the first element and returns the second element.

 If no tuple is found with the given key then `Error(Nil)` is returned.

 This function may be useful for interacting with Erlang code where lists of
 tuples are common.

 ## Examples

 ```gleam
 assert list.key_find([#(\"a\", 0), #(\"b\", 1)], \"a\") == Ok(0)
 ```

 ```gleam
 assert list.key_find([#(\"a\", 0), #(\"b\", 1)], \"b\") == Ok(1)
 ```

 ```gleam
 assert list.key_find([#(\"a\", 0), #(\"b\", 1)], \"c\") == Error(Nil)
 ```
").
key_find(Keyword_list, Desired_key) ->
    find_map(Keyword_list, fun(Keyword) ->
        {Key, Value} = Keyword,
        case Key =:= Desired_key of
            true ->
                {ok, Value};

            false ->
                {error, nil}
        end
    end).

-file("src/gleam/list.gleam", 1539).
-spec key_filter(list({AMH, AMI}), AMH) -> list(AMI).
-doc(~" Given a list of 2-element tuples, finds all tuples that have a given
 key as the first element and returns the second element.

 This function may be useful for interacting with Erlang code where lists of
 tuples are common.

 ## Examples

 ```gleam
 assert list.key_filter([#(\"a\", 0), #(\"b\", 1), #(\"a\", 2)], \"a\") == [0, 2]
 ```

 ```gleam
 assert list.key_filter([#(\"a\", 0), #(\"b\", 1)], \"c\") == []
 ```
").
key_filter(Keyword_list, Desired_key) ->
    filter_map(Keyword_list, fun(Keyword) ->
        {Key, Value} = Keyword,
        case Key =:= Desired_key of
            true ->
                {ok, Value};

            false ->
                {error, nil}
        end
    end).

-file("src/gleam/list.gleam", 1579).
-spec key_pop_loop(list({AMR, AMS}), AMR, list({AMR, AMS})) -> {ok, {AMS, list({AMR, AMS})}} | {error, nil}.
key_pop_loop(List, Key, Checked) ->
    case List of
        [] ->
            {error, nil};

        [{K, V} | Rest] when K =:= Key ->
            {ok, {V, lists:reverse(Checked, Rest)}};

        [First | Rest@1] ->
            key_pop_loop(Rest@1, Key, [First | Checked])
    end.

-file("src/gleam/list.gleam", 1572).
-spec key_pop(list({AML, AMM}), AML) -> {ok, {AMM, list({AML, AMM})}} | {error, nil}.
-doc(~" Given a list of 2-element tuples, finds the first tuple that has a given
 key as the first element. This function will return the second element
 of the found tuple and list with tuple removed.

 If no tuple is found with the given key then `Error(Nil)` is returned.

 ## Examples

 ```gleam
 assert list.key_pop([#(\"a\", 0), #(\"b\", 1)], \"a\") == Ok(#(0, [#(\"b\", 1)]))
 ```

 ```gleam
 assert list.key_pop([#(\"a\", 0), #(\"b\", 1)], \"b\") == Ok(#(1, [#(\"a\", 0)]))
 ```

 ```gleam
 assert list.key_pop([#(\"a\", 0), #(\"b\", 1)], \"c\") == Error(Nil)
 ```
").
key_pop(List, Key) ->
    key_pop_loop(List, Key, []).

-file("src/gleam/list.gleam", 1612).
-spec key_set_loop(list({ANC, AND}), ANC, AND, list({ANC, AND})) -> list({ANC, AND}).
key_set_loop(List, Key, Value, Inspected) ->
    case List of
        [{K, _} | Rest] when K =:= Key ->
            lists:reverse(Inspected, [{K, Value} | Rest]);

        [First | Rest@1] ->
            key_set_loop(Rest@1, Key, Value, [First | Inspected]);

        [] ->
            lists:reverse([{Key, Value} | Inspected])
    end.

-file("src/gleam/list.gleam", 1608).
-spec key_set(list({AMY, AMZ}), AMY, AMZ) -> list({AMY, AMZ}).
-doc(~" Given a list of 2-element tuples, inserts a key and value into the list.

 If there was already a tuple with the key then it is replaced, otherwise it
 is added to the end of the list.

 ## Examples

 ```gleam
 assert list.key_set([#(5, 0), #(4, 1)], 4, 100) == [#(5, 0), #(4, 100)]
 ```

 ```gleam
 assert list.key_set([#(5, 0), #(4, 1)], 1, 100)
   == [#(5, 0), #(4, 1), #(1, 100)]
 ```
").
key_set(List, Key, Value) ->
    key_set_loop(List, Key, Value, []).

-file("src/gleam/list.gleam", 1639).
-spec each(list(ANH), fun((ANH) -> any())) -> nil.
-doc(~" Calls a function for each element in a list, discarding the return value.

 Useful for calling a side effect for every item of a list.

 ```gleam
 import gleam/io

 assert list.each([\"1\", \"2\", \"3\"], io.println) == Nil
 // 1
 // 2
 // 3
 ```
").
each(List, F) ->
    case List of
        [] ->
            nil;

        [First | Rest] ->
            F(First),
            each(Rest, F)
    end.

-file("src/gleam/list.gleam", 1662).
-spec try_each(list(ANK), fun((ANK) -> {ok, any()} | {error, ANN})) -> {ok, nil} | {error, ANN}.
-doc(~" Calls a `Result` returning function for each element in a list, discarding
 the return value. If the function returns `Error` then the iteration is
 stopped and the error is returned.

 Useful for calling a side effect for every item of a list.

 ## Examples

 ```gleam
 assert list.try_each(over: [1, 2, 3], with: function_that_might_fail)
   == Ok(Nil)
 ```
").
try_each(List, Fun) ->
    case List of
        [] ->
            {ok, nil};

        [First | Rest] ->
            case Fun(First) of
                {ok, _} ->
                    try_each(Rest, Fun);

                {error, E} ->
                    {error, E}
            end
    end.

-file("src/gleam/list.gleam", 1694).
-spec partition_loop(list(BGI), fun((BGI) -> boolean()), list(BGI), list(BGI)) -> {list(BGI), list(BGI)}.
partition_loop(List, Categorise, Trues, Falses) ->
    case List of
        [] ->
            {lists:reverse(Trues), lists:reverse(Falses)};

        [First | Rest] ->
            case Categorise(First) of
                true ->
                    partition_loop(Rest, Categorise, [First | Trues], Falses);

                false ->
                    partition_loop(Rest, Categorise, Trues, [First | Falses])
            end
    end.

-file("src/gleam/list.gleam", 1687).
-spec partition(list(ANS), fun((ANS) -> boolean())) -> {list(ANS), list(ANS)}.
-doc(~" Partitions a list into a tuple/pair of lists
 by a given categorisation function.

 ## Examples

 ```gleam
 import gleam/int

 assert [1, 2, 3, 4, 5] |> list.partition(int.is_odd) == #([1, 3, 5], [2, 4])
 ```
").
partition(List, Categorise) ->
    partition_loop(List, Categorise, [], []).

-file("src/gleam/list.gleam", 1738).
-spec permutation_prepend(AOM, list(list(AOM)), list(AOM), list(AOM), list(list(AOM))) -> list(list(AOM)).
permutation_prepend(El, Permutations, List_1, List_2, Acc) ->
    case Permutations of
        [] ->
            permutation_zip(List_1, List_2, Acc);

        [Head | Tail] ->
            permutation_prepend(El, Tail, List_1, List_2, [[El | Head] | Acc])
    end.

-file("src/gleam/list.gleam", 1720).
-spec permutation_zip(list(AOF), list(AOF), list(list(AOF))) -> list(list(AOF)).
permutation_zip(List, Rest, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [Head | Tail] ->
            permutation_prepend(Head, permutations(lists:reverse(Rest, Tail)), Tail, [Head | Rest], Acc)
    end.

-file("src/gleam/list.gleam", 1713).
-spec permutations(list(AOB)) -> list(list(AOB)).
-doc(~" Returns all the permutations of a list.

 ## Examples

 ```gleam
 assert list.permutations([1, 2]) == [[1, 2], [2, 1]]
 ```
").
permutations(List) ->
    case List of
        [] ->
            [[]];

        L ->
            permutation_zip(L, [], [])
    end.

-file("src/gleam/list.gleam", 1771).
-spec window_loop(list(list(AOZ)), list(AOZ), integer()) -> list(list(AOZ)).
window_loop(Acc, List, N) ->
    Window = take(List, N),
    case erlang:length(Window) =:= N of
        true ->
            window_loop([Window | Acc], drop(List, 1), N);

        false ->
            lists:reverse(Acc)
    end.

-file("src/gleam/list.gleam", 1764).
-spec window(list(AOV), integer()) -> list(list(AOV)).
-doc(~" Returns a list of sliding windows.

 ## Examples

 ```gleam
 assert list.window([1, 2, 3, 4, 5], 3) == [[1, 2, 3], [2, 3, 4], [3, 4, 5]]
 ```

 ```gleam
 assert list.window([1, 2], 4) == []
 ```
").
window(List, N) ->
    case N =< 0 of
        true ->
            [];

        false ->
            window_loop([], List, N)
    end.

-file("src/gleam/list.gleam", 1792).
-spec window_by_2(list(APF)) -> list({APF, APF}).
-doc(~" Returns a list of tuples containing two contiguous elements.

 ## Examples

 ```gleam
 assert list.window_by_2([1, 2, 3, 4]) == [#(1, 2), #(2, 3), #(3, 4)]
 ```

 ```gleam
 assert list.window_by_2([1]) == []
 ```
").
window_by_2(List) ->
    zip(List, drop(List, 1)).

-file("src/gleam/list.gleam", 1804).
-spec drop_while(list(API), fun((API) -> boolean())) -> list(API).
-doc(~" Drops the first elements in a given list for which the predicate function returns `True`.

 ## Examples

 ```gleam
 assert list.drop_while([1, 2, 3, 4], fn(x) { x < 3 }) == [3, 4]
 ```
").
drop_while(List, Predicate) ->
    case List of
        [] ->
            [];

        [First | Rest] ->
            case Predicate(First) of
                true ->
                    drop_while(Rest, Predicate);

                false ->
                    [First | Rest]
            end
    end.

-file("src/gleam/list.gleam", 1833).
-spec take_while_loop(list(APO), fun((APO) -> boolean()), list(APO)) -> list(APO).
take_while_loop(List, Predicate, Acc) ->
    case List of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            case Predicate(First) of
                true ->
                    take_while_loop(Rest, Predicate, [First | Acc]);

                false ->
                    lists:reverse(Acc)
            end
    end.

-file("src/gleam/list.gleam", 1826).
-spec take_while(list(APL), fun((APL) -> boolean())) -> list(APL).
-doc(~" Takes the first elements in a given list for which the predicate function returns `True`.

 ## Examples

 ```gleam
 assert list.take_while([1, 2, 3, 2, 4], fn(x) { x < 3 }) == [1, 2]
 ```
").
take_while(List, Predicate) ->
    take_while_loop(List, Predicate, []).

-file("src/gleam/list.gleam", 1865).
-spec chunk_loop(list(APX), fun((APX) -> APZ), APZ, list(APX), list(list(APX))) -> list(list(APX)).
chunk_loop(List, F, Previous_key, Current_chunk, Acc) ->
    case List of
        [First | Rest] ->
            Key = F(First),
            case Key =:= Previous_key of
                true ->
                    chunk_loop(Rest, F, Key, [First | Current_chunk], Acc);

                false ->
                    New_acc = [lists:reverse(Current_chunk) | Acc],
                    chunk_loop(Rest, F, Key, [First], New_acc)
            end;

        [] ->
            lists:reverse([lists:reverse(Current_chunk) | Acc])
    end.

-file("src/gleam/list.gleam", 1858).
-spec chunk(list(APS), fun((APS) -> any())) -> list(list(APS)).
-doc(~" Returns a list of chunks in which
 the return value of calling `f` on each element is the same.

 ## Examples

 ```gleam
 assert [1, 2, 2, 3, 4, 4, 6, 7, 7] |> list.chunk(by: fn(n) { n % 2 })
   == [[1], [2, 2], [3], [4, 4, 6], [7, 7]]
 ```
").
chunk(List, F) ->
    case List of
        [] ->
            [];

        [First | Rest] ->
            chunk_loop(Rest, F, F(First), [First], [])
    end.

-file("src/gleam/list.gleam", 1910).
-spec sized_chunk_loop(list(AQJ), integer(), integer(), list(AQJ), list(list(AQJ))) -> list(list(AQJ)).
sized_chunk_loop(List, Count, Left, Current_chunk, Acc) ->
    case List of
        [] ->
            case Current_chunk of
                [] ->
                    lists:reverse(Acc);

                Remaining ->
                    lists:reverse([lists:reverse(Remaining) | Acc])
            end;

        [First | Rest] ->
            Chunk = [First | Current_chunk],
            case Left > 1 of
                true ->
                    sized_chunk_loop(Rest, Count, Left - 1, Chunk, Acc);

                false ->
                    sized_chunk_loop(Rest, Count, Count, [], [lists:reverse(Chunk) | Acc])
            end
    end.

-file("src/gleam/list.gleam", 1906).
-spec sized_chunk(list(AQF), integer()) -> list(list(AQF)).
-doc(~" Returns a list of chunks containing `count` elements each.

 If the last chunk does not have `count` elements, it is instead
 a partial chunk, with less than `count` elements.

 For any `count` less than 1 this function behaves as if it was set to 1.

 ## Examples

 ```gleam
 assert [1, 2, 3, 4, 5, 6] |> list.sized_chunk(into: 2)
   == [[1, 2], [3, 4], [5, 6]]
 ```

 ```gleam
 assert [1, 2, 3, 4, 5, 6, 7, 8] |> list.sized_chunk(into: 3)
   == [[1, 2, 3], [4, 5, 6], [7, 8]]
 ```
").
sized_chunk(List, Count) ->
    sized_chunk_loop(List, Count, Count, [], []).

-file("src/gleam/list.gleam", 1952).
-spec reduce(list(AQQ), fun((AQQ, AQQ) -> AQQ)) -> {ok, AQQ} | {error, nil}.
-doc(~" This function acts similar to fold, but does not take an initial state.
 Instead, it starts from the first element in the list
 and combines it with each subsequent element in turn using the given
 function. The function is called as `fun(accumulator, current_element)`.

 Returns `Ok` to indicate a successful run, and `Error` if called on an
 empty list.

 ## Examples

 ```gleam
 assert [] |> list.reduce(fn(acc, x) { acc + x }) == Error(Nil)
 ```

 ```gleam
 assert [1, 2, 3, 4, 5] |> list.reduce(fn(acc, x) { acc + x }) == Ok(15)
 ```
").
reduce(List, Fun) ->
    case List of
        [] ->
            {error, nil};

        [First | Rest] ->
            {ok, fold(Rest, First, Fun)}
    end.

-file("src/gleam/list.gleam", 1976).
-spec scan_loop(list(AQY), ARA, list(ARA), fun((ARA, AQY) -> ARA)) -> list(ARA).
scan_loop(List, Accumulator, Accumulated, Fun) ->
    case List of
        [] ->
            lists:reverse(Accumulated);

        [First | Rest] ->
            Next = Fun(Accumulator, First),
            scan_loop(Rest, Next, [Next | Accumulated], Fun)
    end.

-file("src/gleam/list.gleam", 1968).
-spec scan(list(AQU), AQW, fun((AQW, AQU) -> AQW)) -> list(AQW).
-doc(~" Similar to `fold`, but yields the state of the accumulator at each stage.

 ## Examples

 ```gleam
 assert list.scan(over: [1, 2, 3], from: 100, with: fn(acc, i) { acc + i })
   == [101, 103, 106]
 ```
").
scan(List, Initial, Fun) ->
    scan_loop(List, Initial, [], Fun).

-file("src/gleam/list.gleam", 2007).
-spec last(list(ARD)) -> {ok, ARD} | {error, nil}.
-doc(~" Returns the last element in the given list.

 Returns `Error(Nil)` if the list is empty.

 This function runs in linear time.

 ## Examples

 ```gleam
 assert list.last([]) == Error(Nil)
 ```

 ```gleam
 assert list.last([1, 2, 3, 4, 5]) == Ok(5)
 ```
").
last(List) ->
    case List of
        [] ->
            {error, nil};

        [Last] ->
            {ok, Last};

        [_ | Rest] ->
            last(Rest)
    end.

-file("src/gleam/list.gleam", 2028).
-spec combinations(list(ARH), integer()) -> list(list(ARH)).
-doc(~" Return unique combinations of elements in the list.

 ## Examples

 ```gleam
 assert list.combinations([1, 2, 3], 2) == [[1, 2], [1, 3], [2, 3]]
 ```

 ```gleam
 assert list.combinations([1, 2, 3, 4], 3)
   == [[1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4]]
 ```
").
combinations(Items, N) ->
    case {N, Items} of
        {0, _} ->
            [[]];

        {_, []} ->
            [];

        {_, [First | Rest]} ->
            _pipe = Rest,
            _pipe@1 = combinations(_pipe, N - 1),
            _pipe@2 = map(_pipe@1, fun(Combination) ->
                [First | Combination]
            end),
            _pipe@3 = lists:reverse(_pipe@2),
            fold(_pipe@3, combinations(Rest, N), fun(Acc, C) ->
                [C | Acc]
            end)
    end.

-file("src/gleam/list.gleam", 2053).
-spec combination_pairs_loop(list(ARO), list({ARO, ARO})) -> list({ARO, ARO}).
combination_pairs_loop(Items, Acc) ->
    case Items of
        [] ->
            lists:reverse(Acc);

        [First | Rest] ->
            First_combinations = map(Rest, fun(Other) ->
                {First, Other}
            end),
            Acc@1 = lists:reverse(First_combinations, Acc),
            combination_pairs_loop(Rest, Acc@1)
    end.

-file("src/gleam/list.gleam", 2049).
-spec combination_pairs(list(ARL)) -> list({ARL, ARL}).
-doc(~" Return unique pair combinations of elements in the list.

 ## Examples

 ```gleam
 assert list.combination_pairs([1, 2, 3]) == [#(1, 2), #(1, 3), #(2, 3)]
 ```
").
combination_pairs(Items) ->
    combination_pairs_loop(Items, []).

-file("src/gleam/list.gleam", 2112).
-spec take_firsts(list(list(ASI)), list(ASI), list(list(ASI))) -> {list(ASI), list(list(ASI))}.
take_firsts(Rows, Column, Remaining_rows) ->
    case Rows of
        [] ->
            {lists:reverse(Column), lists:reverse(Remaining_rows)};

        [[] | Rest] ->
            take_firsts(Rest, Column, Remaining_rows);

        [[First | Remaining_row] | Rest_rows] ->
            Remaining_rows@1 = [Remaining_row | Remaining_rows],
            take_firsts(Rest_rows, [First | Column], Remaining_rows@1)
    end.

-file("src/gleam/list.gleam", 2096).
-spec transpose_loop(list(list(ASB)), list(list(ASB))) -> list(list(ASB)).
transpose_loop(Rows, Columns) ->
    case Rows of
        [] ->
            lists:reverse(Columns);

        _ ->
            {Column, Rest} = take_firsts(Rows, [], []),
            case Column of
                [_ | _] ->
                    transpose_loop(Rest, [Column | Columns]);

                [] ->
                    transpose_loop(Rest, Columns)
            end
    end.

-file("src/gleam/list.gleam", 2092).
-spec transpose(list(list(ARW))) -> list(list(ARW)).
-doc(~" Transpose rows and columns of the list of lists.

 Notice: This function is not tail recursive,
 and thus may exceed stack size if called,
 with large lists (on the JavaScript target).

 ## Examples

 ```gleam
 assert list.transpose([[1, 2, 3], [101, 102, 103]])
   == [[1, 101], [2, 102], [3, 103]]
 ```
").
transpose(List_of_lists) ->
    transpose_loop(List_of_lists, []).

-file("src/gleam/list.gleam", 2073).
-spec interleave(list(list(ARS))) -> list(ARS).
-doc(~" Make a list alternating the elements from the given lists

 ## Examples

 ```gleam
 assert list.interleave([[1, 2], [101, 102], [201, 202]])
   == [1, 101, 201, 2, 102, 202]
 ```
").
interleave(List) ->
    _pipe = List,
    _pipe@1 = transpose(_pipe),
    lists:append(_pipe@1).

-file("src/gleam/list.gleam", 2145).
-spec shuffle_pair_unwrap_loop(list({float(), ASU}), list(ASU)) -> list(ASU).
shuffle_pair_unwrap_loop(List, Acc) ->
    case List of
        [] ->
            Acc;

        [Elem_pair | Enumerable] ->
            shuffle_pair_unwrap_loop(Enumerable, [erlang:element(2, Elem_pair) | Acc])
    end.

-file("src/gleam/list.gleam", 2153).
-spec do_shuffle_by_pair_indexes(list({float(), ASY})) -> list({float(), ASY}).
do_shuffle_by_pair_indexes(List_of_pairs) ->
    sort(List_of_pairs, fun(A_pair, B_pair) ->
        gleam@float:compare(erlang:element(1, A_pair), erlang:element(1, B_pair))
    end).

-file("src/gleam/list.gleam", 2138).
-spec shuffle(list(ASR)) -> list(ASR).
-doc(~" Takes a list, randomly sorts all items and returns the shuffled list.

 This function uses `float.random` to decide the order of the elements.

 ## Example

 ```gleam
 [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] |> list.shuffle
 // -> [1, 6, 9, 10, 3, 8, 4, 2, 7, 5]
 ```
").
shuffle(List) ->
    _pipe = List,
    _pipe@1 = fold(_pipe, [], fun(Acc, A) ->
        [{rand:uniform(), A} | Acc]
    end),
    _pipe@2 = do_shuffle_by_pair_indexes(_pipe@1),
    shuffle_pair_unwrap_loop(_pipe@2, []).

-file("src/gleam/list.gleam", 2183).
-spec max_loop(list(ATI), fun((ATI, ATI) -> gleam@order:order()), ATI) -> ATI.
max_loop(List, Compare, Max) ->
    case List of
        [] ->
            Max;

        [First | Rest] ->
            case Compare(First, Max) of
                gt ->
                    max_loop(Rest, Compare, First);

                lt ->
                    max_loop(Rest, Compare, Max);

                eq ->
                    max_loop(Rest, Compare, Max)
            end
    end.

-file("src/gleam/list.gleam", 2173).
-spec max(list(ATB), fun((ATB, ATB) -> gleam@order:order())) -> {ok, ATB} | {error, nil}.
-doc(~" Takes a list and a comparator, and returns the maximum element in the list

 ## Examples

 ```gleam
 assert [1, 2, 3, 4, 5] |> list.max(int.compare) == Ok(5)
 ```

 ```gleam
 assert [\"a\", \"c\", \"b\"] |> list.max(string.compare) == Ok(\"c\")
 ```
").
max(List, Compare) ->
    case List of
        [] ->
            {error, nil};

        [First | Rest] ->
            {ok, max_loop(Rest, Compare, First)}
    end.

-file("src/gleam/list.gleam", 2248).
-spec log_random() -> float().
log_random() ->
    case gleam@float:logarithm(rand:uniform() + 0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022250738585072014) of
        {ok, Random} ->
            Random;

        _value ->
            erlang:error(#{
                gleam_error => let_assert,
                message => ~"Pattern match failed, no pattern matched the value.",
                file => ~"src/gleam/list.gleam",
                module => ~"gleam/list",
                function => ~"log_random",
                line => 2249,
                value => _value,
                start => 55759,
                'end' => 55830,
                pattern_start => 55770,
                pattern_end => 55780
            })
    end.

-file("src/gleam/list.gleam", 2225).
-spec sample_loop(list(ATM), gleam@dict:dict(integer(), ATM), integer(), float()) -> gleam@dict:dict(integer(), ATM).
sample_loop(List, Reservoir, N, W) ->
    Skip = begin
        case gleam@float:logarithm(1.0 - W) of
            {ok, Log} ->
                erlang:round(math:floor(begin
                    _value = log_random(),
                    case Log of
                        +0.0 ->
                            +0.0;

                        -0.0 ->
                            -0.0;

                        _value@1 ->
                            _value / _value@1
                    end
                end));

            _value@2 ->
                erlang:error(#{
                    gleam_error => let_assert,
                    message => ~"Pattern match failed, no pattern matched the value.",
                    file => ~"src/gleam/list.gleam",
                    module => ~"gleam/list",
                    function => ~"sample_loop",
                    line => 2232,
                    value => _value@2,
                    start => 55320,
                    'end' => 55366,
                    pattern_start => 55331,
                    pattern_end => 55338
                })
        end
    end,
    case drop(List, Skip) of
        [] ->
            Reservoir;

        [First | Rest] ->
            Reservoir@1 = gleam@dict:insert(Reservoir, gleam@int:random(N), First),
            W@1 = W * math:exp(begin
                _value@3 = log_random(),
                case erlang:float(N) of
                    +0.0 ->
                        +0.0;

                    -0.0 ->
                        -0.0;

                    _value@4 ->
                        _value@3 / _value@4
                end
            end),
            sample_loop(Rest, Reservoir@1, N, W@1)
    end.

-file("src/gleam/list.gleam", 2267).
-spec build_reservoir_loop(list(ATX), integer(), gleam@dict:dict(integer(), ATX)) -> {gleam@dict:dict(integer(), ATX), list(ATX)}.
build_reservoir_loop(List, Size, Reservoir) ->
    Reservoir_size = maps:size(Reservoir),
    case Reservoir_size >= Size of
        true ->
            {Reservoir, List};

        false ->
            case List of
                [] ->
                    {Reservoir, []};

                [First | Rest] ->
                    Reservoir@1 = gleam@dict:insert(Reservoir, Reservoir_size, First),
                    build_reservoir_loop(Rest, Size, Reservoir@1)
            end
    end.

-file("src/gleam/list.gleam", 2260).
-spec build_reservoir(list(ATS), integer()) -> {gleam@dict:dict(integer(), ATS), list(ATS)}.
-doc(~" Builds the initial reservoir used by Algorithm L.
 This is a dictionary with keys ranging from `0` up to `n - 1` where each
 value is the corresponding element at that position in `list`.

 This also returns the remaining elements of `list` that didn't end up in
 the reservoir.
").
build_reservoir(List, N) ->
    build_reservoir_loop(List, N, maps:new()).

-file("src/gleam/list.gleam", 2207).
-spec sample(list(ATJ), integer()) -> list(ATJ).
-doc(~" Returns a random sample of up to n elements from a list using reservoir
 sampling via [Algorithm L](https://en.wikipedia.org/wiki/Reservoir_sampling#Optimal:_Algorithm_L).
 Returns an empty list if the sample size is less than or equal to 0.

 Order is not random, only selection is.

 ## Examples

 ```gleam
 list.sample([1, 2, 3, 4, 5], 3)
 // -> [2, 4, 5]  // A random sample of 3 items
 ```
").
sample(List, N) ->
    {Reservoir, Rest} = build_reservoir(List, N),
    case gleam@dict:is_empty(Reservoir) of
        true ->
            [];

        false ->
            W = math:exp(begin
                _value = log_random(),
                case erlang:float(N) of
                    +0.0 ->
                        +0.0;

                    -0.0 ->
                        -0.0;

                    _value@1 ->
                        _value / _value@1
                end
            end),
            maps:values(sample_loop(Rest, Reservoir, N, W))
    end.

