-module(gleam@dict).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([size/1, is_empty/1, fold/3, to_list/1, new/0, from_list/1, has_key/2, get/2, insert/3, map_values/2, keys/1, values/1, filter/2, take/2, combine/3, merge/2, delete/2, drop/2, upsert/3, each/2, group/2]).
-export_type([dict/2, transient_dict/2]).

-type dict(JL, JM) :: any() | {gleam_phantom, JL, JM}.

-type transient_dict(JN, JO) :: any() | {gleam_phantom, JN, JO}.

-file("src/gleam/dict.gleam", 53).
-spec size(dict(any(), any())) -> integer().
-doc(~" Determines the number of key-value pairs in the dict.
 This function runs in constant time and does not need to iterate the dict.

 ## Examples

 ```gleam
 assert dict.new() |> dict.size == 0
 ```

 ```gleam
 assert dict.new() |> dict.insert(\"key\", \"value\") |> dict.size == 1
 ```
").
size(Dict) ->
    maps:size(Dict).

-file("src/gleam/dict.gleam", 67).
-spec is_empty(dict(any(), any())) -> boolean().
-doc(~" Determines whether or not the dict is empty.

 ## Examples

 ```gleam
 assert dict.new() |> dict.is_empty
 ```

 ```gleam
 assert !{ dict.new() |> dict.insert(\"b\", 1) |> dict.is_empty }
 ```
").
is_empty(Dict) ->
    maps:size(Dict) =:= 0.

-file("src/gleam/dict.gleam", 483).
-spec fold(dict(QN, QO), QR, fun((QR, QN, QO) -> QR)) -> QR.
-doc(~" Combines all entries into a single value by calling a given function on each
 one.

 Dicts are not ordered so the values are not returned in any specific order. Do
 not write code that relies on the order entries are used by this function
 as it may change in later versions of Gleam or Erlang.

 ## Examples

 ```gleam
 let dict = dict.from_list([#(\"a\", 1), #(\"b\", 3), #(\"c\", 9)])
 assert dict.fold(dict, 0, fn(accumulator, key, value) { accumulator + value })
   == 13
 ```

 ```gleam
 import gleam/string

 let dict = dict.from_list([#(\"a\", 1), #(\"b\", 3), #(\"c\", 9)])
 assert dict.fold(dict, \"\", fn(accumulator, key, value) {
     string.append(accumulator, key)
   })
   == \"abc\"
 ```
").
fold(Dict, Initial, Fun) ->
    Fun@1 = fun(Key, Value, Acc) ->
        Fun(Acc, Key, Value)
    end,
    maps:fold(Fun@1, Initial, Dict).

-file("src/gleam/dict.gleam", 97).
-spec to_list(dict(KJ, KK)) -> list({KJ, KK}).
-doc(~" Converts the dict to a list of 2-element tuples `#(key, value)`, one for
 each key-value pair in the dict.

 The tuples in the list have no specific order.

 ## Examples

 Calling `to_list` on an empty `dict` returns an empty list.

 ```gleam
 assert dict.new() |> dict.to_list == []
 ```

 The ordering of elements in the resulting list is an implementation detail
 that should not be relied upon.

 ```gleam
 assert dict.new()
   |> dict.insert(\"b\", 1)
   |> dict.insert(\"a\", 0)
   |> dict.insert(\"c\", 2)
   |> dict.to_list
   == [#(\"a\", 0), #(\"b\", 1), #(\"c\", 2)]
 ```
").
to_list(Dict) ->
    maps:to_list(Dict).

-file("src/gleam/dict.gleam", 146).
-spec new() -> dict(any(), any()).
-doc(~" Creates a fresh dict that contains no values.
").
new() ->
    maps:new().

-file("src/gleam/dict.gleam", 111).
-spec from_list_loop(transient_dict(KT, KU), list({KT, KU})) -> dict(KT, KU).
from_list_loop(Transient, List) ->
    case List of
        [] ->
            gleam_stdlib:identity(Transient);

        [{Key, Value} | Rest] ->
            from_list_loop(maps:put(Key, Value, Transient), Rest)
    end.

-file("src/gleam/dict.gleam", 107).
-spec from_list(list({KO, KP})) -> dict(KO, KP).
-doc(~" Converts a list of 2-element tuples `#(key, value)` to a dict.

 If two tuples have the same key the last one in the list will be the one
 that is present in the dict.
").
from_list(List) ->
    maps:from_list(List).

-file("src/gleam/dict.gleam", 135).
-spec has_key(dict(LA, any()), LA) -> boolean().
-doc(~" Determines whether or not a value is present in the dict for a given key.

 ## Examples

 ```gleam
 assert dict.new() |> dict.insert(\"a\", 0) |> dict.has_key(\"a\")
 ```

 ```gleam
 assert !{ dict.new() |> dict.insert(\"a\", 0) |> dict.has_key(\"b\") }
 ```
").
has_key(Dict, Key) ->
    maps:is_key(Key, Dict).

-file("src/gleam/dict.gleam", 165).
-spec get(dict(LM, LN), LM) -> {ok, LN} | {error, nil}.
-doc(~" Fetches a value from a dict for a given key.

 The dict may not have a value for the key, so the value is wrapped in a
 `Result`.

 ## Examples

 ```gleam
 assert dict.new() |> dict.insert(\"a\", 0) |> dict.get(\"a\") == Ok(0)
 ```

 ```gleam
 assert dict.new() |> dict.insert(\"a\", 0) |> dict.get(\"b\") == Error(Nil)
 ```
").
get(From, Get) ->
    gleam_stdlib:map_get(From, Get).

-file("src/gleam/dict.gleam", 184).
-spec insert(dict(LS, LT), LS, LT) -> dict(LS, LT).
-doc(~" Inserts a value into the dict with the given key.

 If the dict already has a value for the given key then the value is
 replaced with the new value.

 ## Examples

 ```gleam
 assert dict.new() |> dict.insert(\"a\", 0) == dict.from_list([#(\"a\", 0)])
 ```

 ```gleam
 assert dict.new() |> dict.insert(\"a\", 0) |> dict.insert(\"a\", 5)
   == dict.from_list([#(\"a\", 5)])
 ```
").
insert(Dict, Key, Value) ->
    maps:put(Key, Value, Dict).

-file("src/gleam/dict.gleam", 215).
-spec map_values(dict(MK, ML), fun((MK, ML) -> MO)) -> dict(MK, MO).
-doc(~" Updates all values in a given dict by calling a given function on each key
 and value.

 ## Examples

 ```gleam
 assert dict.from_list([#(3, 3), #(2, 4)])
   |> dict.map_values(fn(key, value) { key * value })
   == dict.from_list([#(3, 9), #(2, 8)])
 ```
").
map_values(Dict, Fun) ->
    maps:map(Fun, Dict).

-file("src/gleam/dict.gleam", 235).
-spec keys(dict(MY, any())) -> list(MY).
-doc(~" Gets a list of all keys in a given dict.

 Dicts are not ordered so the keys are not returned in any specific order. Do
 not write code that relies on the order keys are returned by this function
 as it may change in later versions of Gleam or Erlang.

 ## Examples

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.keys == [\"a\", \"b\"]
 ```
").
keys(Dict) ->
    maps:keys(Dict).

-file("src/gleam/dict.gleam", 252).
-spec values(dict(any(), NE)) -> list(NE).
-doc(~" Gets a list of all values in a given dict.

 Dicts are not ordered so the values are not returned in any specific order. Do
 not write code that relies on the order values are returned by this function
 as it may change in later versions of Gleam or Erlang.

 ## Examples

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.values == [0, 1]
 ```
").
values(Dict) ->
    maps:values(Dict).

-file("src/gleam/dict.gleam", 273).
-spec filter(dict(NI, NJ), fun((NI, NJ) -> boolean())) -> dict(NI, NJ).
-doc(~" Creates a new dict from a given dict, minus any entries that a given function
 returns `False` for.

 ## Examples

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)])
   |> dict.filter(fn(key, value) { value != 0 })
   == dict.from_list([#(\"b\", 1)])
 ```

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)])
   |> dict.filter(fn(key, value) { True })
   == dict.from_list([#(\"a\", 0), #(\"b\", 1)])
 ```
").
filter(Dict, Predicate) ->
    maps:filter(Predicate, Dict).

-file("src/gleam/dict.gleam", 321).
-spec do_take_loop(dict(OI, OJ), list(OI), transient_dict(OI, OJ)) -> dict(OI, OJ).
do_take_loop(Dict, Desired_keys, Acc) ->
    case Desired_keys of
        [] ->
            gleam_stdlib:identity(Acc);

        [Key | Rest] ->
            case gleam_stdlib:map_get(Dict, Key) of
                {ok, Value} ->
                    do_take_loop(Dict, Rest, maps:put(Key, Value, Acc));

                {error, _} ->
                    do_take_loop(Dict, Rest, Acc)
            end
    end.

-file("src/gleam/dict.gleam", 309).
-spec take(dict(NU, NV), list(NU)) -> dict(NU, NV).
-doc(~" Creates a new dict from a given dict, only including any entries for which the
 keys are in a given list.

 ## Examples

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)])
   |> dict.take([\"b\"])
   == dict.from_list([#(\"b\", 1)])
 ```

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)])
   |> dict.take([\"a\", \"b\", \"c\"])
   == dict.from_list([#(\"a\", 0), #(\"b\", 1)])
 ```
").
take(Dict, Desired_keys) ->
    maps:with(Desired_keys, Dict).

-file("src/gleam/dict.gleam", 536).
-spec combine(dict(RC, RD), dict(RC, RD), fun((RD, RD) -> RD)) -> dict(RC, RD).
-doc(~" Creates a new dict from a pair of given dicts by combining their entries.

 If there are entries with the same keys in both dicts the given function is
 used to determine the new value to use in the resulting dict.

 ## Examples

 ```gleam
 let a = dict.from_list([#(\"a\", 0), #(\"b\", 1)])
 let b = dict.from_list([#(\"a\", 2), #(\"c\", 3)])
 assert dict.combine(a, b, fn(one, other) { one + other })
   == dict.from_list([#(\"a\", 2), #(\"b\", 1), #(\"c\", 3)])
 ```
").
combine(Dict, Other, Fun) ->
    maps:merge_with(fun(_, L, R) ->
        Fun(L, R)
    end, Dict, Other).

-file("src/gleam/dict.gleam", 350).
-spec merge(dict(OR, OS), dict(OR, OS)) -> dict(OR, OS).
-doc(~" Creates a new dict from a pair of given dicts by combining their entries.

 If there are entries with the same keys in both dicts the entry from the
 second dict takes precedence.

 ## Examples

 ```gleam
 let a = dict.from_list([#(\"a\", 0), #(\"b\", 1)])
 let b = dict.from_list([#(\"b\", 2), #(\"c\", 3)])
 assert dict.merge(a, b) == dict.from_list([#(\"a\", 0), #(\"b\", 2), #(\"c\", 3)])
 ```
").
merge(Dict, New_entries) ->
    maps:merge(Dict, New_entries).

-file("src/gleam/dict.gleam", 372).
-spec delete(dict(OZ, PA), OZ) -> dict(OZ, PA).
-doc(~" Creates a new dict from a given dict with all the same entries except for the
 one with a given key, if it exists.

 ## Examples

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.delete(\"a\")
   == dict.from_list([#(\"b\", 1)])
 ```

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.delete(\"c\")
   == dict.from_list([#(\"a\", 0), #(\"b\", 1)])
 ```
").
delete(Dict, Key) ->
    _pipe = gleam_stdlib:identity(Dict),
    _pipe@1 = fun(_capture) ->
        maps:remove(Key, _capture)
    end(_pipe),
    gleam_stdlib:identity(_pipe@1).

-file("src/gleam/dict.gleam", 412).
-spec drop_loop(transient_dict(PZ, QA), list(PZ)) -> dict(PZ, QA).
drop_loop(Transient, Disallowed_keys) ->
    case Disallowed_keys of
        [] ->
            gleam_stdlib:identity(Transient);

        [Key | Rest] ->
            drop_loop(maps:remove(Key, Transient), Rest)
    end.

-file("src/gleam/dict.gleam", 400).
-spec drop(dict(PL, PM), list(PL)) -> dict(PL, PM).
-doc(~" Creates a new dict from a given dict with all the same entries except any with
 keys found in a given list.

 ## Examples

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.drop([\"a\"])
   == dict.from_list([#(\"b\", 1)])
 ```

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.drop([\"c\"])
   == dict.from_list([#(\"a\", 0), #(\"b\", 1)])
 ```

 ```gleam
 assert dict.from_list([#(\"a\", 0), #(\"b\", 1)]) |> dict.drop([\"a\", \"b\", \"c\"])
   == dict.from_list([])
 ```
").
drop(Dict, Disallowed_keys) ->
    maps:without(Disallowed_keys, Dict).

-file("src/gleam/dict.gleam", 446).
-spec upsert(dict(QG, QH), QG, fun((gleam@option:option(QH)) -> QH)) -> dict(QG, QH).
-doc(~" Creates a new dict with one entry inserted or updated using a given function.

 If there was not an entry in the dict for the given key then the function
 gets `None` as its argument, otherwise it gets `Some(value)`.

 ## Examples

 ```gleam
 let dict = dict.from_list([#(\"a\", 0)])
 let increment = fn(x) {
   case x {
     Some(i) -> i + 1
     None -> 0
   }
 }

 assert dict.upsert(dict, \"a\", increment) == dict.from_list([#(\"a\", 1)])
 ```

 ```gleam
 assert dict.upsert(dict, \"b\", increment)
   == dict.from_list([#(\"a\", 0), #(\"b\", 0)])
 ```
").
upsert(Dict, Key, Fun) ->
    case gleam_stdlib:map_get(Dict, Key) of
        {ok, Value} ->
            insert(Dict, Key, Fun({some, Value}));

        {error, _} ->
            insert(Dict, Key, Fun(none))
    end.

-file("src/gleam/dict.gleam", 515).
-spec each(dict(QX, QY), fun((QX, QY) -> any())) -> nil.
-doc(~" Calls a function for each key and value in a dict, discarding the return
 value.

 Useful for producing a side effect for every item of a dict.

 ```gleam
 import gleam/io

 let dict =
   dict.from_list([#(\"a\", \"apple\"), #(\"b\", \"banana\"), #(\"c\", \"cherry\")])

 assert dict.each(dict, fn(k, v) { io.println(k <> \" => \" <> v) }) == Nil
 // a => apple
 // b => banana
 // c => cherry
 ```

 The order of elements in the iteration is an implementation detail that
 should not be relied upon.
").
each(Dict, Fun) ->
    fold(Dict, nil, fun(Nil, K, V) ->
        Fun(K, V),
        Nil
    end).

-file("src/gleam/dict.gleam", 577).
-spec group_loop(transient_dict(SE, list(SF)), fun((SF) -> SE), list(SF)) -> dict(SE, list(SF)).
group_loop(Transient, To_key, List) ->
    case List of
        [] ->
            gleam_stdlib:identity(Transient);

        [Value | Rest] ->
            Key = To_key(Value),
            Update = fun(Existing) ->
                [Value | Existing]
            end,
            _pipe = Transient,
            _pipe@1 = fun(_capture) ->
                maps:update_with(Key, Update, [Value], _capture)
            end(_pipe),
            group_loop(_pipe@1, To_key, Rest)
    end.

-file("src/gleam/dict.gleam", 573).
-spec group(fun((RY) -> RZ), list(RY)) -> dict(RZ, list(RY)).
-doc(false).
group(Key, List) ->
    group_loop(gleam_stdlib:identity(maps:new()), Key, List).

