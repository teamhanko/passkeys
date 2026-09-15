-module(gleam@dynamic).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([classify/1, bool/1, string/1, float/1, int/1, bit_array/1, list/1, array/1, properties/1, nil/0]).
-export_type([dynamic_/0]).

-type dynamic_() :: any().

-file("src/gleam/dynamic.gleam", 29).
-spec classify(dynamic_()) -> binary().
-doc(~" Return a string indicating the type of the dynamic value.

 This function may be useful for constructing error messages or logs. If you
 want to turn dynamic data into well typed data then you want the
 `gleam/dynamic/decode` module.

 ```gleam
 assert dynamic.classify(dynamic.string(\"Hello\")) == \"String\"
 ```
").
classify(Data) ->
    gleam_stdlib:classify_dynamic(Data).

-file("src/gleam/dynamic.gleam", 35).
-spec bool(boolean()) -> dynamic_().
-doc(~" Create a dynamic value from a bool.
").
bool(A) ->
    gleam_stdlib:identity(A).

-file("src/gleam/dynamic.gleam", 43).
-spec string(binary()) -> dynamic_().
-doc(~" Create a dynamic value from a string.

 On Erlang this will be a binary string rather than a character list.
").
string(A) ->
    gleam_stdlib:identity(A).

-file("src/gleam/dynamic.gleam", 49).
-spec float(float()) -> dynamic_().
-doc(~" Create a dynamic value from a float.
").
float(A) ->
    gleam_stdlib:identity(A).

-file("src/gleam/dynamic.gleam", 55).
-spec int(integer()) -> dynamic_().
-doc(~" Create a dynamic value from an int.
").
int(A) ->
    gleam_stdlib:identity(A).

-file("src/gleam/dynamic.gleam", 61).
-spec bit_array(bitstring()) -> dynamic_().
-doc(~" Create a dynamic value from a bit array.
").
bit_array(A) ->
    gleam_stdlib:identity(A).

-file("src/gleam/dynamic.gleam", 67).
-spec list(list(dynamic_())) -> dynamic_().
-doc(~" Create a dynamic value from a list.
").
list(A) ->
    gleam_stdlib:identity(A).

-file("src/gleam/dynamic.gleam", 76).
-spec array(list(dynamic_())) -> dynamic_().
-doc(~" Create a dynamic value from a list, converting it to a sequential runtime
 format rather than the regular list format.

 On Erlang this will be a tuple, on JavaScript this will be an array.
").
array(A) ->
    erlang:list_to_tuple(A).

-file("src/gleam/dynamic.gleam", 84).
-spec properties(list({dynamic_(), dynamic_()})) -> dynamic_().
-doc(~" Create a dynamic value made of an unordered series of keys and values, where
 the keys are unique.

 On Erlang this will be a map, on JavaScript this will be a Gleam dict
 object.
").
properties(Entries) ->
    gleam_stdlib:identity(maps:from_list(Entries)).

-file("src/gleam/dynamic.gleam", 93).
-spec nil() -> dynamic_().
-doc(~" A dynamic value representing nothing.

 On Erlang this will be the atom `nil`, on JavaScript this will be
 `undefined`.
").
nil() ->
    gleam_stdlib:identity(nil).

