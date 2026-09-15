-module(gleam@string_tree).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([from_strings/1, new/0, from_string/1, append_tree/2, prepend/2, append/2, prepend_tree/2, concat/1, to_string/1, byte_size/1, join/2, lowercase/1, uppercase/1, reverse/1, split/2, replace/3, is_equal/2, is_empty/1]).
-export_type([string_tree/0, direction/0]).

-type string_tree() :: any().

-type direction() :: all.

-file("src/gleam/string_tree.gleam", 69).
-spec from_strings(list(binary())) -> string_tree().
-doc(~" Converts a list of strings into a `StringTree`.

 Runs in constant time.
").
from_strings(Strings) ->
    gleam_stdlib:identity(Strings).

-file("src/gleam/string_tree.gleam", 24).
-spec new() -> string_tree().
-doc(~" Create an empty `StringTree`. Useful as the start of a pipe chaining many
 trees together.
").
new() ->
    gleam_stdlib:identity([]).

-file("src/gleam/string_tree.gleam", 85).
-spec from_string(binary()) -> string_tree().
-doc(~" Converts a string into a `StringTree`.

 Runs in constant time.
").
from_string(String) ->
    gleam_stdlib:identity(String).

-file("src/gleam/string_tree.gleam", 61).
-spec append_tree(string_tree(), string_tree()) -> string_tree().
-doc(~" Appends some `StringTree` onto the end of another.

 Runs in constant time.
").
append_tree(Tree, Suffix) ->
    gleam_stdlib:iodata_append(Tree, Suffix).

-file("src/gleam/string_tree.gleam", 32).
-spec prepend(string_tree(), binary()) -> string_tree().
-doc(~" Prepends a `String` onto the start of some `StringTree`.

 Runs in constant time.
").
prepend(Tree, Prefix) ->
    gleam_stdlib:iodata_append(gleam_stdlib:identity(Prefix), Tree).

-file("src/gleam/string_tree.gleam", 40).
-spec append(string_tree(), binary()) -> string_tree().
-doc(~" Appends a `String` onto the end of some `StringTree`.

 Runs in constant time.
").
append(Tree, Second) ->
    gleam_stdlib:iodata_append(Tree, gleam_stdlib:identity(Second)).

-file("src/gleam/string_tree.gleam", 48).
-spec prepend_tree(string_tree(), string_tree()) -> string_tree().
-doc(~" Prepends some `StringTree` onto the start of another.

 Runs in constant time.
").
prepend_tree(Tree, Prefix) ->
    gleam_stdlib:iodata_append(Prefix, Tree).

-file("src/gleam/string_tree.gleam", 77).
-spec concat(list(string_tree())) -> string_tree().
-doc(~" Joins a list of trees into a single tree.

 Runs in constant time.
").
concat(Trees) ->
    gleam_stdlib:identity(Trees).

-file("src/gleam/string_tree.gleam", 94).
-spec to_string(string_tree()) -> binary().
-doc(~" Turns a `StringTree` into a `String`.

 This function is implemented natively by the virtual machine and is highly
 optimised.
").
to_string(Tree) ->
    unicode:characters_to_binary(Tree).

-file("src/gleam/string_tree.gleam", 100).
-spec byte_size(string_tree()) -> integer().
-doc(~" Returns the size of the `StringTree` in bytes.
").
byte_size(Tree) ->
    erlang:iolist_size(Tree).

-file("src/gleam/string_tree.gleam", 104).
-spec join(list(string_tree()), binary()) -> string_tree().
-doc(~" Joins the given trees into a new tree separated with the given string.
").
join(Trees, Sep) ->
    _pipe = Trees,
    _pipe@1 = gleam@list:intersperse(_pipe, gleam_stdlib:identity(Sep)),
    gleam_stdlib:identity(_pipe@1).

-file("src/gleam/string_tree.gleam", 115).
-spec lowercase(string_tree()) -> string_tree().
-doc(~" Converts a `StringTree` to a new one where the contents have been
 lowercased.
").
lowercase(Tree) ->
    string:lowercase(Tree).

-file("src/gleam/string_tree.gleam", 122).
-spec uppercase(string_tree()) -> string_tree().
-doc(~" Converts a `StringTree` to a new one where the contents have been
 uppercased.
").
uppercase(Tree) ->
    string:uppercase(Tree).

-file("src/gleam/string_tree.gleam", 127).
-spec reverse(string_tree()) -> string_tree().
-doc(~" Converts a `StringTree` to a new one with the contents reversed.
").
reverse(Tree) ->
    string:reverse(Tree).

-file("src/gleam/string_tree.gleam", 145).
-spec split(string_tree(), binary()) -> list(string_tree()).
-doc(~" Splits a `StringTree` on a given pattern into a list of trees.
").
split(Tree, Pattern) ->
    string:split(Tree, Pattern, all).

-file("src/gleam/string_tree.gleam", 156).
-spec replace(string_tree(), binary(), binary()) -> string_tree().
-doc(~" Replaces all instances of a pattern with a given string substitute.
").
replace(Tree, Pattern, Substitute) ->
    gleam_stdlib:string_replace(Tree, Pattern, Substitute).

-file("src/gleam/string_tree.gleam", 183).
-spec is_equal(string_tree(), string_tree()) -> boolean().
-doc(~" Compares two string trees to determine if they have the same textual
 content.

 Comparing two string trees using the `==` operator may return `False` even
 if they have the same content as they may have been built in different ways,
 so using this function is often preferred.

 ## Examples

 ```gleam
 assert string_tree.from_strings([\"a\", \"b\"]) != string_tree.from_string(\"ab\")
 ```

 ```gleam
 assert string_tree.is_equal(
   string_tree.from_strings([\"a\", \"b\"]),
   string_tree.from_string(\"ab\"),
 )
 ```
").
is_equal(A, B) ->
    string:equal(A, B).

-file("src/gleam/string_tree.gleam", 204).
-spec is_empty(string_tree()) -> boolean().
-doc(~" Inspects a `StringTree` to determine if it is equivalent to an empty string.

 ## Examples

 ```gleam
 assert !{ string_tree.from_string(\"ok\") |> string_tree.is_empty }
 ```

 ```gleam
 assert string_tree.from_string(\"\") |> string_tree.is_empty
 ```

 ```gleam
 assert string_tree.from_strings([]) |> string_tree.is_empty
 ```
").
is_empty(Tree) ->
    string:is_empty(Tree).

