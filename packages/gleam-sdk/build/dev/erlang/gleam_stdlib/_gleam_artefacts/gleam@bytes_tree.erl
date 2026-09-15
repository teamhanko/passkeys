-module(gleam@bytes_tree).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([concat/1, new/0, from_bit_array/1, append_tree/2, prepend/2, append/2, prepend_tree/2, from_string/1, prepend_string/2, append_string/2, concat_bit_arrays/1, from_string_tree/1, to_bit_array/1, byte_size/1]).
-export_type([bytes_tree/0]).
-moduledoc(~" `BytesTree` is a type used for efficiently building binary content to be
 written to a file or a socket. Internally it is represented as a tree so to
 append or prepend to a bytes tree is a constant time operation that
 allocates a new node in the tree without copying any of the content. When
 writing to an output stream the tree is traversed and the content is sent
 directly rather than copying it into a single buffer beforehand.

 If we append one bit array to another the bit arrays must be copied to a
 new location in memory so that they can sit together. This behaviour
 enables efficient reading of the data but copying can be expensive,
 especially if we want to join many bit arrays together.

 BytesTree is different in that it can be joined together in constant
 time using minimal memory, and then can be efficiently converted to a
 bit array using the `to_bit_array` function.

 Byte trees are always byte aligned, so that a number of bits that is not
 divisible by 8 will be padded with 0s.

 On Erlang this type is compatible with Erlang's iolists.").

-opaque bytes_tree() :: {bytes, bitstring()} | {text, gleam@string_tree:string_tree()} | {many, list(bytes_tree())}.

-file("src/gleam/bytes_tree.gleam", 101).
-spec concat(list(bytes_tree())) -> bytes_tree().
-doc(~" Joins a list of bytes trees into a single one.

 Runs in constant time.
").
concat(Trees) ->
    gleam_stdlib:identity(Trees).

-file("src/gleam/bytes_tree.gleam", 35).
-spec new() -> bytes_tree().
-doc(~" Create an empty `BytesTree`. Useful as the start of a pipe chaining many
 trees together.
").
new() ->
    gleam_stdlib:identity([]).

-file("src/gleam/bytes_tree.gleam", 139).
-spec from_bit_array(bitstring()) -> bytes_tree().
-doc(~" Creates a new bytes tree from a bit array.

 Runs in constant time.
").
from_bit_array(Bits) ->
    _pipe = Bits,
    _pipe@1 = gleam@bit_array:pad_to_bytes(_pipe),
    gleam_stdlib:wrap_list(_pipe@1).

-file("src/gleam/bytes_tree.gleam", 71).
-spec append_tree(bytes_tree(), bytes_tree()) -> bytes_tree().
-doc(~" Appends a bytes tree onto the end of another.

 Runs in constant time.
").
append_tree(First, Second) ->
    gleam_stdlib:iodata_append(First, Second).

-file("src/gleam/bytes_tree.gleam", 43).
-spec prepend(bytes_tree(), bitstring()) -> bytes_tree().
-doc(~" Prepends a bit array to the start of a bytes tree.

 Runs in constant time.
").
prepend(Second, First) ->
    gleam_stdlib:iodata_append(from_bit_array(First), Second).

-file("src/gleam/bytes_tree.gleam", 51).
-spec append(bytes_tree(), bitstring()) -> bytes_tree().
-doc(~" Appends a bit array to the end of a bytes tree.

 Runs in constant time.
").
append(First, Second) ->
    gleam_stdlib:iodata_append(First, from_bit_array(Second)).

-file("src/gleam/bytes_tree.gleam", 59).
-spec prepend_tree(bytes_tree(), bytes_tree()) -> bytes_tree().
-doc(~" Prepends a bytes tree onto the start of another.

 Runs in constant time.
").
prepend_tree(Second, First) ->
    gleam_stdlib:iodata_append(First, Second).

-file("src/gleam/bytes_tree.gleam", 121).
-spec from_string(binary()) -> bytes_tree().
-doc(~" Creates a new bytes tree from a string.

 Runs in constant time when running on Erlang.
 Runs in linear time otherwise.
").
from_string(String) ->
    gleam_stdlib:wrap_list(String).

-file("src/gleam/bytes_tree.gleam", 83).
-spec prepend_string(bytes_tree(), binary()) -> bytes_tree().
-doc(~" Prepends a string onto the start of a bytes tree.

 Runs in constant time when running on Erlang.
 Runs in linear time with the length of the string otherwise.
").
prepend_string(Second, First) ->
    gleam_stdlib:iodata_append(gleam_stdlib:wrap_list(First), Second).

-file("src/gleam/bytes_tree.gleam", 92).
-spec append_string(bytes_tree(), binary()) -> bytes_tree().
-doc(~" Appends a string onto the end of a bytes tree.

 Runs in constant time when running on Erlang.
 Runs in linear time with the length of the string otherwise.
").
append_string(First, Second) ->
    gleam_stdlib:iodata_append(First, gleam_stdlib:wrap_list(Second)).

-file("src/gleam/bytes_tree.gleam", 109).
-spec concat_bit_arrays(list(bitstring())) -> bytes_tree().
-doc(~" Joins a list of bit arrays into a single bytes tree.

 Runs in constant time.
").
concat_bit_arrays(Bits) ->
    _pipe = Bits,
    _pipe@1 = gleam@list:map(_pipe, fun from_bit_array/1),
    gleam_stdlib:identity(_pipe@1).

-file("src/gleam/bytes_tree.gleam", 131).
-spec from_string_tree(gleam@string_tree:string_tree()) -> bytes_tree().
-doc(~" Creates a new bytes tree from a string tree.

 Runs in constant time when running on Erlang.
 Runs in linear time otherwise.
").
from_string_tree(Tree) ->
    gleam_stdlib:wrap_list(Tree).

-file("src/gleam/bytes_tree.gleam", 165).
-spec to_list(list(list(bytes_tree())), list(bitstring())) -> list(bitstring()).
to_list(Stack, Acc) ->
    case Stack of
        [] ->
            Acc;

        [[] | Remaining_stack] ->
            to_list(Remaining_stack, Acc);

        [[{bytes, Bits} | Rest] | Remaining_stack@1] ->
            to_list([Rest | Remaining_stack@1], [Bits | Acc]);

        [[{text, Tree} | Rest@1] | Remaining_stack@2] ->
            Bits@1 = gleam_stdlib:identity(unicode:characters_to_binary(Tree)),
            to_list([Rest@1 | Remaining_stack@2], [Bits@1 | Acc]);

        [[{many, Trees} | Rest@2] | Remaining_stack@3] ->
            to_list([Trees, Rest@2 | Remaining_stack@3], Acc)
    end.

-file("src/gleam/bytes_tree.gleam", 158).
-spec to_bit_array(bytes_tree()) -> bitstring().
-doc(~" Turns a bytes tree into a bit array.

 Runs in linear time.

 When running on Erlang this function is implemented natively by the
 virtual machine and is highly optimised.
").
to_bit_array(Tree) ->
    erlang:list_to_bitstring(Tree).

-file("src/gleam/bytes_tree.gleam", 192).
-spec byte_size(bytes_tree()) -> integer().
-doc(~" Returns the size of the bytes tree's content in bytes.

 Runs in linear time.
").
byte_size(Tree) ->
    erlang:iolist_size(Tree).

