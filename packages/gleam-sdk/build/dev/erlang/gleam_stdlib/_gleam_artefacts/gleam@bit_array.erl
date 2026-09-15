-module(gleam@bit_array).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([from_string/1, bit_size/1, byte_size/1, pad_to_bytes/1, concat/1, append/2, slice/3, is_utf8/1, to_string/1, base64_encode/2, base64_decode/1, base64_url_encode/2, base64_url_decode/1, base16_encode/1, base16_decode/1, inspect/1, compare/2, starts_with/2]).
-moduledoc(~" BitArrays are a sequence of binary data of any length.").

-file("src/gleam/bit_array.gleam", 14).
-spec from_string(binary()) -> bitstring().
-doc(~" Converts a string type into a bit array of UTF8 encoded data.

 This function runs in constant time on Erlang and in linear time on
 JavaScript.
").
from_string(X) ->
    gleam_stdlib:identity(X).

-file("src/gleam/bit_array.gleam", 20).
-spec bit_size(bitstring()) -> integer().
-doc(~" Returns an integer which is the number of bits in the bit array.
").
bit_size(X) ->
    erlang:bit_size(X).

-file("src/gleam/bit_array.gleam", 26).
-spec byte_size(bitstring()) -> integer().
-doc(~" Returns an integer which is the number of bytes in the bit array.
").
byte_size(X) ->
    erlang:byte_size(X).

-file("src/gleam/bit_array.gleam", 30).
-spec pad_to_bytes(bitstring()) -> bitstring().
-doc(~" Pads a bit array with zeros so that it is a whole number of bytes.
").
pad_to_bytes(Data) ->
    case erlang:bit_size(Data) rem 8 of
        0 ->
            Data;

        Trailing_bit_count ->
            Padding_bits = 8 - Trailing_bit_count,
            <<Data/bitstring, 0:(erlang:max(0, Padding_bits))>>
    end.

-file("src/gleam/bit_array.gleam", 124).
-spec concat(list(bitstring())) -> bitstring().
-doc(~" Creates a new bit array by joining multiple binaries.

 ## Examples

 ```gleam
 assert bit_array.concat([
     bit_array.from_string(\"butter\"),
     bit_array.from_string(\"fly\"),
   ])
   == bit_array.from_string(\"butterfly\")
 ```
").
concat(Bit_arrays) ->
    gleam_stdlib:bit_array_concat(Bit_arrays).

-file("src/gleam/bit_array.gleam", 52).
-spec append(bitstring(), bitstring()) -> bitstring().
-doc(~" Creates a new bit array by joining two bit arrays.

 ## Examples

 ```gleam
 assert bit_array.append(
     to: bit_array.from_string(\"butter\"),
     suffix: bit_array.from_string(\"fly\"),
   )
   == bit_array.from_string(\"butterfly\")
 ```
").
append(First, Second) ->
    gleam_stdlib:bit_array_concat([First, Second]).

-file("src/gleam/bit_array.gleam", 66).
-spec slice(bitstring(), integer(), integer()) -> {ok, bitstring()} | {error, nil}.
-doc(~" Extracts a sub-section of a bit array.

 The slice will start at given position and continue up to specified
 length.
 A negative length can be used to extract bytes at the end of a bit array.

 This function runs in constant time.
").
slice(String, Position, Length) ->
    gleam_stdlib:bit_array_slice(String, Position, Length).

-file("src/gleam/bit_array.gleam", 79).
-spec is_utf8_loop(bitstring()) -> boolean().
is_utf8_loop(Bits) ->
    case Bits of
        <<>> ->
            true;

        <<_/utf8, Rest/binary>> ->
            is_utf8_loop(Rest);

        _ ->
            false
    end.

-file("src/gleam/bit_array.gleam", 74).
-spec is_utf8(bitstring()) -> boolean().
-doc(~" Tests to see whether a bit array is valid UTF-8.
").
is_utf8(Bits) ->
    is_utf8_loop(Bits).

-file("src/gleam/bit_array.gleam", 100).
-spec to_string(bitstring()) -> {ok, binary()} | {error, nil}.
-doc(~" Converts a bit array to a string.

 Returns an error if the bit array is invalid UTF-8 data.
").
to_string(Bits) ->
    case is_utf8(Bits) of
        true ->
            {ok, gleam_stdlib:identity(Bits)};

        false ->
            {error, nil}
    end.

-file("src/gleam/bit_array.gleam", 133).
-spec base64_encode(bitstring(), boolean()) -> binary().
-doc(~" Encodes a BitArray into a base 64 encoded string.

 If the bit array does not contain a whole number of bytes then it is padded
 with zero bits prior to being encoded.
").
base64_encode(Input, Padding) ->
    gleam_stdlib:base64_encode(Input, Padding).

-file("src/gleam/bit_array.gleam", 137).
-spec base64_decode(binary()) -> {ok, bitstring()} | {error, nil}.
-doc(~" Decodes a base 64 encoded string into a `BitArray`.
").
base64_decode(Encoded) ->
    Padded = case erlang:byte_size(gleam_stdlib:identity(Encoded)) rem 4 of
        0 ->
            Encoded;

        N ->
            gleam@string:append(Encoded, gleam@string:repeat(~"=", 4 - N))
    end,
    gleam_stdlib:base64_decode(Padded).

-file("src/gleam/bit_array.gleam", 155).
-spec base64_url_encode(bitstring(), boolean()) -> binary().
-doc(~" Encodes a `BitArray` into a base 64 encoded string with URL and filename
 safe alphabet.

 If the bit array does not contain a whole number of bytes then it is padded
 with zero bits prior to being encoded.
").
base64_url_encode(Input, Padding) ->
    _pipe = Input,
    _pipe@1 = gleam_stdlib:base64_encode(_pipe, Padding),
    _pipe@2 = gleam@string:replace(_pipe@1, ~"+", ~"-"),
    gleam@string:replace(_pipe@2, ~"/", ~"_").

-file("src/gleam/bit_array.gleam", 165).
-spec base64_url_decode(binary()) -> {ok, bitstring()} | {error, nil}.
-doc(~" Decodes a base 64 encoded string with URL and filename safe alphabet into a
 `BitArray`.
").
base64_url_decode(Encoded) ->
    _pipe = Encoded,
    _pipe@1 = gleam@string:replace(_pipe, ~"-", ~"+"),
    _pipe@2 = gleam@string:replace(_pipe@1, ~"_", ~"/"),
    base64_decode(_pipe@2).

-file("src/gleam/bit_array.gleam", 179).
-spec base16_encode(bitstring()) -> binary().
-doc(~" Encodes a `BitArray` into a base 16 encoded string.

 If the bit array does not contain a whole number of bytes then it is padded
 with zero bits prior to being encoded.
").
base16_encode(Input) ->
    gleam_stdlib:base16_encode(Input).

-file("src/gleam/bit_array.gleam", 185).
-spec base16_decode(binary()) -> {ok, bitstring()} | {error, nil}.
-doc(~" Decodes a base 16 encoded string into a `BitArray`.
").
base16_decode(Input) ->
    gleam_stdlib:base16_decode(Input).

-file("src/gleam/bit_array.gleam", 206).
-spec inspect_loop(bitstring(), binary()) -> binary().
inspect_loop(Input, Accumulator) ->
    case Input of
        <<>> ->
            Accumulator;

        <<X:1>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X))/binary>>/binary, ":size(1)"/utf8>>;

        <<X@1:2>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X@1))/binary>>/binary, ":size(2)"/utf8>>;

        <<X@2:3>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X@2))/binary>>/binary, ":size(3)"/utf8>>;

        <<X@3:4>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X@3))/binary>>/binary, ":size(4)"/utf8>>;

        <<X@4:5>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X@4))/binary>>/binary, ":size(5)"/utf8>>;

        <<X@5:6>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X@5))/binary>>/binary, ":size(6)"/utf8>>;

        <<X@6:7>> ->
            <<<<Accumulator/binary, (erlang:integer_to_binary(X@6))/binary>>/binary, ":size(7)"/utf8>>;

        <<X@7, Rest/bitstring>> ->
            Suffix = case Rest of
                <<>> ->
                    ~"";

                _ ->
                    ~", "
            end,
            Accumulator@1 = <<<<Accumulator/binary, (erlang:integer_to_binary(X@7))/binary>>/binary, Suffix/binary>>,
            inspect_loop(Rest, Accumulator@1);

        _ ->
            Accumulator
    end.

-file("src/gleam/bit_array.gleam", 202).
-spec inspect(bitstring()) -> binary().
-doc(~" Converts a bit array to a string containing the decimal value of each byte.

 Use this over `string.inspect` when you have a bit array you want printed
 in the array syntax even if it is valid UTF-8.

 ## Examples

 ```gleam
 assert bit_array.inspect(<<0, 20, 0x20, 255>>) == \"<<0, 20, 32, 255>>\"
 ```

 ```gleam
 assert bit_array.inspect(<<100, 5:3>>) == \"<<100, 5:size(3)>>\"
 ```
").
inspect(Input) ->
    <<(inspect_loop(Input, ~"<<"))/binary, ">>"/utf8>>.

-file("src/gleam/bit_array.gleam", 248).
-spec compare(bitstring(), bitstring()) -> gleam@order:order().
-doc(~" Compare two bit arrays as sequences of bytes.

 ## Examples

 ```gleam
 assert bit_array.compare(<<1>>, <<2>>) == Lt
 ```

 ```gleam
 assert bit_array.compare(<<\"AB\":utf8>>, <<\"AA\":utf8>>) == Gt
 ```

 ```gleam
 assert bit_array.compare(<<1, 2:size(2)>>, with: <<1, 2:size(2)>>) == Eq
 ```
").
compare(A, B) ->
    case {A, B} of
        {<<First_byte, First_rest/bitstring>>, <<Second_byte, Second_rest/bitstring>>} ->
            case {First_byte, Second_byte} of
                {F, S} when F > S ->
                    gt;

                {F@1, S@1} when F@1 < S@1 ->
                    lt;

                {_, _} ->
                    compare(First_rest, Second_rest)
            end;

        {<<>>, <<>>} ->
            eq;

        {_, <<>>} ->
            gt;

        {<<>>, _} ->
            lt;

        {First, Second} ->
            case {gleam_stdlib:bit_array_to_int_and_size(First), gleam_stdlib:bit_array_to_int_and_size(Second)} of
                {{A@1, _}, {B@1, _}} when A@1 > B@1 ->
                    gt;

                {{A@2, _}, {B@2, _}} when A@2 < B@2 ->
                    lt;

                {{_, Size_a}, {_, Size_b}} when Size_a > Size_b ->
                    gt;

                {{_, Size_a@1}, {_, Size_b@1}} when Size_a@1 < Size_b@1 ->
                    lt;

                {_, _} ->
                    eq
            end
    end.

-file("src/gleam/bit_array.gleam", 288).
-spec starts_with(bitstring(), bitstring()) -> boolean().
-doc(~" Checks whether the first `BitArray` starts with the second one.

 ## Examples

 ```gleam
 assert bit_array.starts_with(<<1, 2, 3, 4>>, <<1, 2>>)
 ```
").
starts_with(Bits, Prefix) ->
    Prefix_size = erlang:bit_size(Prefix),
    case Bits of
        <<Pref:Prefix_size/bitstring, _/bitstring>> when Pref =:= Prefix ->
            true;

        _ ->
            false
    end.

