-module(gleam@string).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([is_empty/1, length/1, reverse/1, replace/3, lowercase/1, uppercase/1, compare/2, slice/3, crop/2, byte_size/1, drop_start/2, drop_end/2, contains/2, starts_with/2, ends_with/2, pop_grapheme/1, to_graphemes/1, split/2, split_once/2, append/2, concat/1, repeat/2, join/2, pad_start/3, pad_end/3, trim_end/1, trim_start/1, trim/1, to_utf_codepoints/1, from_utf_codepoints/1, utf_codepoint/1, utf_codepoint_to_int/1, to_option/1, first/1, last/1, capitalise/1, inspect/1, remove_prefix/2, remove_suffix/2]).
-export_type([direction/0]).
-moduledoc(~" Strings are Gleam's text type, written in code using double quotes,
 `\"like this\"`.

 Two strings can be joined together using the concatenation operator: `<>`.

 Strings use the native string type of the compilation target. On Erlang
 they are UTF8 encoded binary strings, and on JavaScript they are UTF16
 encoded strings.

 Several escape sequences can be used in strings:

    `\\\"` - Double quote
    `\\\\` - Backslash
    `\\f` - Form feed
    `\\n` - Newline
    `\\r` - Carriage return
    `\\t` - Tab
    `\\u{xxxxxx}` - Unicode codepoint, where each `x` is a digit 0-9.").

-type direction() :: leading | trailing.

-file("src/gleam/string.gleam", 37).
-spec is_empty(binary()) -> boolean().
-doc(~" Determines if a `String` is empty.

 ## Examples

 ```gleam
 assert string.is_empty(\"\")
 ```

 ```gleam
 assert !string.is_empty(\"the world\")
 ```
").
is_empty(Str) ->
    Str =:= ~"".

-file("src/gleam/string.gleam", 62).
-spec length(binary()) -> integer().
-doc(~" Gets the number of grapheme clusters in a given `String`.

 This function has to iterate across the whole string to count the number of
 graphemes, so it runs in linear time. Avoid using this in a loop.

 ## Examples

 ```gleam
 assert string.length(\"Gleam\") == 5
 ```

 ```gleam
 assert string.length(\"ß↑e̊\") == 3
 ```

 ```gleam
 assert string.length(\"\") == 0
 ```
").
length(String) ->
    string:length(String).

-file("src/gleam/string.gleam", 75).
-spec reverse(binary()) -> binary().
-doc(~" Reverses a `String`.

 This function has to iterate across the whole `String` so it runs in linear
 time. Avoid using this in a loop.

 ## Examples

 ```gleam
 assert string.reverse(\"stressed\") == \"desserts\"
 ```
").
reverse(String) ->
    _pipe = String,
    _pipe@1 = gleam_stdlib:identity(_pipe),
    _pipe@2 = string:reverse(_pipe@1),
    unicode:characters_to_binary(_pipe@2).

-file("src/gleam/string.gleam", 95).
-spec replace(binary(), binary(), binary()) -> binary().
-doc(~" Creates a new `String` by replacing all occurrences of a given substring.

 ## Examples

 ```gleam
 assert string.replace(\"www.example.com\", each: \".\", with: \"-\")
   == \"www-example-com\"
 ```

 ```gleam
 assert string.replace(\"a,b,c,d,e\", each: \",\", with: \"/\") == \"a/b/c/d/e\"
 ```
").
replace(String, Pattern, Substitute) ->
    _pipe = String,
    _pipe@1 = gleam_stdlib:identity(_pipe),
    _pipe@2 = gleam_stdlib:string_replace(_pipe@1, Pattern, Substitute),
    unicode:characters_to_binary(_pipe@2).

-file("src/gleam/string.gleam", 119).
-spec lowercase(binary()) -> binary().
-doc(~" Creates a new `String` with all the graphemes in the input `String` converted to
 lowercase.

 Useful for case-insensitive comparisons.

 ## Examples

 ```gleam
 assert string.lowercase(\"X-FILES\") == \"x-files\"
 ```
").
lowercase(String) ->
    string:lowercase(String).

-file("src/gleam/string.gleam", 134).
-spec uppercase(binary()) -> binary().
-doc(~" Creates a new `String` with all the graphemes in the input `String` converted to
 uppercase.

 Useful for case-insensitive comparisons and VIRTUAL YELLING.

 ## Examples

 ```gleam
 assert string.uppercase(\"skinner\") == \"SKINNER\"
 ```
").
uppercase(String) ->
    string:uppercase(String).

-file("src/gleam/string.gleam", 154).
-spec compare(binary(), binary()) -> gleam@order:order().
-doc(~" Compares two `String`s to see which is \"larger\" by comparing their graphemes.

 This does not compare the size or length of the given `String`s.

 ## Examples

 ```gleam
 import gleam/order

 assert string.compare(\"Anthony\", \"Anthony\") == order.Eq
 ```

 ```gleam
 import gleam/order

 assert string.compare(\"A\", \"B\") == order.Lt
 ```
").
compare(A, B) ->
    case A =:= B of
        true ->
            eq;

        _ ->
            case gleam_stdlib:less_than(A, B) of
                true ->
                    lt;

                false ->
                    gt
            end
    end.

-file("src/gleam/string.gleam", 198).
-spec slice(binary(), integer(), integer()) -> binary().
-doc(~" Takes a substring given a start grapheme index and a length. Negative indexes
 are taken starting from the *end* of the string.

 This function runs in linear time with the size of the index and the
 length. Negative indexes are linear with the size of the input string in
 addition to the other costs.

 ## Examples

 ```gleam
 assert string.slice(from: \"gleam\", at_index: 1, length: 2) == \"le\"
 ```

 ```gleam
 assert string.slice(from: \"gleam\", at_index: 1, length: 10) == \"leam\"
 ```

 ```gleam
 assert string.slice(from: \"gleam\", at_index: 10, length: 3) == \"\"
 ```

 ```gleam
 assert string.slice(from: \"gleam\", at_index: -2, length: 2) == \"am\"
 ```

 ```gleam
 assert string.slice(from: \"gleam\", at_index: -12, length: 2) == \"\"
 ```
").
slice(String, Idx, Len) ->
    case Len =< 0 of
        true ->
            ~"";

        false ->
            case Idx < 0 of
                true ->
                    Translated_idx = string:length(String) + Idx,
                    case Translated_idx < 0 of
                        true ->
                            ~"";

                        false ->
                            gleam_stdlib:slice(String, Translated_idx, Len)
                    end;

                false ->
                    gleam_stdlib:slice(String, Idx, Len)
            end
    end.

-file("src/gleam/string.gleam", 239).
-spec crop(binary(), binary()) -> binary().
-doc(~" Drops contents of the first `String` that occur before the second `String`.
 If the `from` string does not contain the `before` string, `from` is
 returned unchanged.

 ## Examples

 ```gleam
 assert string.crop(from: \"The Lone Gunmen\", before: \"Lone\") == \"Lone Gunmen\"
 ```
").
crop(String, Substring) ->
    gleam_stdlib:crop_string(String, Substring).

-file("src/gleam/string.gleam", 874).
-spec byte_size(binary()) -> integer().
-doc(~" Returns the number of bytes in a `String`.

 This function runs in constant time on Erlang and in linear time on
 JavaScript.

 ## Examples

 ```gleam
 assert string.byte_size(\"🏳️‍⚧️🏳️‍🌈👩🏾‍❤️‍👨🏻\") == 58
 ```
").
byte_size(String) ->
    erlang:byte_size(String).

-file("src/gleam/string.gleam", 251).
-spec drop_start(binary(), integer()) -> binary().
-doc(~" Drops *n* graphemes from the start of a `String`.

 This function runs in linear time with the number of graphemes to drop.

 ## Examples

 ```gleam
 assert string.drop_start(from: \"The Lone Gunmen\", up_to: 2) == \"e Lone Gunmen\"
 ```
").
drop_start(String, Num_graphemes) ->
    case Num_graphemes =< 0 of
        true ->
            String;

        false ->
            Prefix = gleam_stdlib:slice(String, 0, Num_graphemes),
            Prefix_size = erlang:byte_size(Prefix),
            binary:part(String, Prefix_size, erlang:byte_size(String) - Prefix_size)
    end.

-file("src/gleam/string.gleam", 274).
-spec drop_end(binary(), integer()) -> binary().
-doc(~" Drops *n* graphemes from the end of a `String`.

 This function traverses the full string, so it runs in linear time with the
 size of the string. Avoid using this in a loop.

 ## Examples

 ```gleam
 assert string.drop_end(from: \"Cigarette Smoking Man\", up_to: 2)
   == \"Cigarette Smoking M\"
 ```
").
drop_end(String, Num_graphemes) ->
    case Num_graphemes =< 0 of
        true ->
            String;

        false ->
            slice(String, 0, string:length(String) - Num_graphemes)
    end.

-file("src/gleam/string.gleam", 299).
-spec contains(binary(), binary()) -> boolean().
-doc(~" Checks if the first `String` contains the second.

 ## Examples

 ```gleam
 assert string.contains(does: \"theory\", contain: \"ory\")
 ```

 ```gleam
 assert string.contains(does: \"theory\", contain: \"the\")
 ```

 ```gleam
 assert !string.contains(does: \"theory\", contain: \"THE\")
 ```
").
contains(Haystack, Needle) ->
    gleam_stdlib:contains_string(Haystack, Needle).

-file("src/gleam/string.gleam", 311).
-spec starts_with(binary(), binary()) -> boolean().
-doc(~" Checks whether the first `String` starts with the second one.

 ## Examples

 ```gleam
 assert !string.starts_with(\"theory\", \"ory\")
 ```
").
starts_with(String, Prefix) ->
    gleam_stdlib:string_starts_with(String, Prefix).

-file("src/gleam/string.gleam", 323).
-spec ends_with(binary(), binary()) -> boolean().
-doc(~" Checks whether the first `String` ends with the second one.

 ## Examples

 ```gleam
 assert string.ends_with(\"theory\", \"ory\")
 ```
").
ends_with(String, Suffix) ->
    gleam_stdlib:string_ends_with(String, Suffix).

-file("src/gleam/string.gleam", 616).
-spec pop_grapheme(binary()) -> {ok, {binary(), binary()}} | {error, nil}.
-doc(~" Splits a non-empty `String` into its first element (head) and rest (tail).
 This lets you pattern match on `String`s exactly as you would with lists.

 ## Performance

 There is a notable overhead to using this function, so you may not want to
 use it in a tight loop. If you wish to efficiently parse a string you may
 want to use alternatives such as the [splitter package](https://hex.pm/packages/splitter).

 ## Examples

 ```gleam
 assert string.pop_grapheme(\"gleam\") == Ok(#(\"g\", \"leam\"))
 ```

 ```gleam
 assert string.pop_grapheme(\"\") == Error(Nil)
 ```
").
pop_grapheme(String) ->
    gleam_stdlib:string_pop_grapheme(String).

-file("src/gleam/string.gleam", 632).
-spec to_graphemes_loop(binary(), list(binary())) -> list(binary()).
to_graphemes_loop(String, Acc) ->
    case gleam_stdlib:string_pop_grapheme(String) of
        {ok, {Grapheme, Rest}} ->
            to_graphemes_loop(Rest, [Grapheme | Acc]);

        {error, _} ->
            Acc
    end.

-file("src/gleam/string.gleam", 626).
-spec to_graphemes(binary()) -> list(binary()).
-doc(~" Converts a `String` to a list of
 [graphemes](https://en.wikipedia.org/wiki/Grapheme).

 ```gleam
 assert string.to_graphemes(\"abc\") == [\"a\", \"b\", \"c\"]
 ```
").
to_graphemes(String) ->
    _pipe = String,
    _pipe@1 = to_graphemes_loop(_pipe, []),
    lists:reverse(_pipe@1).

-file("src/gleam/string.gleam", 334).
-spec split(binary(), binary()) -> list(binary()).
-doc(~" Creates a list of `String`s by splitting a given string on a given substring.

 ## Examples

 ```gleam
 assert string.split(\"home/gleam/desktop/\", on: \"/\")
   == [\"home\", \"gleam\", \"desktop\", \"\"]
 ```
").
split(X, Substring) ->
    case Substring of
        ~"" ->
            to_graphemes(X);

        _ ->
            _pipe = X,
            _pipe@1 = gleam_stdlib:identity(_pipe),
            _pipe@2 = gleam@string_tree:split(_pipe@1, Substring),
            gleam@list:map(_pipe@2, fun unicode:characters_to_binary/1)
    end.

-file("src/gleam/string.gleam", 361).
-spec split_once(binary(), binary()) -> {ok, {binary(), binary()}} | {error, nil}.
-doc(~" Splits a `String` a single time on the given substring.

 Returns an `Error` if substring not present.

 ## Examples

 ```gleam
 assert string.split_once(\"home/gleam/desktop/\", on: \"/\")
   == Ok(#(\"home\", \"gleam/desktop/\"))
 ```

 ```gleam
 assert string.split_once(\"home/gleam/desktop/\", on: \"?\") == Error(Nil)
 ```
").
split_once(String, Substring) ->
    case string:split(String, Substring) of
        [First, Rest] ->
            {ok, {First, Rest}};

        _ ->
            {error, nil}
    end.

-file("src/gleam/string.gleam", 391).
-spec append(binary(), binary()) -> binary().
-doc(~" Creates a new `String` by joining two `String`s together.

 This function typically copies both `String`s and runs in linear time, but
 the exact behaviour will depend on how the runtime you are using optimises
 your code. Benchmark and profile your code if you need to understand its
 performance better.

 If you are joining together large string and want to avoid copying any data
 you may want to investigate using the [`string_tree`](../gleam/string_tree.html)
 module.

 ## Examples

 ```gleam
 assert string.append(to: \"butter\", suffix: \"fly\") == \"butterfly\"
 ```
").
append(First, Second) ->
    <<First/binary, Second/binary>>.

-file("src/gleam/string.gleam", 410).
-spec concat_loop(list(binary()), binary()) -> binary().
concat_loop(Strings, Accumulator) ->
    case Strings of
        [String | Strings@1] ->
            concat_loop(Strings@1, <<Accumulator/binary, String/binary>>);

        [] ->
            Accumulator
    end.

-file("src/gleam/string.gleam", 406).
-spec concat(list(binary())) -> binary().
-doc(~" Creates a new `String` by joining many `String`s together.

 This function copies all the `String`s and runs in linear time.

 ## Examples

 ```gleam
 assert string.concat([\"never\", \"the\", \"less\"]) == \"nevertheless\"
 ```
").
concat(Strings) ->
    erlang:list_to_binary(Strings).

-file("src/gleam/string.gleam", 434).
-spec repeat_loop(integer(), binary(), binary()) -> binary().
repeat_loop(Times, Doubling_acc, Acc) ->
    Acc@1 = case Times rem 2 of
        0 ->
            Acc;

        _ ->
            <<Acc/binary, Doubling_acc/binary>>
    end,
    Times@1 = Times div 2,
    case Times@1 =< 0 of
        true ->
            Acc@1;

        false ->
            repeat_loop(Times@1, <<Doubling_acc/binary, Doubling_acc/binary>>, Acc@1)
    end.

-file("src/gleam/string.gleam", 427).
-spec repeat(binary(), integer()) -> binary().
-doc(~" Creates a new `String` by repeating a `String` a given number of times.

 This function runs in loglinear time.

 ## Examples

 ```gleam
 assert string.repeat(\"ha\", times: 3) == \"hahaha\"
 ```
").
repeat(String, Times) ->
    case Times =< 0 of
        true ->
            ~"";

        false ->
            repeat_loop(Times, String, ~"")
    end.

-file("src/gleam/string.gleam", 464).
-spec join_loop(list(binary()), binary(), binary()) -> binary().
join_loop(Strings, Separator, Accumulator) ->
    case Strings of
        [] ->
            Accumulator;

        [String | Strings@1] ->
            join_loop(Strings@1, Separator, <<<<Accumulator/binary, Separator/binary>>/binary, String/binary>>)
    end.

-file("src/gleam/string.gleam", 457).
-spec join(list(binary()), binary()) -> binary().
-doc(~" Joins many `String`s together with a given separator.

 This function runs in linear time.

 ## Examples

 ```gleam
 assert string.join([\"home\", \"evan\", \"Desktop\"], with: \"/\")
   == \"home/evan/Desktop\"
 ```
").
join(Strings, Separator) ->
    case Strings of
        [] ->
            ~"";

        [First | Rest] ->
            join_loop(Rest, Separator, First)
    end.

-file("src/gleam/string.gleam", 536).
-spec padding(integer(), binary()) -> binary().
padding(Size, Pad_string) ->
    Pad_string_length = string:length(Pad_string),
    Num_pads = case Pad_string_length of
        0 ->
            0;

        _value ->
            Size div _value
    end,
    Extra = case Pad_string_length of
        0 ->
            0;

        _value@1 ->
            Size rem _value@1
    end,
    <<(repeat(Pad_string, Num_pads))/binary, (slice(Pad_string, 0, Extra))/binary>>.

-file("src/gleam/string.gleam", 492).
-spec pad_start(binary(), integer(), binary()) -> binary().
-doc(~" Pads the start of a `String` until it has a given length.

 ## Examples

 ```gleam
 assert string.pad_start(\"121\", to: 5, with: \".\") == \"..121\"
 ```

 ```gleam
 assert string.pad_start(\"121\", to: 3, with: \".\") == \"121\"
 ```

 ```gleam
 assert string.pad_start(\"121\", to: 2, with: \".\") == \"121\"
 ```
").
pad_start(String, Desired_length, Pad_string) ->
    Current_length = string:length(String),
    To_pad_length = Desired_length - Current_length,
    case To_pad_length =< 0 of
        true ->
            String;

        false ->
            <<(padding(To_pad_length, Pad_string))/binary, String/binary>>
    end.

-file("src/gleam/string.gleam", 522).
-spec pad_end(binary(), integer(), binary()) -> binary().
-doc(~" Pads the end of a `String` until it has a given length.

 ## Examples

 ```gleam
 assert string.pad_end(\"123\", to: 5, with: \".\") == \"123..\"
 ```

 ```gleam
 assert string.pad_end(\"123\", to: 3, with: \".\") == \"123\"
 ```

 ```gleam
 assert string.pad_end(\"123\", to: 2, with: \".\") == \"123\"
 ```
").
pad_end(String, Desired_length, Pad_string) ->
    Current_length = string:length(String),
    To_pad_length = Desired_length - Current_length,
    case To_pad_length =< 0 of
        true ->
            String;

        false ->
            <<String/binary, (padding(To_pad_length, Pad_string))/binary>>
    end.

-file("src/gleam/string.gleam", 591).
-spec trim_end(binary()) -> binary().
-doc(~" Removes whitespace at the end of a `String`.

 ## Examples

 ```gleam
 assert string.trim_end(\"  hats  \\n\") == \"  hats\"
 ```
").
trim_end(String) ->
    string:trim(String, trailing).

-file("src/gleam/string.gleam", 578).
-spec trim_start(binary()) -> binary().
-doc(~" Removes whitespace at the start of a `String`.

 ## Examples

 ```gleam
 assert string.trim_start(\"  hats  \\n\") == \"hats  \\n\"
 ```
").
trim_start(String) ->
    string:trim(String, leading).

-file("src/gleam/string.gleam", 557).
-spec trim(binary()) -> binary().
-doc(~" Removes whitespace on both sides of a `String`.

 Whitespace in this function is the set of nonbreakable whitespace
 codepoints, defined as Pattern_White_Space in [Unicode Standard Annex #31][1].

 [1]: https://unicode.org/reports/tr31/

 ## Examples

 ```gleam
 assert string.trim(\"  hats  \\n\") == \"hats\"
 ```
").
trim(String) ->
    _pipe = String,
    _pipe@1 = trim_start(_pipe),
    trim_end(_pipe@1).

-file("src/gleam/string.gleam", 678).
-spec to_utf_codepoints_loop(bitstring(), list(integer())) -> list(integer()).
to_utf_codepoints_loop(Bit_array, Acc) ->
    case Bit_array of
        <<First/utf8, Rest/binary>> ->
            to_utf_codepoints_loop(Rest, [First | Acc]);

        _ ->
            lists:reverse(Acc)
    end.

-file("src/gleam/string.gleam", 673).
-spec do_to_utf_codepoints(binary()) -> list(integer()).
do_to_utf_codepoints(String) ->
    to_utf_codepoints_loop(<<String/binary>>, []).

-file("src/gleam/string.gleam", 668).
-spec to_utf_codepoints(binary()) -> list(integer()).
-doc(~" Converts a `String` to a `List` of `UtfCodepoint`.

 See <https://en.wikipedia.org/wiki/Code_point> and
 <https://en.wikipedia.org/wiki/Unicode#Codespace_and_Code_Points> for an
 explanation on code points.

 ## Examples

 ```gleam
 assert \"a\" |> string.to_utf_codepoints == [UtfCodepoint(97)]
 ```

 ```gleam
 // Semantically the same as:
 // [\"🏳\", \"️\", \"‍\", \"🌈\"] or:
 // [waving_white_flag, variant_selector_16, zero_width_joiner, rainbow]
 assert \"🏳️‍🌈\" |> string.to_utf_codepoints
   == [
     UtfCodepoint(127_987),
     UtfCodepoint(65_039),
     UtfCodepoint(8205),
     UtfCodepoint(127_752),
   ]
 ```
").
to_utf_codepoints(String) ->
    do_to_utf_codepoints(String).

-file("src/gleam/string.gleam", 717).
-spec from_utf_codepoints(list(integer())) -> binary().
-doc(~" Converts a `List` of `UtfCodepoint`s to a `String`.

 See <https://en.wikipedia.org/wiki/Code_point> and
 <https://en.wikipedia.org/wiki/Unicode#Codespace_and_Code_Points> for an
 explanation on code points.

 ## Examples

 ```gleam
 let assert Ok(a) = string.utf_codepoint(97)
 let assert Ok(b) = string.utf_codepoint(98)
 let assert Ok(c) = string.utf_codepoint(99)
 assert string.from_utf_codepoints([a, b, c]) == \"abc\"
 ```
").
from_utf_codepoints(Utf_codepoints) ->
    gleam_stdlib:utf_codepoint_list_to_string(Utf_codepoints).

-file("src/gleam/string.gleam", 723).
-spec utf_codepoint(integer()) -> {ok, integer()} | {error, nil}.
-doc(~" Converts an integer to a `UtfCodepoint`.

 Returns an `Error` if the integer does not represent a valid UTF codepoint.
").
utf_codepoint(Value) ->
    case Value of
        I when I > 1114111 ->
            {error, nil};

        I@1 when (I@1 >= 55296) andalso (I@1 =< 57343) ->
            {error, nil};

        I@2 when I@2 < 0 ->
            {error, nil};

        I@3 ->
            {ok, gleam_stdlib:identity(I@3)}
    end.

-file("src/gleam/string.gleam", 743).
-spec utf_codepoint_to_int(integer()) -> integer().
-doc(~" Converts a `UtfCodepoint` to its ordinal code point value.

 ## Examples

 ```gleam
 let assert [utf_codepoint, ..] = string.to_utf_codepoints(\"💜\")
 assert string.utf_codepoint_to_int(utf_codepoint) == 128_156
 ```
").
utf_codepoint_to_int(Cp) ->
    gleam_stdlib:identity(Cp).

-file("src/gleam/string.gleam", 758).
-spec to_option(binary()) -> gleam@option:option(binary()).
-doc(~" Converts a `String` into `Option(String)` where an empty `String` becomes
 `None`.

 ## Examples

 ```gleam
 assert string.to_option(\"\") == None
 ```

 ```gleam
 assert string.to_option(\"hats\") == Some(\"hats\")
 ```
").
to_option(String) ->
    case String of
        ~"" ->
            none;

        _ ->
            {some, String}
    end.

-file("src/gleam/string.gleam", 779).
-spec first(binary()) -> {ok, binary()} | {error, nil}.
-doc(~" Returns the first grapheme cluster in a given `String` and wraps it in a
 `Result(String, Nil)`. If the `String` is empty, it returns `Error(Nil)`.
 Otherwise, it returns `Ok(String)`.

 ## Examples

 ```gleam
 assert string.first(\"\") == Error(Nil)
 ```

 ```gleam
 assert string.first(\"icecream\") == Ok(\"i\")
 ```
").
first(String) ->
    case gleam_stdlib:string_pop_grapheme(String) of
        {ok, {First, _}} ->
            {ok, First};

        {error, E} ->
            {error, E}
    end.

-file("src/gleam/string.gleam", 803).
-spec last(binary()) -> {ok, binary()} | {error, nil}.
-doc(~" Returns the last grapheme cluster in a given `String` and wraps it in a
 `Result(String, Nil)`. If the `String` is empty, it returns `Error(Nil)`.
 Otherwise, it returns `Ok(String)`.

 This function traverses the full string, so it runs in linear time with the
 length of the string. Avoid using this in a loop.

 ## Examples

 ```gleam
 assert string.last(\"\") == Error(Nil)
 ```

 ```gleam
 assert string.last(\"icecream\") == Ok(\"m\")
 ```
").
last(String) ->
    case gleam_stdlib:string_pop_grapheme(String) of
        {ok, {First, ~""}} ->
            {ok, First};

        {ok, {_, Rest}} ->
            {ok, slice(Rest, -1, 1)};

        {error, E} ->
            {error, E}
    end.

-file("src/gleam/string.gleam", 820).
-spec capitalise(binary()) -> binary().
-doc(~" Creates a new `String` with the first grapheme in the input `String`
 converted to uppercase and the remaining graphemes to lowercase.

 ## Examples

 ```gleam
 assert string.capitalise(\"mamouna\") == \"Mamouna\"
 ```
").
capitalise(String) ->
    case gleam_stdlib:string_pop_grapheme(String) of
        {ok, {First, Rest}} ->
            append(string:uppercase(First), string:lowercase(Rest));

        {error, _} ->
            ~""
    end.

-file("src/gleam/string.gleam", 851).
-spec inspect(any()) -> binary().
-doc(~" Returns a `String` representation of a term in Gleam syntax.

 This may be occasionally useful for quick-and-dirty printing of values in
 scripts. For error reporting and other uses prefer constructing strings by
 pattern matching on the values.

 ## Limitations

 The output format of this function is not stable and could change at any
 time. The output is not suitable for parsing.

 This function works using runtime reflection, so the output may not be
 perfectly accurate for data structures where the runtime structure doesn't
 hold enough information to determine the original syntax. For example,
 tuples with an Erlang atom in the first position will be mistaken for Gleam
 records.

 ## Security and safety

 There is no limit to how large the strings that this function can produce.
 Be careful not to call this function with large data structures or you
 could use very large amounts of memory, potentially causing runtime
 problems.
").
inspect(Term) ->
    _pipe = Term,
    _pipe@1 = gleam_stdlib:inspect(_pipe),
    unicode:characters_to_binary(_pipe@1).

-file("src/gleam/string.gleam", 893).
-spec remove_prefix(binary(), binary()) -> binary().
-doc(~" Removes the given prefix from the start of a `String`, if present.

 If the `String` does not start with the given prefix the string is returned
 unchanged.

 ## Examples

 ```gleam
 assert string.remove_prefix(\"@lpil\", \"@\") == \"lpil\"
 ```

 ```gleam
 assert string.remove_prefix(\"hello!\", \"@\") == \"hello!\"
 ```
").
remove_prefix(String, Prefix) ->
    gleam_stdlib:string_remove_prefix(String, Prefix).

-file("src/gleam/string.gleam", 912).
-spec remove_suffix(binary(), binary()) -> binary().
-doc(~" Removes the given suffix from the end of a `String`, if present.

 If the `String` does not end with the given suffix the string is returned
 unchanged.

 ## Examples

 ```gleam
 assert string.remove_suffix(\"Hello!\", \"!\") == \"Hello\"
 ```

 ```gleam
 assert string.remove_suffix(\"Hello!?\", \"!\") == \"Hello!?\"
 ```
").
remove_suffix(String, Suffix) ->
    gleam_stdlib:string_remove_suffix(String, Suffix).

