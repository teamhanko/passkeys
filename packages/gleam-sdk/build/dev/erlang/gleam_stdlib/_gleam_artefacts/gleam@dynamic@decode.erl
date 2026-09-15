-module(gleam@dynamic@decode).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([decode_dynamic/1, run/2, decode_float/1, map/2, decode_int/1, decode_bit_array/1, decode_string/1, one_of/2, list/1, subfield/3, at/2, success/1, decode_error/2, field/3, optional_field/4, optionally_at/3, decode_bool/1, dict/2, optional/1, map_errors/2, collapse_errors/2, then/2, failure/2, new_primitive_decoder/2, recursive/1]).
-export_type([decode_error/0, decoder/1]).
-moduledoc(~" The `Dynamic` type is used to represent dynamically typed data. That is, data
 that we don't know the precise type of yet, so we need to introspect the data to
 see if it is of the desired type before we can use it. Typically data like this
 would come from user input or from untyped languages such as Erlang or JavaScript.

 This module provides the `Decoder` type and associated functions, which provides
 a type-safe and composable way to convert dynamic data into some desired type,
 or into errors if the data doesn't have the desired structure.

 The `Decoder` type is generic and has 1 type parameter, which is the type that
 it attempts to decode. A `Decoder(String)` can be used to decode strings, and a
 `Decoder(Option(Int))` can be used to decode `Option(Int)`s

 Decoders work using _runtime reflection_ and the data structures of the target
 platform. Differences between Erlang and JavaScript data structures may impact
 your decoders, so it is important to test your decoders on all supported
 platforms.

 The decoding technique used by this module was inspired by Juraj Petráš'
 [Toy](https://github.com/Hackder/toy), Go's `encoding/json`, and Elm's
 `Json.Decode`. Thank you to them!

 # Generating decoders

 The language server has the \"generate dynamic decoder\" code action, which
 will generate a decoder function when run on a custom type definition.
 This generated decoder function can be a convenient shortcut when creating
 your own decoders, and you can edit the generated function to suit your needs.

 # Examples

 Dynamic data may come from various sources and so many different syntaxes could
 be used to describe or construct them. In these examples a pseudocode
 syntax is used to describe the data.

 ## Simple types

 This module defines decoders for simple data types such as [`string`](#string),
 [`int`](#int), [`float`](#float), [`bit_array`](#bit_array), and [`bool`](#bool).

 ```gleam
 // Data:
 // \"Hello, Joe!\"

 let result = decode.run(data, decode.string)
 assert result == Ok(\"Hello, Joe!\")
 ```

 ## Lists

 The [`list`](#list) decoder decodes `List`s. To use it you must construct it by
 passing in another decoder into the `list` function, which is the decoder that
 is to be used for the elements of the list, type checking both the list and its
 elements.

 ```gleam
 // Data:
 // [1, 2, 3, 4]

 let result = decode.run(data, decode.list(decode.int))
 assert result == Ok([1, 2, 3, 4])
 ```

 On Erlang this decoder can decode from lists, and on JavaScript it can
 decode from lists as well as JavaScript arrays.

 ## Options

 The [`optional`](#optional) decoder is used to decode values that may or may not
 be present. In other environments these might be called \"nullable\" values.

 Like the `list` decoder, the `optional` decoder takes another decoder,
 which is used to decode the value if it is present.

 ```gleam
 // Data:
 // 12.45

 let result = decode.run(data, decode.optional(decode.float))
 assert result == Ok(option.Some(12.45))
 ```
 ```gleam
 // Data:
 // null

 let result = decode.run(data, decode.optional(decode.int))
 assert result == Ok(option.None)
 ```

 This decoder knows how to handle multiple different runtime representations of
 absent values, including `Nil`, `None`, `null`, and `undefined`.

 ## Dicts

 The [`dict`](#dict) decoder decodes `Dicts` and contains two other decoders, one
 for the keys, one for the values.

 ```gleam
 // Data:
 // { \"Lucy\" -> 10, \"Nubi\" -> 20 }

 let result = decode.run(data, decode.dict(decode.string, decode.int))
 assert result
   == Ok(
     dict.from_list([
       #(\"Lucy\", 10),
       #(\"Nubi\", 20),
     ]),
   )
 ```

 ## Indexing objects

 The [`at`](#at) decoder can be used to decode a value that is nested within
 key-value containers such as Gleam dicts, Erlang maps, or JavaScript objects.

 ```gleam
 // Data:
 // { \"one\" -> { \"two\" -> 123 } }

 let result = decode.run(data, decode.at([\"one\", \"two\"], decode.int))
 assert result == Ok(123)
 ```

 ## Indexing arrays

 If you use ints as keys then the [`at`](#at) decoder can be used to index into
 array-like containers such as Gleam or Erlang tuples, or JavaScript arrays.

 ```gleam
 // Data:
 // [\"one\", \"two\", \"three\"]

 let result = decode.run(data, decode.at([1], decode.string))
 assert result == Ok(\"two\")
 ```

 ## Records

 Decoding records from dynamic data is more complex and requires combining a
 decoder for each field and a special constructor that builds your records with
 the decoded field values.

 ```gleam
 // Data:
 // {
 //   \"score\" -> 180,
 //   \"name\" -> \"Mel Smith\",
 //   \"is-admin\" -> false,
 //   \"enrolled\" -> true,
 //   \"colour\" -> \"Red\",
 // }

 let decoder = {
   use name <- decode.field(\"name\", decode.string)
   use score <- decode.field(\"score\", decode.int)
   use colour <- decode.field(\"colour\", decode.string)
   use enrolled <- decode.field(\"enrolled\", decode.bool)
   decode.success(Player(name:, score:, colour:, enrolled:))
 }

 let result = decode.run(data, decoder)
 assert result == Ok(Player(\"Mel Smith\", 180, \"Red\", True))
 ```

 ## Enum variants

 Imagine you have a custom type where all the variants do not contain any values.

 ```gleam
 pub type PocketMonsterType {
   Fire
   Water
   Grass
   Electric
 }
 ```

 You might choose to encode these variants as strings, `\"fire\"` for `Fire`,
 `\"water\"` for `Water`, and so on. To decode them you'll need to decode the dynamic
 data as a string, but then you'll need to decode it further still as not all
 strings are valid values for the enum. This can be done with the `then`
 function, which enables running a second decoder after the first one
 succeeds.

 ```gleam
 let decoder = {
   use decoded_string <- decode.then(decode.string)
   case decoded_string {
     // Return succeeding decoders for valid strings
     \"fire\" -> decode.success(Fire)
     \"water\" -> decode.success(Water)
     \"grass\" -> decode.success(Grass)
     \"electric\" -> decode.success(Electric)
     // Return a failing decoder for any other strings
     _ -> decode.failure(Fire, expected: \"PocketMonsterType\")
   }
 }

 let result = decode.run(dynamic.string(\"water\"), decoder)
 assert result == Ok(Water)

 let result = decode.run(dynamic.string(\"wobble\"), decoder)
 assert result == Error([DecodeError(\"PocketMonsterType\", \"String\", [])])
 ```

 ## Record variants

 Decoding type variants that contain other values is done by combining the
 techniques from the \"enum variants\" and \"records\" examples. Imagine you have
 this custom type that you want to decode:

 ```gleam
 pub type PocketMonsterPerson {
   Trainer(name: String, badge_count: Int)
   GymLeader(name: String, speciality: PocketMonsterType)
 }
 ```
 And you would like to be able to decode these from dynamic data like this:
 ```erlang
 {
   \"type\" -> \"trainer\",
   \"name\" -> \"Ash\",
   \"badge-count\" -> 1,
 }
 ```
 ```erlang
 {
   \"type\" -> \"gym-leader\",
   \"name\" -> \"Misty\",
   \"speciality\" -> \"water\",
 }
 ```

 Notice how both documents have a `\"type\"` field, which is used to indicate which
 variant the data is for.

 First, define decoders for each of the variants:

 ```gleam
 let trainer_decoder = {
   use name <- decode.field(\"name\", decode.string)
   use badge_count <- decode.field(\"badge-count\", decode.int)
   decode.success(Trainer(name, badge_count))
 }

 let gym_leader_decoder = {
   use name <- decode.field(\"name\", decode.string)
   use speciality <- decode.field(\"speciality\", pocket_monster_type_decoder)
   decode.success(GymLeader(name, speciality))
 }
 ```

 A third decoder can be used to extract and decode the `\"type\"` field, and the
 expression can evaluate to whichever decoder is suitable for the document.

 ```gleam
 // Data:
 // {
 //   \"type\" -> \"gym-leader\",
 //   \"name\" -> \"Misty\",
 //   \"speciality\" -> \"water\",
 // }

 let decoder = {
   use tag <- decode.field(\"type\", decode.string)
   case tag {
     \"gym-leader\" -> gym_leader_decoder
     _ -> trainer_decoder
   }
 }

 let result = decode.run(data, decoder)
 assert result == Ok(GymLeader(\"Misty\", Water))
 ```").

-type decode_error() :: {decode_error, binary(), binary(), list(binary())}.

-opaque decoder(BVO) :: {decoder, fun((gleam@dynamic:dynamic_()) -> {BVO, list(decode_error())})}.

-file("src/gleam/dynamic/decode.gleam", 757).
-spec decode_dynamic(gleam@dynamic:dynamic_()) -> {gleam@dynamic:dynamic_(), list(decode_error())}.
decode_dynamic(Data) ->
    {Data, []}.

-file("src/gleam/dynamic/decode.gleam", 371).
-spec run(gleam@dynamic:dynamic_(), decoder(BVW)) -> {ok, BVW} | {error, list(decode_error())}.
-doc(~" Run a decoder on a `Dynamic` value, decoding the value if it is of the
 desired type, or returning errors.

 ## Examples

 ```gleam
 let decoder = {
   use name <- decode.field(\"name\", decode.string)
   use email <- decode.field(\"email\", decode.string)
   decode.success(SignUp(name: name, email: email))
 }

 decode.run(data, decoder)
 ```
").
run(Data, Decoder) ->
    {Maybe_invalid_data, Errors} = (erlang:element(2, Decoder))(Data),
    case Errors of
        [] ->
            {ok, Maybe_invalid_data};

        [_ | _] ->
            {error, Errors}
    end.

-file("src/gleam/dynamic/decode.gleam", 632).
-spec run_dynamic_function(gleam@dynamic:dynamic_(), binary(), fun((gleam@dynamic:dynamic_()) -> {ok, BXR} | {error, BXR})) -> {BXR, list(decode_error())}.
run_dynamic_function(Data, Name, F) ->
    case F(Data) of
        {ok, Data@1} ->
            {Data@1, []};

        {error, Placeholder} ->
            {Placeholder, [{decode_error, Name, gleam_stdlib:classify_dynamic(Data), []}]}
    end.

-file("src/gleam/dynamic/decode.gleam", 738).
-spec decode_float(gleam@dynamic:dynamic_()) -> {float(), list(decode_error())}.
decode_float(Data) ->
    run_dynamic_function(Data, ~"Float", fun gleam_stdlib:float/1).

-file("src/gleam/dynamic/decode.gleam", 917).
-spec map(decoder(BZU), fun((BZU) -> BZW)) -> decoder(BZW).
-doc(~" Apply a transformation function to any value decoded by the decoder.

 ## Examples

 ```gleam
 let decoder = decode.int |> decode.map(int.to_string)
 let result = decode.run(dynamic.int(1000), decoder)
 assert result == Ok(\"1000\")
 ```
").
map(Decoder, Transformer) ->
    {decoder, fun(D) ->
        {Data, Errors} = (erlang:element(2, Decoder))(D),
        {Transformer(Data), Errors}
    end}.

-file("src/gleam/dynamic/decode.gleam", 712).
-spec decode_int(gleam@dynamic:dynamic_()) -> {integer(), list(decode_error())}.
decode_int(Data) ->
    run_dynamic_function(Data, ~"Int", fun gleam_stdlib:int/1).

-file("src/gleam/dynamic/decode.gleam", 772).
-spec decode_bit_array(gleam@dynamic:dynamic_()) -> {bitstring(), list(decode_error())}.
decode_bit_array(Data) ->
    run_dynamic_function(Data, ~"BitArray", fun gleam_stdlib:bit_array/1).

-file("src/gleam/dynamic/decode.gleam", 661).
-spec dynamic_string(gleam@dynamic:dynamic_()) -> {ok, binary()} | {error, binary()}.
dynamic_string(Data) ->
    case gleam_stdlib:bit_array(Data) of
        {ok, Data@1} ->
            case gleam@bit_array:to_string(Data@1) of
                {ok, String} ->
                    {ok, String};

                {error, _} ->
                    {error, ~""}
            end;

        {error, _} ->
            {error, ~""}
    end.

-file("src/gleam/dynamic/decode.gleam", 656).
-spec decode_string(gleam@dynamic:dynamic_()) -> {binary(), list(decode_error())}.
decode_string(Data) ->
    run_dynamic_function(Data, ~"String", fun dynamic_string/1).

-file("src/gleam/dynamic/decode.gleam", 1007).
-spec run_decoders(gleam@dynamic:dynamic_(), {CAQ, list(decode_error())}, list(decoder(CAQ))) -> {CAQ, list(decode_error())}.
run_decoders(Data, Failure, Decoders) ->
    case Decoders of
        [] ->
            Failure;

        [Decoder | Decoders@1] ->
            {_, Errors} = Layer = (erlang:element(2, Decoder))(Data),
            case Errors of
                [] ->
                    Layer;

                [_ | _] ->
                    run_decoders(Data, Failure, Decoders@1)
            end
    end.

-file("src/gleam/dynamic/decode.gleam", 994).
-spec one_of(decoder(CAL), list(decoder(CAL))) -> decoder(CAL).
-doc(~" Create a new decoder from several other decoders. Each of the inner
 decoders is run in turn, and the value from the first to succeed is used.

 If no decoder succeeds then the errors from the first decoder are used.
 If you wish for different errors then you may wish to use the
 `collapse_errors` or `map_errors` functions.

 ## Examples

 ```gleam
 let decoder =
   decode.one_of(decode.string, or: [
     decode.int |> decode.map(int.to_string),
     decode.float |> decode.map(float.to_string),
   ])
 assert decode.run(dynamic.int(1000), decoder) == Ok(\"1000\")
 ```
").
one_of(First, Alternatives) ->
    {decoder, fun(Dynamic_data) ->
        {_, Errors} = Layer = (erlang:element(2, First))(Dynamic_data),
        case Errors of
            [] ->
                Layer;

            [_ | _] ->
                run_decoders(Dynamic_data, Layer, Alternatives)
        end
    end}.

-file("src/gleam/dynamic/decode.gleam", 468).
-spec path_segment_to_string(gleam@dynamic:dynamic_()) -> binary().
path_segment_to_string(Key) ->
    Decoder = one_of({decoder, fun decode_string/1}, [begin
        _pipe = {decoder, fun decode_int/1},
        map(_pipe, fun erlang:integer_to_binary/1)
    end, begin
        _pipe@1 = {decoder, fun decode_float/1},
        map(_pipe@1, fun gleam_stdlib:float_to_string/1)
    end]),
    case run(Key, Decoder) of
        {ok, Key@1} ->
            Key@1;

        {error, _} ->
            <<<<"<"/utf8, (gleam_stdlib:classify_dynamic(Key))/binary>>/binary, ">"/utf8>>
    end.

-file("src/gleam/dynamic/decode.gleam", 456).
-spec push_path({BWS, list(decode_error())}, list(any())) -> {BWS, list(decode_error())}.
push_path(Layer, Path) ->
    Path@1 = gleam@list:map(Path, fun(Key) ->
        _pipe = Key,
        _pipe@1 = gleam_stdlib:identity(_pipe),
        path_segment_to_string(_pipe@1)
    end),
    Errors = gleam@list:map(erlang:element(2, Layer), fun(Error) ->
        {decode_error, erlang:element(2, Error), erlang:element(3, Error), lists:append(Path@1, erlang:element(4, Error))}
    end),
    {erlang:element(1, Layer), Errors}.

-file("src/gleam/dynamic/decode.gleam", 794).
-spec list(decoder(BYJ)) -> decoder(list(BYJ)).
-doc(~" A decoder that decodes lists where all elements are decoded with a given
 decoder.

 ## Examples

 ```gleam
 let result =
   [1, 2, 3]
   |> list.map(dynamic.int)
   |> dynamic.list
   |> decode.run(decode.list(of: decode.int))
 assert result == Ok([1, 2, 3])
 ```
").
list(Inner) ->
    {decoder, fun(Data) ->
        gleam_stdlib:list(Data, erlang:element(2, Inner), fun(P, K) ->
            push_path(P, [K])
        end, 0, [])
    end}.

-file("src/gleam/dynamic/decode.gleam", 420).
-spec index(list(BWG), list(BWG), fun((gleam@dynamic:dynamic_()) -> {BWJ, list(decode_error())}), gleam@dynamic:dynamic_(), fun((gleam@dynamic:dynamic_(), list(BWG)) -> {BWJ, list(decode_error())})) -> {BWJ, list(decode_error())}.
index(Path, Position, Inner, Data, Handle_miss) ->
    case Path of
        [] ->
            _pipe = Data,
            _pipe@1 = Inner(_pipe),
            push_path(_pipe@1, lists:reverse(Position));

        [Key | Path@1] ->
            case gleam_stdlib:index(Data, Key) of
                {ok, {some, Data@1}} ->
                    index(Path@1, [Key | Position], Inner, Data@1, Handle_miss);

                {ok, none} ->
                    Handle_miss(Data, [Key | Position]);

                {error, Kind} ->
                    {Default, _} = Inner(Data),
                    _pipe@2 = {Default, [{decode_error, Kind, gleam_stdlib:classify_dynamic(Data), []}]},
                    push_path(_pipe@2, lists:reverse(Position))
            end
    end.

-file("src/gleam/dynamic/decode.gleam", 339).
-spec subfield(list(any()), decoder(BVR), fun((BVR) -> decoder(BVT))) -> decoder(BVT).
-doc(~" The same as [`field`](#field), except taking a path to the value rather
 than a field name.

 This function will index into dictionaries with any key type, and if the key is
 an int then it'll also index into Erlang tuples and JavaScript arrays, and
 the first eight elements of Gleam lists.

 ## Examples

 ```gleam
 let data =
   dynamic.properties([
     #(
       dynamic.string(\"data\"),
       dynamic.properties([
         #(dynamic.string(\"email\"), dynamic.string(\"lucy@example.com\")),
         #(dynamic.string(\"name\"), dynamic.string(\"Lucy\")),
       ]),
     ),
   ])

 let decoder = {
   use name <- decode.subfield([\"data\", \"name\"], decode.string)
   use email <- decode.subfield([\"data\", \"email\"], decode.string)
   decode.success(SignUp(name: name, email: email))
 }
 let result = decode.run(data, decoder)
 assert result == Ok(SignUp(name: \"Lucy\", email: \"lucy@example.com\"))
 ```
").
subfield(Field_path, Field_decoder, Next) ->
    {decoder, fun(Data) ->
        {Out, Errors1} = index(Field_path, [], erlang:element(2, Field_decoder), Data, fun(Data@1, Position) ->
            {Default, _} = (erlang:element(2, Field_decoder))(Data@1),
            _pipe = {Default, [{decode_error, ~"Field", ~"Nothing", []}]},
            push_path(_pipe, lists:reverse(Position))
        end),
        {Out@1, Errors2} = (erlang:element(2, Next(Out)))(Data),
        {Out@1, lists:append(Errors1, Errors2)}
    end}.

-file("src/gleam/dynamic/decode.gleam", 410).
-spec at(list(any()), decoder(BWD)) -> decoder(BWD).
-doc(~" A decoder that decodes a value that is nested within other values. For
 example, decoding a value that is within some deeply nested JSON objects.

 This function will index into dictionaries with any key type, and if the key is
 an int then it'll also index into Erlang tuples and JavaScript arrays, and
 the first eight elements of Gleam lists.

 ## Examples

 ```gleam
 let decoder = decode.at([\"one\", \"two\"], decode.int)

 let data =
   dynamic.properties([
     #(
       dynamic.string(\"one\"),
       dynamic.properties([
         #(dynamic.string(\"two\"), dynamic.int(1000)),
       ]),
     ),
   ])

 assert decode.run(data, decoder) == Ok(1000)
 ```

 ```gleam
 assert dynamic.nil()
   |> decode.run(decode.optional(decode.int))
   == Ok(option.None)
 ```
").
at(Path, Inner) ->
    {decoder, fun(Data) ->
        index(Path, [], erlang:element(2, Inner), Data, fun(Data@1, Position) ->
            {Default, _} = (erlang:element(2, Inner))(Data@1),
            _pipe = {Default, [{decode_error, ~"Field", ~"Nothing", []}]},
            push_path(_pipe, lists:reverse(Position))
        end)
    end}.

-file("src/gleam/dynamic/decode.gleam", 501).
-spec success(BWX) -> decoder(BWX).
-doc(~" Finalise a decoder having successfully extracted a value.

 ## Examples

 ```gleam
 let data =
   dynamic.properties([
     #(dynamic.string(\"email\"), dynamic.string(\"lucy@example.com\")),
     #(dynamic.string(\"name\"), dynamic.string(\"Lucy\")),
   ])

 let decoder = {
   use name <- decode.field(\"name\", string)
   use email <- decode.field(\"email\", string)
   decode.success(SignUp(name: name, email: email))
 }

 let result = decode.run(data, decoder)
 assert result == Ok(SignUp(name: \"Lucy\", email: \"lucy@example.com\"))
 ```
").
success(Data) ->
    {decoder, fun(_) ->
        {Data, []}
    end}.

-file("src/gleam/dynamic/decode.gleam", 507).
-spec decode_error(binary(), gleam@dynamic:dynamic_()) -> list(decode_error()).
-doc(~" Construct a decode error for some unexpected dynamic data.
").
decode_error(Expected, Found) ->
    [{decode_error, Expected, gleam_stdlib:classify_dynamic(Found), []}].

-file("src/gleam/dynamic/decode.gleam", 547).
-spec field(any(), decoder(BXB), fun((BXB) -> decoder(BXD))) -> decoder(BXD).
-doc(~" Run a decoder on a field of a `Dynamic` value, decoding the value if it is
 of the desired type, or returning errors. An error is returned if there is
 no field for the specified key.

 This function will index into dictionaries with any key type, and if the key is
 an int then it'll also index into Erlang tuples and JavaScript arrays, and
 the first eight elements of Gleam lists.

 ## Examples

 ```gleam
 let data =
   dynamic.properties([
     #(dynamic.string(\"email\"), dynamic.string(\"lucy@example.com\")),
     #(dynamic.string(\"name\"), dynamic.string(\"Lucy\")),
   ])

 let decoder = {
   use name <- decode.field(\"name\", string)
   use email <- decode.field(\"email\", string)
   decode.success(SignUp(name: name, email: email))
 }

 let result = decode.run(data, decoder)
 assert result == Ok(SignUp(name: \"Lucy\", email: \"lucy@example.com\"))
 ```

 If you wish to decode a value that is more deeply nested within the dynamic
 data, see [`subfield`](#subfield) and [`at`](#at).

 If you wish to return a default in the event that a field is not present,
 see [`optional_field`](#optional_field) and / [`optionally_at`](#optionally_at).
").
field(Field_name, Field_decoder, Next) ->
    subfield([Field_name], Field_decoder, Next).

-file("src/gleam/dynamic/decode.gleam", 581).
-spec optional_field(any(), BXH, decoder(BXH), fun((BXH) -> decoder(BXJ))) -> decoder(BXJ).
-doc(~" Run a decoder on a field of a `Dynamic` value, decoding the value if it is
 of the desired type, or returning errors. The given default value is
 returned if there is no field for the specified key.

 This function will index into dictionaries with any key type, and if the key is
 an int then it'll also index into Erlang tuples and JavaScript arrays, and
 the first eight elements of Gleam lists.

 ## Examples

 ```gleam
 let data =
   dynamic.properties([
     #(dynamic.string(\"name\"), dynamic.string(\"Lucy\")),
   ])

 let decoder = {
   use name <- decode.field(\"name\", string)
   use email <- decode.optional_field(\"email\", \"n/a\", string)
   decode.success(SignUp(name: name, email: email))
 }

 let result = decode.run(data, decoder)
 assert result == Ok(SignUp(name: \"Lucy\", email: \"n/a\"))
 ```
").
optional_field(Key, Default, Field_decoder, Next) ->
    {decoder, fun(Data) ->
        {Out, Errors1} = begin
            _pipe = case gleam_stdlib:index(Data, Key) of
                {ok, {some, Data@1}} ->
                    (erlang:element(2, Field_decoder))(Data@1);

                {ok, none} ->
                    {Default, []};

                {error, Kind} ->
                    {Default, [{decode_error, Kind, gleam_stdlib:classify_dynamic(Data), []}]}
            end,
            push_path(_pipe, [Key])
        end,
        {Out@1, Errors2} = (erlang:element(2, Next(Out)))(Data),
        {Out@1, lists:append(Errors1, Errors2)}
    end}.

-file("src/gleam/dynamic/decode.gleam", 622).
-spec optionally_at(list(any()), BXO, decoder(BXO)) -> decoder(BXO).
-doc(~" A decoder that decodes a value that is nested within other values. For
 example, decoding a value that is within some deeply nested JSON objects.

 This function will index into dictionaries with any key type, and if the key is
 an int then it'll also index into Erlang tuples and JavaScript arrays, and
 the first eight elements of Gleam lists.

 ## Examples

 ```gleam
 let decoder = decode.optionally_at([\"one\", \"two\"], 100, decode.int)

 let data =
   dynamic.properties([
     #(dynamic.string(\"one\"), dynamic.properties([])),
   ])

 assert decode.run(data, decoder) == Ok(100)
 ```
").
optionally_at(Path, Default, Inner) ->
    {decoder, fun(Data) ->
        index(Path, [], erlang:element(2, Inner), Data, fun(_, _) ->
            {Default, []}
        end)
    end}.

-file("src/gleam/dynamic/decode.gleam", 683).
-spec decode_bool(gleam@dynamic:dynamic_()) -> {boolean(), list(decode_error())}.
decode_bool(Data) ->
    case gleam_stdlib:identity(true) =:= Data of
        true ->
            {true, []};

        false ->
            case gleam_stdlib:identity(false) =:= Data of
                true ->
                    {false, []};

                false ->
                    {false, decode_error(~"Bool", Data)}
            end
    end.

-file("src/gleam/dynamic/decode.gleam", 846).
-spec fold_dict({gleam@dict:dict(BZC, BZD), list(decode_error())}, gleam@dynamic:dynamic_(), gleam@dynamic:dynamic_(), fun((gleam@dynamic:dynamic_()) -> {BZC, list(decode_error())}), fun((gleam@dynamic:dynamic_()) -> {BZD, list(decode_error())})) -> {gleam@dict:dict(BZC, BZD), list(decode_error())}.
fold_dict(Acc, Key, Value, Key_decoder, Value_decoder) ->
    case Key_decoder(Key) of
        {Key_decoded, []} ->
            case Value_decoder(Value) of
                {Value@1, []} ->
                    Dict = gleam@dict:insert(erlang:element(1, Acc), Key_decoded, Value@1),
                    {Dict, erlang:element(2, Acc)};

                {_, Errors} ->
                    Key_identifier = path_segment_to_string(Key),
                    push_path({maps:new(), Errors}, [Key_identifier])
            end;

        {_, Errors@1} ->
            push_path({maps:new(), Errors@1}, [~"keys"])
    end.

-file("src/gleam/dynamic/decode.gleam", 826).
-spec dict(decoder(BYV), decoder(BYX)) -> decoder(gleam@dict:dict(BYV, BYX)).
-doc(~" A decoder that decodes dicts where all keys and values are decoded with
 given decoders.

 ## Examples

 ```gleam
 let values =
   dynamic.properties([
     #(dynamic.string(\"one\"), dynamic.int(1)),
     #(dynamic.string(\"two\"), dynamic.int(2)),
   ])

 let result = decode.run(values, decode.dict(decode.string, decode.int))
 assert result == Ok(values)
 ```
").
dict(Key, Value) ->
    {decoder, fun(Data) ->
        case gleam_stdlib:dict(Data) of
            {error, _} ->
                {maps:new(), decode_error(~"Dict", Data)};

            {ok, Dict} ->
                gleam@dict:fold(Dict, {maps:new(), []}, fun(A, K, V) ->
                    case erlang:element(2, A) of
                        [] ->
                            fold_dict(A, K, V, erlang:element(2, Key), erlang:element(2, Value));

                        [_ | _] ->
                            A
                    end
                end)
        end
    end}.

-file("src/gleam/dynamic/decode.gleam", 895).
-spec optional(decoder(BZQ)) -> decoder(gleam@option:option(BZQ)).
-doc(~" A decoder that decodes nullable values of a type decoded by with a given
 decoder.

 This function can handle common representations of null on all runtimes, such as
 `nil`, `null`, and `undefined` on Erlang, and `undefined` and `null` on
 JavaScript.

 ## Examples

 ```gleam
 let result = decode.run(dynamic.int(100), decode.optional(decode.int))
 assert result == Ok(option.Some(100))
 ```

 ```gleam
 let result = decode.run(dynamic.nil(), decode.optional(decode.int))
 assert result == Ok(option.None)
 ```
").
optional(Inner) ->
    {decoder, fun(Data) ->
        case gleam_stdlib:is_null(Data) of
            true ->
                {none, []};

            false ->
                {Data@1, Errors} = (erlang:element(2, Inner))(Data),
                {{some, Data@1}, Errors}
        end
    end}.

-file("src/gleam/dynamic/decode.gleam", 926).
-spec map_errors(decoder(BZY), fun((list(decode_error())) -> list(decode_error()))) -> decoder(BZY).
-doc(~" Apply a transformation function to any errors returned by the decoder.
").
map_errors(Decoder, Transformer) ->
    {decoder, fun(D) ->
        {Data, Errors} = (erlang:element(2, Decoder))(D),
        {Data, Transformer(Errors)}
    end}.

-file("src/gleam/dynamic/decode.gleam", 950).
-spec collapse_errors(decoder(CAD), binary()) -> decoder(CAD).
-doc(~" Replace all errors produced by a decoder with one single error for a named
 expected type.

 This function may be useful if you wish to simplify errors before
 presenting them to a user, particularly when using the `one_of` function.

 ## Examples

 ```gleam
 let decoder = decode.string |> decode.collapse_errors(\"MyThing\")
 let result = decode.run(dynamic.int(1000), decoder)
 assert result == Error([DecodeError(\"MyThing\", \"Int\", [])])
 ```
").
collapse_errors(Decoder, Name) ->
    {decoder, fun(Dynamic_data) ->
        {Data, Errors} = Layer = (erlang:element(2, Decoder))(Dynamic_data),
        case Errors of
            [] ->
                Layer;

            [_ | _] ->
                {Data, decode_error(Name, Dynamic_data)}
        end
    end}.

-file("src/gleam/dynamic/decode.gleam", 964).
-spec then(decoder(CAG), fun((CAG) -> decoder(CAI))) -> decoder(CAI).
-doc(~" Create a new decoder based upon the value of a previous decoder.

 This may be useful to run one previous decoder to use in further decoding.
").
then(Decoder, Next) ->
    {decoder, fun(Dynamic_data) ->
        {Data, Errors} = (erlang:element(2, Decoder))(Dynamic_data),
        Decoder@1 = Next(Data),
        {Data@1, _} = Layer = (erlang:element(2, Decoder@1))(Dynamic_data),
        case Errors of
            [] ->
                Layer;

            [_ | _] ->
                {Data@1, Errors}
        end
    end}.

-file("src/gleam/dynamic/decode.gleam", 1040).
-spec failure(CAV, binary()) -> decoder(CAV).
-doc(~" Define a decoder that always fails.

 The first parameter is a \"placeholder\" value, which is some default value that the
 decoder uses internally in place of the value that would have been produced
 if the decoder was successful. It doesn't matter what this value is, it is
 never returned by the decoder or shown to the user, so pick some arbitrary
 value. If it is an int you might pick `0`, if it is a list you might pick
 `[]`.

 The second parameter is the name of the type that has failed to decode.

 ```gleam
 decode.failure(User(name: \"\", score: 0, tags: []), expected: \"User\")
 ```
").
failure(Placeholder, Name) ->
    {decoder, fun(D) ->
        {Placeholder, decode_error(Name, D)}
    end}.

-file("src/gleam/dynamic/decode.gleam", 1081).
-spec new_primitive_decoder(binary(), fun((gleam@dynamic:dynamic_()) -> {ok, CAX} | {error, CAX})) -> decoder(CAX).
-doc(~" Create a decoder for a new data type from a decoding function.

 This function is used for new primitive types. For example, you might
 define a decoder for Erlang's pid type.

 A default \"placeholder\" value is also required to make a decoder. When this
 decoder is used as part of a larger decoder this placeholder value is used
 so that the rest of the decoder can continue to run and
 collect all decoding errors. It doesn't matter what this value is, it is
 never returned by the decoder or shown to the user, so pick some arbitrary
 value. If it is an int you might pick `0`, if it is a list you might pick
 `[]`.

 If you were to make a decoder for the `Int` type (rather than using the
 built-in `Int` decoder) you would define it like so:

 ```gleam
 pub fn int_decoder() -> decode.Decoder(Int) {
   let default = \"\"
   decode.new_primitive_decoder(\"Int\", int_from_dynamic)
 }

 @external(erlang, \"my_module\", \"int_from_dynamic\")
 fn int_from_dynamic(data: Int) -> Result(Int, Int)
 ```

 ```erlang
 -module(my_module).
 -export([int_from_dynamic/1]).

 int_from_dynamic(Data) ->
     case is_integer(Data) of
         true -> {ok, Data};
         false -> {error, 0}
     end.
 ```
").
new_primitive_decoder(Name, Decoding_function) ->
    {decoder, fun(D) ->
        case Decoding_function(D) of
            {ok, T} ->
                {T, []};

            {error, Placeholder} ->
                {Placeholder, [{decode_error, Name, gleam_stdlib:classify_dynamic(D), []}]}
        end
    end}.

-file("src/gleam/dynamic/decode.gleam", 1118).
-spec recursive(fun(() -> decoder(CBB))) -> decoder(CBB).
-doc(~" Create a decoder that can refer to itself, useful for decoding deeply
 nested data.

 Attempting to create a recursive decoder without this function could result
 in an infinite loop. If you are using `field` or other `use`able functions
 then you may not need to use this function.

 ## Examples

 ```gleam
 type Nested {
   Nested(List(Nested))
   Value(String)
 }

 fn nested_decoder() -> decode.Decoder(Nested) {
   use <- decode.recursive
   decode.one_of(decode.string |> decode.map(Value), [
     decode.list(nested_decoder()) |> decode.map(Nested),
   ])
 }
 ```
").
recursive(Inner) ->
    {decoder, fun(Data) ->
        Decoder = Inner(),
        (erlang:element(2, Decoder))(Data)
    end}.

