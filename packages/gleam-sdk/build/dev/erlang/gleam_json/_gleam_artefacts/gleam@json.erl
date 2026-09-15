-module(gleam@json).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([parse_bits/2, parse/2, to_string/1, to_string_tree/1, string/1, bool/1, int/1, float/1, null/0, nullable/2, object/1, preprocessed_array/1, array/2, dict/3]).
-export_type([json/0, decode_error/0]).

-type json() :: any().

-type decode_error() :: unexpected_end_of_input | {unexpected_byte, binary()} | {unexpected_sequence, binary()} | {unable_to_decode, list(gleam@dynamic@decode:decode_error())}.

-file("src/gleam/json.gleam", 88).
-spec parse_bits(bitstring(), gleam@dynamic@decode:decoder(EPT)) -> {ok, EPT} | {error, decode_error()}.
-doc(~" Decode a JSON bit string into dynamically typed data which can be decoded
 into typed data with the `gleam/dynamic` module.

 ## Examples

 ```gleam
 > parse_bits(<<\"[1,2,3]\">>, decode.list(of: decode.int))
 Ok([1, 2, 3])
 ```

 ```gleam
 > parse_bits(<<\"[\">>, decode.list(of: decode.int))
 Error(UnexpectedEndOfInput)
 ```

 ```gleam
 > parse_bits(<<\"1\">>, decode.string)
 Error(UnableToDecode([decode.DecodeError(\"String\", \"Int\", [])])),
 ```
").
parse_bits(Json, Decoder) ->
    gleam@result:'try'(gleam_json_ffi:decode(Json), fun(Dynamic_value) ->
        _pipe = gleam@dynamic@decode:run(Dynamic_value, Decoder),
        gleam@result:map_error(_pipe, fun(_value) ->
            {unable_to_decode, _value}
        end)
    end).

-file("src/gleam/json.gleam", 47).
-spec do_parse(binary(), gleam@dynamic@decode:decoder(EPN)) -> {ok, EPN} | {error, decode_error()}.
do_parse(Json, Decoder) ->
    Bits = gleam_stdlib:identity(Json),
    parse_bits(Bits, Decoder).

-file("src/gleam/json.gleam", 39).
-spec parse(binary(), gleam@dynamic@decode:decoder(EPJ)) -> {ok, EPJ} | {error, decode_error()}.
-doc(~" Decode a JSON string into dynamically typed data which can be decoded into
 typed data with the `gleam/dynamic` module.

 ## Examples

 ```gleam
 > parse(\"[1,2,3]\", decode.list(of: decode.int))
 Ok([1, 2, 3])
 ```

 ```gleam
 > parse(\"[\", decode.list(of: decode.int))
 Error(UnexpectedEndOfInput)
 ```

 ```gleam
 > parse(\"1\", decode.string)
 Error(UnableToDecode([decode.DecodeError(\"String\", \"Int\", [])]))
 ```
").
parse(Json, Decoder) ->
    do_parse(Json, Decoder).

-file("src/gleam/json.gleam", 117).
-spec to_string(json()) -> binary().
-doc(~" Convert a JSON value into a string.

 Where possible prefer the `to_string_tree` function as it is faster than
 this function, and BEAM VM IO is optimised for sending `StringTree` data.

 ## Examples

 ```gleam
 > to_string(array([1, 2, 3], of: int))
 \"[1,2,3]\"
 ```
").
to_string(Json) ->
    gleam_json_ffi:json_to_string(Json).

-file("src/gleam/json.gleam", 140).
-spec to_string_tree(json()) -> gleam@string_tree:string_tree().
-doc(~" Convert a JSON value into a string tree.

 Where possible prefer this function to the `to_string` function as it is
 slower than this function, and BEAM VM IO is optimised for sending
 `StringTree` data.

 ## Examples

 ```gleam
 > to_string_tree(array([1, 2, 3], of: int))
 string_tree.from_string(\"[1,2,3]\")
 ```
").
to_string_tree(Json) ->
    gleam_json_ffi:json_to_iodata(Json).

-file("src/gleam/json.gleam", 151).
-spec string(binary()) -> json().
-doc(~" Encode a string into JSON, using normal JSON escaping.

 ## Examples

 ```gleam
 > to_string(string(\"Hello!\"))
 \"\\\"Hello!\\\"\"
 ```
").
string(Input) ->
    gleam_json_ffi:string(Input).

-file("src/gleam/json.gleam", 168).
-spec bool(boolean()) -> json().
-doc(~" Encode a bool into JSON.

 ## Examples

 ```gleam
 > to_string(bool(False))
 \"false\"
 ```
").
bool(Input) ->
    gleam_json_ffi:bool(Input).

-file("src/gleam/json.gleam", 185).
-spec int(integer()) -> json().
-doc(~" Encode an int into JSON.

 ## Examples

 ```gleam
 > to_string(int(50))
 \"50\"
 ```
").
int(Input) ->
    gleam_json_ffi:int(Input).

-file("src/gleam/json.gleam", 202).
-spec float(float()) -> json().
-doc(~" Encode a float into JSON.

 ## Examples

 ```gleam
 > to_string(float(4.7))
 \"4.7\"
 ```
").
float(Input) ->
    gleam_json_ffi:float(Input).

-file("src/gleam/json.gleam", 219).
-spec null() -> json().
-doc(~" The JSON value null.

 ## Examples

 ```gleam
 > to_string(null())
 \"null\"
 ```
").
null() ->
    gleam_json_ffi:null().

-file("src/gleam/json.gleam", 241).
-spec nullable(gleam@option:option(EPZ), fun((EPZ) -> json())) -> json().
-doc(~" Encode an optional value into JSON, using null if it is the `None` variant.

 ## Examples

 ```gleam
 > to_string(nullable(Some(50), of: int))
 \"50\"
 ```

 ```gleam
 > to_string(nullable(None, of: int))
 \"null\"
 ```
").
nullable(Input, Inner_type) ->
    case Input of
        {some, Value} ->
            Inner_type(Value);

        none ->
            null()
    end.

-file("src/gleam/json.gleam", 260).
-spec object(list({binary(), json()})) -> json().
-doc(~" Encode a list of key-value pairs into a JSON object.

 ## Examples

 ```gleam
 > to_string(object([
   #(\"game\", string(\"Pac-Man\")),
   #(\"score\", int(3333360)),
 ]))
 \"{\\\"game\\\":\\\"Pac-Mac\\\",\\\"score\\\":3333360}\"
 ```
").
object(Entries) ->
    gleam_json_ffi:object(Entries).

-file("src/gleam/json.gleam", 292).
-spec preprocessed_array(list(json())) -> json().
-doc(~" Encode a list of JSON values into a JSON array.

 ## Examples

 ```gleam
 > to_string(preprocessed_array([int(1), float(2.0), string(\"3\")]))
 \"[1, 2.0, \\\"3\\\"]\"
 ```
").
preprocessed_array(From) ->
    gleam_json_ffi:array(From).

-file("src/gleam/json.gleam", 277).
-spec array(list(EQD), fun((EQD) -> json())) -> json().
-doc(~" Encode a list into a JSON array.

 ## Examples

 ```gleam
 > to_string(array([1, 2, 3], of: int))
 \"[1, 2, 3]\"
 ```
").
array(Entries, Inner_type) ->
    _pipe = Entries,
    _pipe@1 = gleam@list:map(_pipe, Inner_type),
    preprocessed_array(_pipe@1).

-file("src/gleam/json.gleam", 310).
-spec dict(gleam@dict:dict(EQH, EQI), fun((EQH) -> binary()), fun((EQI) -> json())) -> json().
-doc(~" Encode a Dict into a JSON object using the supplied functions to encode
 the keys and the values respectively.

 ## Examples

 ```gleam
 > to_string(dict(dict.from_list([ #(3, 3.0), #(4, 4.0)]), int.to_string, float)
 \"{\\\"3\\\": 3.0, \\\"4\\\": 4.0}\"
 ```
").
dict(Dict, Keys, Values) ->
    object(gleam@dict:fold(Dict, [], fun(Acc, K, V) ->
        [{Keys(K), Values(V)} | Acc]
    end)).

