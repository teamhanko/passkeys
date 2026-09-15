-module(gleam@json).
-compile([no_auto_import, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-define(FILEPATH, "src/gleam/json.gleam").
-export([parse_bits/2, parse/2, to_string/1, to_string_tree/1, string/1, bool/1, int/1, float/1, null/0, nullable/2, object/1, preprocessed_array/1, array/2, dict/3]).
-export_type([json/0, decode_error/0]).

-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.

-type json() :: any().

-type decode_error() :: unexpected_end_of_input |
    {unexpected_byte, binary()} |
    {unexpected_sequence, binary()} |
    {unable_to_decode, list(gleam@dynamic@decode:decode_error())}.

-file("src/gleam/json.gleam", 88).
?DOC(
    " Decode a JSON bit string into dynamically typed data which can be decoded\n"
    " into typed data with the `gleam/dynamic` module.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > parse_bits(<<\"[1,2,3]\">>, decode.list(of: decode.int))\n"
    " Ok([1, 2, 3])\n"
    " ```\n"
    "\n"
    " ```gleam\n"
    " > parse_bits(<<\"[\">>, decode.list(of: decode.int))\n"
    " Error(UnexpectedEndOfInput)\n"
    " ```\n"
    "\n"
    " ```gleam\n"
    " > parse_bits(<<\"1\">>, decode.string)\n"
    " Error(UnableToDecode([decode.DecodeError(\"String\", \"Int\", [])])),\n"
    " ```\n"
).
-spec parse_bits(bitstring(), gleam@dynamic@decode:decoder(DNO)) -> {ok, DNO} |
    {error, decode_error()}.
parse_bits(Json, Decoder) ->
    gleam@result:'try'(
        gleam_json_ffi:decode(Json),
        fun(Dynamic_value) ->
            _pipe = gleam@dynamic@decode:run(Dynamic_value, Decoder),
            gleam@result:map_error(
                _pipe,
                fun(Field@0) -> {unable_to_decode, Field@0} end
            )
        end
    ).

-file("src/gleam/json.gleam", 47).
-spec do_parse(binary(), gleam@dynamic@decode:decoder(DNI)) -> {ok, DNI} |
    {error, decode_error()}.
do_parse(Json, Decoder) ->
    Bits = gleam_stdlib:identity(Json),
    parse_bits(Bits, Decoder).

-file("src/gleam/json.gleam", 39).
?DOC(
    " Decode a JSON string into dynamically typed data which can be decoded into\n"
    " typed data with the `gleam/dynamic` module.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > parse(\"[1,2,3]\", decode.list(of: decode.int))\n"
    " Ok([1, 2, 3])\n"
    " ```\n"
    "\n"
    " ```gleam\n"
    " > parse(\"[\", decode.list(of: decode.int))\n"
    " Error(UnexpectedEndOfInput)\n"
    " ```\n"
    "\n"
    " ```gleam\n"
    " > parse(\"1\", decode.string)\n"
    " Error(UnableToDecode([decode.DecodeError(\"String\", \"Int\", [])]))\n"
    " ```\n"
).
-spec parse(binary(), gleam@dynamic@decode:decoder(DNE)) -> {ok, DNE} |
    {error, decode_error()}.
parse(Json, Decoder) ->
    do_parse(Json, Decoder).

-file("src/gleam/json.gleam", 117).
?DOC(
    " Convert a JSON value into a string.\n"
    "\n"
    " Where possible prefer the `to_string_tree` function as it is faster than\n"
    " this function, and BEAM VM IO is optimised for sending `StringTree` data.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(array([1, 2, 3], of: int))\n"
    " \"[1,2,3]\"\n"
    " ```\n"
).
-spec to_string(json()) -> binary().
to_string(Json) ->
    gleam_json_ffi:json_to_string(Json).

-file("src/gleam/json.gleam", 140).
?DOC(
    " Convert a JSON value into a string tree.\n"
    "\n"
    " Where possible prefer this function to the `to_string` function as it is\n"
    " slower than this function, and BEAM VM IO is optimised for sending\n"
    " `StringTree` data.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string_tree(array([1, 2, 3], of: int))\n"
    " string_tree.from_string(\"[1,2,3]\")\n"
    " ```\n"
).
-spec to_string_tree(json()) -> gleam@string_tree:string_tree().
to_string_tree(Json) ->
    gleam_json_ffi:json_to_iodata(Json).

-file("src/gleam/json.gleam", 151).
?DOC(
    " Encode a string into JSON, using normal JSON escaping.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(string(\"Hello!\"))\n"
    " \"\\\"Hello!\\\"\"\n"
    " ```\n"
).
-spec string(binary()) -> json().
string(Input) ->
    gleam_json_ffi:string(Input).

-file("src/gleam/json.gleam", 168).
?DOC(
    " Encode a bool into JSON.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(bool(False))\n"
    " \"false\"\n"
    " ```\n"
).
-spec bool(boolean()) -> json().
bool(Input) ->
    gleam_json_ffi:bool(Input).

-file("src/gleam/json.gleam", 185).
?DOC(
    " Encode an int into JSON.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(int(50))\n"
    " \"50\"\n"
    " ```\n"
).
-spec int(integer()) -> json().
int(Input) ->
    gleam_json_ffi:int(Input).

-file("src/gleam/json.gleam", 202).
?DOC(
    " Encode a float into JSON.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(float(4.7))\n"
    " \"4.7\"\n"
    " ```\n"
).
-spec float(float()) -> json().
float(Input) ->
    gleam_json_ffi:float(Input).

-file("src/gleam/json.gleam", 219).
?DOC(
    " The JSON value null.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(null())\n"
    " \"null\"\n"
    " ```\n"
).
-spec null() -> json().
null() ->
    gleam_json_ffi:null().

-file("src/gleam/json.gleam", 241).
?DOC(
    " Encode an optional value into JSON, using null if it is the `None` variant.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(nullable(Some(50), of: int))\n"
    " \"50\"\n"
    " ```\n"
    "\n"
    " ```gleam\n"
    " > to_string(nullable(None, of: int))\n"
    " \"null\"\n"
    " ```\n"
).
-spec nullable(gleam@option:option(DNU), fun((DNU) -> json())) -> json().
nullable(Input, Inner_type) ->
    case Input of
        {some, Value} ->
            Inner_type(Value);

        none ->
            null()
    end.

-file("src/gleam/json.gleam", 260).
?DOC(
    " Encode a list of key-value pairs into a JSON object.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(object([\n"
    "   #(\"game\", string(\"Pac-Man\")),\n"
    "   #(\"score\", int(3333360)),\n"
    " ]))\n"
    " \"{\\\"game\\\":\\\"Pac-Mac\\\",\\\"score\\\":3333360}\"\n"
    " ```\n"
).
-spec object(list({binary(), json()})) -> json().
object(Entries) ->
    gleam_json_ffi:object(Entries).

-file("src/gleam/json.gleam", 292).
?DOC(
    " Encode a list of JSON values into a JSON array.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(preprocessed_array([int(1), float(2.0), string(\"3\")]))\n"
    " \"[1, 2.0, \\\"3\\\"]\"\n"
    " ```\n"
).
-spec preprocessed_array(list(json())) -> json().
preprocessed_array(From) ->
    gleam_json_ffi:array(From).

-file("src/gleam/json.gleam", 277).
?DOC(
    " Encode a list into a JSON array.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(array([1, 2, 3], of: int))\n"
    " \"[1, 2, 3]\"\n"
    " ```\n"
).
-spec array(list(DNY), fun((DNY) -> json())) -> json().
array(Entries, Inner_type) ->
    _pipe = Entries,
    _pipe@1 = gleam@list:map(_pipe, Inner_type),
    preprocessed_array(_pipe@1).

-file("src/gleam/json.gleam", 310).
?DOC(
    " Encode a Dict into a JSON object using the supplied functions to encode\n"
    " the keys and the values respectively.\n"
    "\n"
    " ## Examples\n"
    "\n"
    " ```gleam\n"
    " > to_string(dict(dict.from_list([ #(3, 3.0), #(4, 4.0)]), int.to_string, float)\n"
    " \"{\\\"3\\\": 3.0, \\\"4\\\": 4.0}\"\n"
    " ```\n"
).
-spec dict(
    gleam@dict:dict(DOC, DOD),
    fun((DOC) -> binary()),
    fun((DOD) -> json())
) -> json().
dict(Dict, Keys, Values) ->
    object(
        gleam@dict:fold(
            Dict,
            [],
            fun(Acc, K, V) -> [{Keys(K), Values(V)} | Acc] end
        )
    ).
