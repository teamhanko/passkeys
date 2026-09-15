import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string_tree.{type StringTree}

pub type Json

pub type DecodeError {
  UnexpectedEndOfInput
  UnexpectedByte(String)
  UnexpectedSequence(String)
  UnableToDecode(List(decode.DecodeError))
}

/// Decode a JSON string into dynamically typed data which can be decoded into
/// typed data with the `gleam/dynamic` module.
///
/// ## Examples
///
/// ```gleam
/// > parse("[1,2,3]", decode.list(of: decode.int))
/// Ok([1, 2, 3])
/// ```
///
/// ```gleam
/// > parse("[", decode.list(of: decode.int))
/// Error(UnexpectedEndOfInput)
/// ```
///
/// ```gleam
/// > parse("1", decode.string)
/// Error(UnableToDecode([decode.DecodeError("String", "Int", [])]))
/// ```
///
pub fn parse(
  from json: String,
  using decoder: decode.Decoder(t),
) -> Result(t, DecodeError) {
  do_parse(from: json, using: decoder)
}

@target(erlang)
fn do_parse(
  from json: String,
  using decoder: decode.Decoder(t),
) -> Result(t, DecodeError) {
  let bits = bit_array.from_string(json)
  parse_bits(bits, decoder)
}

@target(javascript)
fn do_parse(
  from json: String,
  using decoder: decode.Decoder(t),
) -> Result(t, DecodeError) {
  use dynamic_value <- result.try(decode_string(json))
  decode.run(dynamic_value, decoder)
  |> result.map_error(UnableToDecode)
}

@external(javascript, "../gleam_json_ffi.mjs", "decode")
fn decode_string(a: String) -> Result(Dynamic, DecodeError)

/// Decode a JSON bit string into dynamically typed data which can be decoded
/// into typed data with the `gleam/dynamic` module.
///
/// ## Examples
///
/// ```gleam
/// > parse_bits(<<"[1,2,3]">>, decode.list(of: decode.int))
/// Ok([1, 2, 3])
/// ```
///
/// ```gleam
/// > parse_bits(<<"[">>, decode.list(of: decode.int))
/// Error(UnexpectedEndOfInput)
/// ```
///
/// ```gleam
/// > parse_bits(<<"1">>, decode.string)
/// Error(UnableToDecode([decode.DecodeError("String", "Int", [])])),
/// ```
///
pub fn parse_bits(
  from json: BitArray,
  using decoder: decode.Decoder(t),
) -> Result(t, DecodeError) {
  use dynamic_value <- result.try(decode_to_dynamic(json))
  decode.run(dynamic_value, decoder)
  |> result.map_error(UnableToDecode)
}

@external(erlang, "gleam_json_ffi", "decode")
fn decode_to_dynamic(json: BitArray) -> Result(Dynamic, DecodeError) {
  case bit_array.to_string(json) {
    Ok(string) -> decode_string(string)
    Error(Nil) -> Error(UnexpectedByte(""))
  }
}

/// Convert a JSON value into a string.
///
/// Where possible prefer the `to_string_tree` function as it is faster than
/// this function, and BEAM VM IO is optimised for sending `StringTree` data.
///
/// ## Examples
///
/// ```gleam
/// > to_string(array([1, 2, 3], of: int))
/// "[1,2,3]"
/// ```
///
pub fn to_string(json: Json) -> String {
  do_to_string(json)
}

@external(erlang, "gleam_json_ffi", "json_to_string")
@external(javascript, "../gleam_json_ffi.mjs", "json_to_string")
fn do_to_string(a: Json) -> String

/// Convert a JSON value into a string tree.
///
/// Where possible prefer this function to the `to_string` function as it is
/// slower than this function, and BEAM VM IO is optimised for sending
/// `StringTree` data.
///
/// ## Examples
///
/// ```gleam
/// > to_string_tree(array([1, 2, 3], of: int))
/// string_tree.from_string("[1,2,3]")
/// ```
///
@external(erlang, "gleam_json_ffi", "json_to_iodata")
@external(javascript, "../gleam_json_ffi.mjs", "json_to_string")
pub fn to_string_tree(json: Json) -> StringTree

/// Encode a string into JSON, using normal JSON escaping.
///
/// ## Examples
///
/// ```gleam
/// > to_string(string("Hello!"))
/// "\"Hello!\""
/// ```
///
pub fn string(input: String) -> Json {
  do_string(input)
}

@external(erlang, "gleam_json_ffi", "string")
@external(javascript, "../gleam_json_ffi.mjs", "identity")
fn do_string(a: String) -> Json

/// Encode a bool into JSON.
///
/// ## Examples
///
/// ```gleam
/// > to_string(bool(False))
/// "false"
/// ```
///
pub fn bool(input: Bool) -> Json {
  do_bool(input)
}

@external(erlang, "gleam_json_ffi", "bool")
@external(javascript, "../gleam_json_ffi.mjs", "identity")
fn do_bool(a: Bool) -> Json

/// Encode an int into JSON.
///
/// ## Examples
///
/// ```gleam
/// > to_string(int(50))
/// "50"
/// ```
///
pub fn int(input: Int) -> Json {
  do_int(input)
}

@external(erlang, "gleam_json_ffi", "int")
@external(javascript, "../gleam_json_ffi.mjs", "identity")
fn do_int(a: Int) -> Json

/// Encode a float into JSON.
///
/// ## Examples
///
/// ```gleam
/// > to_string(float(4.7))
/// "4.7"
/// ```
///
pub fn float(input: Float) -> Json {
  do_float(input)
}

@external(erlang, "gleam_json_ffi", "float")
@external(javascript, "../gleam_json_ffi.mjs", "identity")
fn do_float(input input: Float) -> Json

/// The JSON value null.
///
/// ## Examples
///
/// ```gleam
/// > to_string(null())
/// "null"
/// ```
///
pub fn null() -> Json {
  do_null()
}

@external(erlang, "gleam_json_ffi", "null")
@external(javascript, "../gleam_json_ffi.mjs", "do_null")
fn do_null() -> Json

/// Encode an optional value into JSON, using null if it is the `None` variant.
///
/// ## Examples
///
/// ```gleam
/// > to_string(nullable(Some(50), of: int))
/// "50"
/// ```
///
/// ```gleam
/// > to_string(nullable(None, of: int))
/// "null"
/// ```
///
pub fn nullable(from input: Option(a), of inner_type: fn(a) -> Json) -> Json {
  case input {
    Some(value) -> inner_type(value)
    None -> null()
  }
}

/// Encode a list of key-value pairs into a JSON object.
///
/// ## Examples
///
/// ```gleam
/// > to_string(object([
///   #("game", string("Pac-Man")),
///   #("score", int(3333360)),
/// ]))
/// "{\"game\":\"Pac-Mac\",\"score\":3333360}"
/// ```
///
pub fn object(entries: List(#(String, Json))) -> Json {
  do_object(entries)
}

@external(erlang, "gleam_json_ffi", "object")
@external(javascript, "../gleam_json_ffi.mjs", "object")
fn do_object(entries entries: List(#(String, Json))) -> Json

/// Encode a list into a JSON array.
///
/// ## Examples
///
/// ```gleam
/// > to_string(array([1, 2, 3], of: int))
/// "[1, 2, 3]"
/// ```
///
pub fn array(from entries: List(a), of inner_type: fn(a) -> Json) -> Json {
  entries
  |> list.map(inner_type)
  |> preprocessed_array
}

/// Encode a list of JSON values into a JSON array.
///
/// ## Examples
///
/// ```gleam
/// > to_string(preprocessed_array([int(1), float(2.0), string("3")]))
/// "[1, 2.0, \"3\"]"
/// ```
///
pub fn preprocessed_array(from: List(Json)) -> Json {
  do_preprocessed_array(from)
}

@external(erlang, "gleam_json_ffi", "array")
@external(javascript, "../gleam_json_ffi.mjs", "array")
fn do_preprocessed_array(from from: List(Json)) -> Json

/// Encode a Dict into a JSON object using the supplied functions to encode
/// the keys and the values respectively.
///
/// ## Examples
///
/// ```gleam
/// > to_string(dict(dict.from_list([ #(3, 3.0), #(4, 4.0)]), int.to_string, float)
/// "{\"3\": 3.0, \"4\": 4.0}"
/// ```
///
pub fn dict(
  dict: Dict(k, v),
  keys: fn(k) -> String,
  values: fn(v) -> Json,
) -> Json {
  object(dict.fold(dict, [], fn(acc, k, v) { [#(keys(k), values(v)), ..acc] }))
}
