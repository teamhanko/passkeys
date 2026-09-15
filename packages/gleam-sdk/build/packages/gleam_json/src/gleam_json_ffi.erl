-module(gleam_json_ffi).

-export([
    decode/1, json_to_iodata/1, json_to_string/1, int/1, float/1, string/1,
    bool/1, null/0, array/1, object/1
]).

-if(?OTP_RELEASE < 27).
-define(bad_version, 
    error({erlang_otp_27_required, << "Insufficient Erlang/OTP version.

`gleam_json` uses the Erlang `json` module introduced in Erlang/OTP 27.
You are using Erlang/OTP "/utf8, (integer_to_binary(?OTP_RELEASE))/binary, "
Please upgrade your Erlang install or downgrade to `gleam_json` v1.0.1.
"/utf8>>})).

decode(_) -> ?bad_version.
json_to_iodata(_) -> ?bad_version.
json_to_string(_) -> ?bad_version.
int(_) -> ?bad_version.
float(_) -> ?bad_version.
string(_) -> ?bad_version.
bool(_) -> ?bad_version.
array(_) -> ?bad_version.
object(_) -> ?bad_version.
null()  -> ?bad_version.
-else.

decode(Json) ->
    try
        {ok, json:decode(Json)}
    catch
        error:unexpected_end -> {error, unexpected_end_of_input};
        error:{invalid_byte, Byte} -> {error, {unexpected_byte, hex(Byte)}};
        error:{unexpected_sequence, Byte} -> {error, {unexpected_sequence, Byte}}
    end.

hex(I) ->
    H = list_to_binary(integer_to_list(I, 16)),
    <<"0x"/utf8, H/binary>>.

json_to_iodata(Json) ->
    Json.

json_to_string(Json) when is_binary(Json) ->
    Json;
json_to_string(Json) when is_list(Json) ->
    list_to_binary(Json).

null() -> <<"null">>.
bool(true) -> <<"true">>;
bool(false) -> <<"false">>.
int(X) -> json:encode_integer(X).
float(X) -> json:encode_float(X).
string(X) -> json:encode_binary(X).

array([]) -> <<"[]">>;
array([First | Rest]) -> [$[, First | array_loop(Rest)].
array_loop([]) -> "]";
array_loop([Elem | Rest]) -> [$,, Elem | array_loop(Rest)].

object(List) -> encode_object([[$,, string(Key), $: | Value] || {Key, Value} <- List]).
encode_object([]) -> <<"{}">>;
encode_object([[_Comma | Entry] | Rest]) -> ["{", Entry, Rest, "}"].

-endif.
