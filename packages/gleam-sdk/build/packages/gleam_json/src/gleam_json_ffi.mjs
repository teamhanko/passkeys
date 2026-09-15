import {
  Result$Ok,
  Result$Error,
  List$isNonEmpty,
  List$NonEmpty$first,
  List$NonEmpty$rest,
} from "./gleam.mjs";
import {
  DecodeError$UnexpectedByte,
  DecodeError$UnexpectedEndOfInput,
} from "./gleam/json.mjs";

export function json_to_string(json) {
  return JSON.stringify(json);
}

export function object(entries) {
  return Object.fromEntries(entries);
}

export function identity(x) {
  return x;
}

export function array(list) {
  const array = [];
  while (List$isNonEmpty(list)) {
    array.push(List$NonEmpty$first(list));
    list = List$NonEmpty$rest(list);
  }
  return array;
}

export function do_null() {
  return null;
}

export function decode(string) {
  try {
    const result = JSON.parse(string);
    return Result$Ok(result);
  } catch (err) {
    return Result$Error(getJsonDecodeError(err, string));
  }
}

export function getJsonDecodeError(stdErr, json) {
  if (isUnexpectedEndOfInput(stdErr)) return DecodeError$UnexpectedEndOfInput();
  return toUnexpectedByteError(stdErr, json);
}

/**
 * Matches unexpected end of input messages in:
 * - Chromium (edge, chrome, node)
 * - Spidermonkey (firefox)
 * - JavascriptCore (safari)
 *
 * Note that Spidermonkey and JavascriptCore will both incorrectly report some
 * UnexpectedByte errors as UnexpectedEndOfInput errors. For example:
 *
 * @example
 * // in JavascriptCore
 * JSON.parse('{"a"]: "b"})
 * // => JSON Parse error: Expected ':' before value
 *
 * JSON.parse('{"a"')
 * // => JSON Parse error: Expected ':' before value
 *
 * // in Chromium (correct)
 * JSON.parse('{"a"]: "b"})
 * // => Unexpected token ] in JSON at position 4
 *
 * JSON.parse('{"a"')
 * // => Unexpected end of JSON input
 */
function isUnexpectedEndOfInput(err) {
  const unexpectedEndOfInputRegex =
    /((unexpected (end|eof))|(end of data)|(unterminated string)|(json( parse error|\.parse)\: expected '(\:|\}|\])'))/i;
  return unexpectedEndOfInputRegex.test(err.message);
}

/**
 * Converts a SyntaxError to an UnexpectedByte error based on the JS runtime.
 *
 * For Chromium, the unexpected byte and position are reported by the runtime.
 *
 * For JavascriptCore, only the unexpected byte is reported by the runtime, so
 * there is no way to know which position that character is in unless we then
 * parse the string again ourselves. So instead, the position is reported as 0.
 *
 * For Spidermonkey, the position is reported by the runtime as a line and column number
 * and the unexpected byte is found using those coordinates.
 */
function toUnexpectedByteError(err, json) {
  let converters = [
    v8UnexpectedByteError,
    oldV8UnexpectedByteError,
    jsCoreUnexpectedByteError,
    spidermonkeyUnexpectedByteError,
  ];

  for (let converter of converters) {
    let result = converter(err, json);
    if (result) return result;
  }

  return DecodeError$UnexpectedByte("");
}

/**
 * Matches unexpected byte messages in:
 * - V8 (edge, chrome, node)
 *
 * Matches the character but not the position as this is no longer reported by
 * V8. Boo!
 */
function v8UnexpectedByteError(err) {
  const regex = /unexpected token '(.)', ".+" is not valid JSON/i;
  const match = regex.exec(err.message);
  if (!match) return null;
  const byte = toHex(match[1]);
  return DecodeError$UnexpectedByte(byte);
}

/**
 * Matches unexpected byte messages in:
 * - V8 (edge, chrome, node)
 *
 * No longer works in current versions of V8.
 *
 * Matches the character and its position.
 */
function oldV8UnexpectedByteError(err) {
  const regex = /unexpected token (.) in JSON at position (\d+)/i;
  const match = regex.exec(err.message);
  if (!match) return null;
  const byte = toHex(match[1]);
  return DecodeError$UnexpectedByte(byte);
}

/**
 * Matches unexpected byte messages in:
 * - Spidermonkey (firefox)
 *
 * Matches the position in a 2d grid only and not the character.
 */
function spidermonkeyUnexpectedByteError(err, json) {
  const regex =
    /(unexpected character|expected .*) at line (\d+) column (\d+)/i;
  const match = regex.exec(err.message);
  if (!match) return null;
  const line = Number(match[2]);
  const column = Number(match[3]);
  const position = getPositionFromMultiline(line, column, json);
  const byte = toHex(json[position]);
  return DecodeError$UnexpectedByte(byte);
}

/**
 * Matches unexpected byte messages in:
 * - JavascriptCore (safari)
 *
 * JavascriptCore only reports what the character is and not its position.
 */
function jsCoreUnexpectedByteError(err) {
  const regex = /unexpected (identifier|token) "(.)"/i;
  const match = regex.exec(err.message);
  if (!match) return null;
  const byte = toHex(match[2]);
  return DecodeError$UnexpectedByte(byte);
}

function toHex(char) {
  return "0x" + char.charCodeAt(0).toString(16).toUpperCase();
}

/**
 * Gets the position of a character in a flattened (i.e. single line) string
 * from a line and column number. Note that the position is 0-indexed and
 * the line and column numbers are 1-indexed.
 *
 * @param {number} line
 * @param {number} column
 * @param {string} string
 */
function getPositionFromMultiline(line, column, string) {
  if (line === 1) return column - 1;

  let currentLn = 1;
  let position = 0;
  string.split("").find((char, idx) => {
    if (char === "\n") currentLn += 1;
    if (currentLn === line) {
      position = idx + column;
      return true;
    }
    return false;
  });

  return position;
}
