# json 🐑

Work with JSON in Gleam!

## Installation

```shell
gleam add gleam_json@3
```

## Encoding

```gleam
import myapp.{type Cat}
import gleam/json

pub fn cat_to_json(cat: Cat) -> String {
  json.object([
    #("name", json.string(cat.name)),
    #("lives", json.int(cat.lives)),
    #("flaws", json.null()),
    #("nicknames", json.array(cat.nicknames, of: json.string)),
  ])
  |> json.to_string
}
```

## Parsing

JSON is parsed into a `Dynamic` value which can be decoded using the
`gleam/dynamic/decode` module from the Gleam standard library.

```gleam
import myapp.{Cat}
import gleam/json
import gleam/dynamic/decode

pub fn cat_from_json(json_string: String) -> Result(Cat, json.DecodeError) {
  let cat_decoder = {
    use name <- decode.field("name", decode.string)
    use lives <- decode.field("lives", decode.int)
    use nicknames <- decode.field("nicknames", decode.list(decode.string))
    decode.success(Cat(name:, lives:, nicknames:))
  }
  json.parse(from: json_string, using: cat_decoder)
}
```
