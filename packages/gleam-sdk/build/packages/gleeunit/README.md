# gleeunit

A simple test runner for Gleam, using EUnit on Erlang and a custom runner on JS.

[![Package Version](https://img.shields.io/hexpm/v/gleeunit)](https://hex.pm/packages/gleeunit)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gleeunit/)


```sh
gleam add gleeunit@1 --dev
```
```gleam
// In test/yourapp_test.gleam
import gleeunit

pub fn main() {
  gleeunit.main()
}
```

Now any public function with a name ending in `_test` in the `test` directory
will be found and run as a test.

```gleam
pub fn some_function_test() {
  assert some_function() == "Hello!"
}
```

Run the tests by entering `gleam test` in the command line.

### Deno

If using the Deno JavaScript runtime, you will need to add the following to your
`gleam.toml`.

```toml
[javascript.deno]
allow_read = [
  "gleam.toml",
  "test",
  "build",
]
```
