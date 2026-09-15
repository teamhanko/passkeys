# Hackney

[![Package Version](https://img.shields.io/hexpm/v/gleam_hackney)](https://hex.pm/packages/gleam_hackney)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gleam_hackney/)

Bindings to Erlang's `hackney` HTTP client.

Most the time [`gleam_httpc`](https://github.com/gleam-lang/httpc) is a better
choice as it uses the built-in Erlang HTTP client, but this package may be
useful in some specific situations.

```shell
gleam add gleam_hackney@1 gleam_http
```
```gleam
import gleam/result
import gleam/hackney
import gleam/http/request
import gleam/http/response

pub fn main() {
  // Prepare a HTTP request record
  let assert Ok(request) =
    request.to("https://test-api.service.hmrc.gov.uk/hello/world")

  // Send the HTTP request to the server
  use response <- result.try(
    request
    |> request.prepend_header("accept", "application/vnd.hmrc.1.0+json")
    |> hackney.send
  )

  // We get a response record back
  assert response.status == 200

  assert response.get_header(response, "content-type")
    == Ok("application/json")

  assert response.body
    == "{\"message\":\"Hello World\"}"

  Ok(response)
}
```
