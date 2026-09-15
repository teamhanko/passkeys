-record(more_required_for_headers, {
    continuation :: fun((bitstring()) -> {ok, gleam@http:multipart_headers()} | {error, nil})
}).
