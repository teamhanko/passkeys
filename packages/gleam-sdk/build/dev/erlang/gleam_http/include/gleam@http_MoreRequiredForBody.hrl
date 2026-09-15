-record(more_required_for_body, {
    chunk :: bitstring(),
    continuation :: fun((bitstring()) -> {ok, gleam@http:multipart_body()} | {error, nil})
}).
