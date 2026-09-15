-record(gleam_panic, {
    message :: binary(),
    file :: binary(),
    module :: binary(),
    function :: binary(),
    line :: integer(),
    kind :: gleeunit@internal@gleam_panic:panic_kind()
}).
