-module(passkey_server_client_test).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([main/0]).

-file("test/passkey_server_client_test.gleam", 3).
-spec main() -> nil.
main() ->
    gleeunit:main().

