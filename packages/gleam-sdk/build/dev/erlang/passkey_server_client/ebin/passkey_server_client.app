{application, passkey_server_client, [
    {vsn, "1.0.0"},
    {applications, [gleam_hackney,
                    gleam_http,
                    gleam_json,
                    gleam_stdlib,
                    gleeunit]},
    {description, "Gleam SDK for a Hanko Passkey Server (WebAuthn registration and login flows)"},
    {modules, [passkey_server_client,
               passkey_server_client_test]},
    {registered, []}
]}.
