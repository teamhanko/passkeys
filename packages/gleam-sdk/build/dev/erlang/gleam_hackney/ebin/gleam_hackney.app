{application, gleam_hackney, [
    {vsn, "1.4.0"},
    {applications, [gleam_http,
                    gleam_stdlib,
                    hackney]},
    {description, "Gleam bindings to the Hackney HTTP client"},
    {modules, [gleam@hackney]},
    {registered, []}
]}.
