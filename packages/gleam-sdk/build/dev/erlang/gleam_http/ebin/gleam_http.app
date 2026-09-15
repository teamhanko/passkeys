{application, gleam_http, [
    {vsn, "4.4.0"},
    {applications, [gleam_stdlib]},
    {description, "Types and functions for Gleam HTTP clients and servers"},
    {modules, [gleam@http,
               gleam@http@cookie,
               gleam@http@request,
               gleam@http@response,
               gleam@http@service]},
    {registered, []}
]}.
