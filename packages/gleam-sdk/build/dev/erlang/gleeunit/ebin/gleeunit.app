{application, gleeunit, [
    {vsn, "1.11.0"},
    {applications, [gleam_stdlib]},
    {description, "A simple test runner for Gleam, using EUnit on Erlang"},
    {modules, [gleeunit,
               gleeunit@internal@gleam_panic,
               gleeunit@internal@reporting,
               gleeunit@should]},
    {registered, []}
]}.
