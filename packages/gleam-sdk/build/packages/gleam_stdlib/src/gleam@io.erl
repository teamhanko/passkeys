-module(gleam@io).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([print/1, print_error/1, println/1, println_error/1]).

-file("src/gleam/io.gleam", 14).
-spec print(binary()) -> nil.
-doc(~" Writes a string to standard output (stdout).

 If you want your output to be printed on its own line see `println`.

 ## Example

 ```gleam
 assert io.print(\"Hi mum\") == Nil
 // Hi mum
 ```
").
print(String) ->
    gleam_stdlib:print(String).

-file("src/gleam/io.gleam", 29).
-spec print_error(binary()) -> nil.
-doc(~" Writes a string to standard error (stderr).

 If you want your output to be printed on its own line see `println_error`.

 ## Example

 ```gleam
 assert io.print_error(\"Hi pop\") == Nil
 // Hi pop
 ```
").
print_error(String) ->
    gleam_stdlib:print_error(String).

-file("src/gleam/io.gleam", 42).
-spec println(binary()) -> nil.
-doc(~" Writes a string to standard output (stdout), appending a newline to the end.

 ## Example

 ```gleam
 assert io.println(\"Hi mum\") == Nil
 // Hi mum
 ```
").
println(String) ->
    gleam_stdlib:println(String).

-file("src/gleam/io.gleam", 55).
-spec println_error(binary()) -> nil.
-doc(~" Writes a string to standard error (stderr), appending a newline to the end.

 ## Example

 ```gleam
 assert io.println_error(\"Hi pop\") == Nil
 // Hi pop
 ```
").
println_error(String) ->
    gleam_stdlib:println_error(String).

