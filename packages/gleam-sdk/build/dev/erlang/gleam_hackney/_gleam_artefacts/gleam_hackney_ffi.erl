-module(gleam_hackney_ffi).

-export([send/4]).

send(Method, Url, Headers, Body) ->
    Options = [{with_body, true}],
    case hackney:request(Method, Url, Headers, Body, Options) of
        {ok, Status, ResponseHeaders, ResponseBody} -> 
            {ok, {response, Status, ResponseHeaders, ResponseBody}};

        {ok, Status, ResponseHeaders} -> 
            {ok, {response, Status, ResponseHeaders, <<>>}};

        {error, Error} -> 
            {error, {other, Error}}
    end.
