-module(certifi_tests).

-include_lib("eunit/include/eunit.hrl").

-ifdef('OTP_20_AND_ABOVE').
reproducible_module_test() ->
    %% When compiled with +deterministic, only version is left out.
    ?assertMatch([{version,[_|_]}], certifi:module_info(compile)).
-endif.

cacerts_test_() ->
    Certs = [Cert1, Cert2, Cert3 | _] = certifi:cacerts(),
    [?_assertEqual(119, length(Certs))
    ,?_assertMatch(<<48,130,2,207,48,130,2,49,160,3,2,1,2,2,13,0,232,111,24,123,_/binary>>, Cert1)
    ,?_assertMatch(<<48,130,5,131,48,130,3,107,160,3,2,1,2,2,16,85,165,217,103,148,_/binary>>, Cert2)
    ,?_assertMatch(<<48,130,2,53,48,130,1,186,160,3,2,1,2,2,16,35,249,195,214,53,_/binary>>, Cert3)
    ,?_assertMatch(<<48,130,2,137,48,130,2,15,160,3,2,1,2,2,16,31,71,175,170,98,_/binary>>, lists:last(Certs))
    ].
