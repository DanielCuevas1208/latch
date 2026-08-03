%% @doc Tests for latch_kdf.
-module(latch_kdf_tests).

-include_lib("eunit/include/eunit.hrl").

hkdf_rfc5869_case1_test() ->
    IKM = binary:copy(<<16#0B>>, 22),
    Salt = unhex("000102030405060708090a0b0c"),
    Info = unhex("f0f1f2f3f4f5f6f7f8f9"),
    PRK = unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
    OKM = unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"),
    ?assertEqual(PRK, latch_kdf:hkdf_extract(Salt, IKM)),
    ?assertEqual(OKM, latch_kdf:hkdf(Salt, IKM, Info, 42)).

hkdf_lengths_test() ->
    IKM = <<"some ikm material">>,
    Salt = <<"salt">>,
    Info = <<"info">>,
    ?assertEqual(32, byte_size(latch_kdf:hkdf(Salt, IKM, Info, 32))),
    ?assertEqual(64, byte_size(latch_kdf:hkdf(Salt, IKM, Info, 64))).

hkdf_deterministic_test() ->
    ?assertEqual(latch_kdf:hkdf(<<"s">>, <<"i">>, <<"n">>, 32),
                 latch_kdf:hkdf(<<"s">>, <<"i">>, <<"n">>, 32)).

hkdf_salt_matters_test() ->
    ?assertNotEqual(latch_kdf:hkdf(<<"a">>, <<"i">>, <<"n">>, 32),
                    latch_kdf:hkdf(<<"b">>, <<"i">>, <<"n">>, 32)).

chain_key_step_test() ->
    Chain = <<"a chain key">>,
    {Next1, Mk1} = latch_kdf:chain_key_step(Chain),
    {Next2, Mk2} = latch_kdf:chain_key_step(Chain),
    ?assertEqual(32, byte_size(Next1)),
    ?assertEqual(32, byte_size(Mk1)),
    ?assertEqual(Next1, Next2),
    ?assertEqual(Mk1, Mk2),
    ?assertNotEqual(Next1, Mk1),
    %% both differ from the input chain key
    ?assertNotEqual(Chain, Next1),
    ?assertNotEqual(Chain, Mk1).

chain_key_advances_test() ->
    {Next1, Mk1} = latch_kdf:chain_key_step(<<"c1">>),
    {_Next2, Mk2} = latch_kdf:chain_key_step(Next1),
    ?assertNotEqual(Mk1, Mk2).

root_key_step_test() ->
    {Root2, Chain} = latch_kdf:root_key_step(<<"root">>, <<"dhout">>),
    ?assertEqual(32, byte_size(Root2)),
    ?assertEqual(32, byte_size(Chain)),
    ?assertNotEqual(Root2, Chain),
    ?assertNotEqual(<<"root">>, Root2),
    ?assertNotEqual(<<"root">>, Chain).

root_key_step_deterministic_test() ->
    ?assertEqual(latch_kdf:root_key_step(<<"r">>, <<"d">>),
                 latch_kdf:root_key_step(<<"r">>, <<"d">>)).

root_key_step_matches_dh_test() ->
    {PubA, PrivA} = crypto:generate_key(ecdh, x25519),
    {PubB, PrivB} = crypto:generate_key(ecdh, x25519),
    DA = crypto:compute_key(ecdh, PubB, PrivA, x25519),
    DB = crypto:compute_key(ecdh, PubA, PrivB, x25519),
    ?assertEqual(DA, DB),
    ?assertEqual(latch_kdf:root_key_step(<<"r">>, DA),
                 latch_kdf:root_key_step(<<"r">>, DB)).

unhex(Hex) -> latch_test_helpers:unhex(Hex).
