%% @doc Tests for latch_crypto.
-module(latch_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

setup_test() ->
    latch_test_helpers:setup().

roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    Plain = <<"attack at dawn">>,
    AAD = <<"aad">>,
    Blob = latch_crypto:encrypt(Key, Plain, AAD),
    ?assertEqual({ok, Plain}, latch_crypto:decrypt(Key, Blob, AAD)).

roundtrip_empty_test() ->
    Key = crypto:strong_rand_bytes(32),
    Blob = latch_crypto:encrypt(Key, <<>>, <<"aad">>),
    ?assertEqual({ok, <<>>}, latch_crypto:decrypt(Key, Blob, <<"aad">>)).

wrong_aad_test() ->
    Key = crypto:strong_rand_bytes(32),
    Blob = latch_crypto:encrypt(Key, <<"x">>, <<"right">>),
    ?assertEqual(error, latch_crypto:decrypt(Key, Blob, <<"wrong">>)).

wrong_key_test() ->
    Key = crypto:strong_rand_bytes(32),
    Other = crypto:strong_rand_bytes(32),
    Blob = latch_crypto:encrypt(Key, <<"x">>, <<"aad">>),
    ?assertEqual(error, latch_crypto:decrypt(Other, Blob, <<"aad">>)).

tampered_ciphertext_test() ->
    Key = crypto:strong_rand_bytes(32),
    <<IV:12/binary, Ct:10/binary, Tag:16/binary>> =
        latch_crypto:encrypt(Key, <<"0123456789">>, <<"aad">>),
    BadCt = <<Ct:5/binary, 16#FF, Ct:4/binary>>,
    ?assertEqual(error, latch_crypto:decrypt(Key, <<IV/binary, BadCt/binary, Tag/binary>>, <<"aad">>)).

truncated_blob_test() ->
    Key = crypto:strong_rand_bytes(32),
    Blob = latch_crypto:encrypt(Key, <<"0123456789">>, <<"aad">>),
    Size = byte_size(Blob),
    ?assertEqual(error, latch_crypto:decrypt(Key, binary:part(Blob, 0, Size - 1), <<"aad">>)),
    ?assertEqual(error, latch_crypto:decrypt(Key, <<"short">>, <<"aad">>)).

explicit_iv_deterministic_test() ->
    Key = binary:copy(<<16#AB>>, 32),
    IV = binary:copy(<<16#CD>>, 12),
    AAD = <<"deterministic">>,
    ?assertEqual(latch_crypto:encrypt(Key, IV, <<"msg">>, AAD),
                 latch_crypto:encrypt(Key, IV, <<"msg">>, AAD)).

known_vector_test() ->
    %% Fixed inputs produce this exact output. A change in the vector means
    %% the cipher behaviour or the encoding changed.
    Key = binary:copy(<<16#11>>, 32),
    IV = binary:copy(<<16#22>>, 12),
    AAD = <<"latch-aad">>,
    Blob = latch_crypto:encrypt(Key, IV, <<"hello latch">>, AAD),
    ?assertEqual(
        unhex("2222222222222222222222227F926B25AFEFF33E915CB691B802D30B3714F853B4F6F4251E06C8"),
        Blob),
    ?assertEqual({ok, <<"hello latch">>}, latch_crypto:decrypt(Key, Blob, AAD)).

unhex(Hex) -> latch_test_helpers:unhex(Hex).
