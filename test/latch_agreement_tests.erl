%% @doc Tests for latch_agreement.
-module(latch_agreement_tests).

-include_lib("eunit/include/eunit.hrl").

setup_test() ->
    latch_test_helpers:setup().

key_sizes_test() ->
    {Pub, Priv} = latch_agreement:new_identity(),
    ?assertEqual(32, byte_size(Pub)),
    ?assertEqual(32, byte_size(Priv)),
    {EPub, EPriv} = latch_agreement:new_ephemeral(),
    ?assertEqual(32, byte_size(EPub)),
    ?assertEqual(32, byte_size(EPriv)).

keys_distinct_test() ->
    {P1, _} = latch_agreement:new_identity(),
    {P2, _} = latch_agreement:new_identity(),
    ?assertNotEqual(P1, P2).

shared_secret_matches_test() ->
    {IdA, _} = IdPairA = latch_agreement:new_identity(),
    {EphA, _} = EphPairA = latch_agreement:new_ephemeral(),
    {IdB, _} = IdPairB = latch_agreement:new_identity(),
    {EphB, _} = EphPairB = latch_agreement:new_ephemeral(),
    SecretA = latch_agreement:shared_secret(element(2, IdPairA), element(2, EphPairA), IdB, EphB),
    SecretB = latch_agreement:shared_secret(element(2, IdPairB), element(2, EphPairB), IdA, EphA),
    ?assertEqual(SecretA, SecretB),
    ?assertEqual(32, byte_size(SecretA)).

shared_secret_changes_with_keys_test() ->
    {_IdPubA, IdPrivA} = latch_agreement:new_identity(),
    {_EphPubA, EphPrivA} = latch_agreement:new_ephemeral(),
    {IdPubB, _IdPrivB} = latch_agreement:new_identity(),
    {EphPubB, _EphPrivB} = latch_agreement:new_ephemeral(),
    {IdPubC, IdPrivC} = latch_agreement:new_identity(),
    S1 = latch_agreement:shared_secret(IdPrivA, EphPrivA, IdPubB, EphPubB),
    S2 = latch_agreement:shared_secret(IdPrivC, EphPrivA, IdPubB, EphPubB),
    S3 = latch_agreement:shared_secret(IdPrivA, EphPrivA, IdPubC, EphPubB),
    ?assertNotEqual(S1, S2),
    ?assertNotEqual(S1, S3),
    ?assertNotEqual(S2, S3).

session_initial_state_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    AMap = latch_session:to_map(Alice),
    BMap = latch_session:to_map(Bob),
    ?assertEqual(initiator, maps:get(role, AMap)),
    ?assertEqual(responder, maps:get(role, BMap)),
    %% the initiator can send immediately; the responder waits for the first
    %% message and then runs its first DH ratchet
    ?assertEqual(0, maps:get(send_count, AMap)),
    ?assertEqual(0, maps:get(recv_count, AMap)),
    ?assertEqual(undefined, maps:get(dh_recv_pub, BMap)),
    {Header, Blob, _Alice1} = latch_session:encrypt(<<"first">>, Alice),
    {ok, <<"first">>, Bob1} = latch_session:decrypt(Header, Blob, Bob),
    BMap1 = latch_session:to_map(Bob1),
    ?assertEqual(maps:get(dh_send_pub, AMap), maps:get(dh_recv_pub, BMap1)),
    ?assertEqual(1, maps:get(recv_total, BMap1)).
