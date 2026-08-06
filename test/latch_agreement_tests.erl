%% @doc Tests for latch_agreement.
-module(latch_agreement_tests).

-include("latch.hrl").
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

signed_identity_sizes_test() ->
    #latch_identity{id = {IdPub, IdPriv}, sign = {SignPub, SignPriv}} =
        latch_agreement:new_identity_signed(),
    ?assertEqual(32, byte_size(IdPub)),
    ?assertEqual(32, byte_size(IdPriv)),
    ?assertEqual(32, byte_size(SignPub)),
    ?assertEqual(32, byte_size(SignPriv)),
    ?assertNotEqual(IdPub, SignPub).

hello_payload_covers_keys_test() ->
    Identity = latch_agreement:new_identity_signed(),
    #latch_identity{id = {IdPub, _}, sign = {SignPub, _}} = Identity,
    {EphPub, _} = latch_agreement:new_ephemeral(),
    Payload = latch_agreement:hello_payload(IdPub, SignPub, EphPub),
    %% the 14-byte tag plus three 32-byte keys
    ?assertEqual(110, byte_size(Payload)),
    ?assertMatch(<<"latch:v1:hello", _/binary>>, Payload).

signature_verifies_roundtrip_test() ->
    Identity = latch_agreement:new_identity_signed(),
    #latch_identity{id = {IdPub, _}, sign = {SignPub, _}} = Identity,
    {EphPub, _} = latch_agreement:new_ephemeral(),
    Sig = latch_agreement:sign_hello(Identity, EphPub),
    ?assertEqual(64, byte_size(Sig)),
    ?assert(latch_agreement:verify_hello(IdPub, SignPub, EphPub, Sig)).

signature_is_deterministic_test() ->
    Identity = latch_agreement:new_identity_signed(),
    {EphPub, _} = latch_agreement:new_ephemeral(),
    ?assertEqual(latch_agreement:sign_hello(Identity, EphPub),
                 latch_agreement:sign_hello(Identity, EphPub)).

signature_bound_to_identity_test() ->
    IdentityA = latch_agreement:new_identity_signed(),
    IdentityB = latch_agreement:new_identity_signed(),
    #latch_identity{id = {IdPubA, _}, sign = {SignPubA, _}} = IdentityA,
    #latch_identity{id = {_IdPubB, _}, sign = {SignPubB, _}} = IdentityB,
    {EphPub, _} = latch_agreement:new_ephemeral(),
    Sig = latch_agreement:sign_hello(IdentityA, EphPub),
    %% the signature does not verify against another identity's signing key
    ?assertNot(latch_agreement:verify_hello(IdPubA, SignPubB, EphPub, Sig)),
    %% nor against another identity key with the same signing key
    ?assertNot(latch_agreement:verify_hello(SignPubA, SignPubA, EphPub, Sig)).

signature_bound_to_ephemeral_test() ->
    Identity = latch_agreement:new_identity_signed(),
    #latch_identity{id = {IdPub, _}, sign = {SignPub, _}} = Identity,
    {EphPub1, _} = latch_agreement:new_ephemeral(),
    {EphPub2, _} = latch_agreement:new_ephemeral(),
    Sig = latch_agreement:sign_hello(Identity, EphPub1),
    ?assert(latch_agreement:verify_hello(IdPub, SignPub, EphPub1, Sig)),
    %% the signature is invalid for a different ephemeral key
    ?assertNot(latch_agreement:verify_hello(IdPub, SignPub, EphPub2, Sig)).

signature_rejects_tampered_bytes_test() ->
    Identity = latch_agreement:new_identity_signed(),
    #latch_identity{id = {IdPub, _}, sign = {SignPub, _}} = Identity,
    {EphPub, _} = latch_agreement:new_ephemeral(),
    Sig = latch_agreement:sign_hello(Identity, EphPub),
    <<Head:63/binary, Last:8>> = Sig,
    BadSig = <<Head/binary, (Last bxor 16#01):8>>,
    ?assertNot(latch_agreement:verify_hello(IdPub, SignPub, EphPub, BadSig)).

fingerprint_digest_size_test() ->
    SignPub = test_sign_pub(16#ab),
    Digest = latch_agreement:fingerprint_digest(SignPub),
    ?assertEqual(32, byte_size(Digest)).

fingerprint_format_test() ->
    SignPub = test_sign_pub(16#ab),
    FP = latch_agreement:fingerprint(SignPub),
    Groups = string:split(FP, " ", all),
    ?assertEqual(16, length(Groups)),
    ?assert(lists:all(fun(G) -> length(G) =:= 4 end, Groups)),
    ?assertEqual(string:uppercase(FP), FP).

fingerprint_is_deterministic_test() ->
    #latch_identity{sign = {SignPub, _}} = latch_agreement:new_identity_signed(),
    ?assertEqual(latch_agreement:fingerprint(SignPub),
                 latch_agreement:fingerprint(SignPub)).

fingerprints_match_normalizes_test() ->
    SignPub = test_sign_pub(1),
    FP = latch_agreement:fingerprint(SignPub),
    Compact = lists:flatten(string:split(FP, " ", all)),
    Lower = string:lowercase(FP),
    ?assert(latch_agreement:fingerprints_match(FP, Compact)),
    ?assert(latch_agreement:fingerprints_match(FP, Lower)),
    ?assertNot(latch_agreement:fingerprints_match(FP, "0000")).

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

test_sign_pub(Byte) ->
    iolist_to_binary([<<Byte:8>> || _ <- lists:seq(1, 32)]).
