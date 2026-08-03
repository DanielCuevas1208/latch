%% @doc Tests for the forward secrecy behaviour of the double ratchet.
-module(latch_forward_secrecy_tests).

-include("latch.hrl").
-include_lib("eunit/include/eunit.hrl").

setup_test() ->
    latch_test_helpers:setup().

%% A captured old ciphertext cannot be decrypted after the DH ratchet has
%% advanced. The old message key no longer exists in the session.
forward_secrecy_after_ratchet_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {Header, Blob, Alice1} = latch_session:encrypt(<<"secret one">>, Alice),
    {ok, <<"secret one">>, Bob1} = latch_session:decrypt(Header, Blob, Bob),
    %% several alternating rounds advance the DH ratchet repeatedly
    {Alice2, Bob2} = round_trip(Alice1, Bob1, 2),
    {_Alice3, Bob3} = round_trip(Alice2, Bob2, 2),
    %% bob's current session cannot open the old message
    ?assertMatch({error, _}, latch_session:decrypt(Header, Blob, Bob3)),
    ok.

%% The root key changes with every DH ratchet, and each peer moves forward.
root_keys_differ_across_ratchets_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {Alice1, Bob1} = round_trip(Alice, Bob, 2),
    {Alice2, Bob2} = round_trip(Alice1, Bob1, 2),
    Root0 = latch_session:root_hash(Alice),
    Root1 = latch_session:root_hash(Alice1),
    Root2 = latch_session:root_hash(Alice2),
    ?assertNotEqual(Root0, Root1),
    ?assertNotEqual(Root1, Root2),
    ?assertNotEqual(latch_session:root_hash(Bob), latch_session:root_hash(Bob1)),
    ?assertNotEqual(latch_session:root_hash(Bob1), latch_session:root_hash(Bob2)).

%% Fresh keys are used after each ratchet: the sending key and the ciphertext
%% change even for identical plaintext.
no_reuse_of_chain_keys_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {H1, B1, Alice1} = latch_session:encrypt(<<"x">>, Alice),
    {ok, <<"x">>, Bob1} = latch_session:decrypt(H1, B1, Bob),
    {Alice2, Bob2} = round_trip(Alice1, Bob1, 1),
    {H2, B2, _Alice3} = latch_session:encrypt(<<"x">>, Alice2),
    ?assertNotEqual(H1#latch_header.dh, H2#latch_header.dh),
    ?assertNotEqual(B1, B2),
    {ok, <<"x">>, _} = latch_session:decrypt(H2, B2, Bob2).

%% The skip window covers gaps inside one sending chain. A message from a
%% chain that a DH ratchet has already superseded cannot be recovered. This
%% matches the standard Double Ratchet behaviour.
superseded_chain_messages_dropped_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {P1, Alice1} = send_many(Alice, [<<"m0">>, <<"m1">>, <<"m2">>]),
    Bob1 = receive_many(Bob, P1),
    %% bob replies, which rotates alice's ratchet on receive
    {BP, Bob2} = send_many(Bob1, [<<"r">>]),
    Alice2 = receive_many(Alice1, BP),
    %% alice sends a new-chain message; bob ratchets past the m0..m2 chain
    {P2, _Alice3} = send_many(Alice2, [<<"m3">>]),
    Bob3 = receive_many(Bob2, P2),
    %% the old m0 arrives after the ratchet; it cannot be decrypted
    {H0, B0} = hd(P1),
    ?assertMatch({error, _}, latch_session:decrypt(H0, B0, Bob3)).

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

send_many(Session, Texts) ->
    lists:mapfoldl(
        fun(Text, S) ->
            {Header, Blob, S2} = latch_session:encrypt(Text, S),
            {{Header, Blob}, S2}
        end,
        Session, Texts).

receive_many(Session, Packets) ->
    lists:foldl(
        fun({Header, Blob}, S) ->
            {ok, _Plain, S2} = latch_session:decrypt(Header, Blob, S),
            S2
        end,
        Session, Packets).

round_trip(Alice, Bob, N) ->
    {APackets, Alice1} =
        send_many(Alice, [<<"a", (integer_to_binary(I))/binary>> || I <- lists:seq(1, N)]),
    Bob1 = receive_many(Bob, APackets),
    {BPackets, Bob2} =
        send_many(Bob1, [<<"b", (integer_to_binary(I))/binary>> || I <- lists:seq(1, N)]),
    Alice2 = receive_many(Alice1, BPackets),
    {Alice2, Bob2}.
