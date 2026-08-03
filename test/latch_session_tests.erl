%% @doc Tests for latch_session: the double ratchet.
-module(latch_session_tests).

-include("latch.hrl").
-include_lib("eunit/include/eunit.hrl").

setup_test() ->
    latch_test_helpers:setup().

roundtrip_single_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {Header, Blob, Alice1} = latch_session:encrypt(<<"hello">>, Alice),
    ?assertEqual(0, Header#latch_header.n),
    ?assertEqual(0, Header#latch_header.pn),
    {ok, <<"hello">>, Bob1} = latch_session:decrypt(Header, Blob, Bob),
    ?assertEqual(1, maps:get(sent_total, latch_session:to_map(Alice1))),
    ?assertEqual(1, maps:get(recv_total, latch_session:to_map(Bob1))).

roundtrip_sequence_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    Texts = [binary:copy(<<"m">>, I) || I <- lists:seq(1, 20)],
    {Packets, Alice1} = send_many(Alice, Texts),
    Bob1 = receive_many(Bob, Packets),
    ?assertEqual(20, maps:get(sent_total, latch_session:to_map(Alice1))),
    ?assertEqual(20, maps:get(recv_total, latch_session:to_map(Bob1))).

both_directions_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    Texts = [<<"a", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 10)],
    Replies = [<<"r", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 10)],
    {APackets, Alice1} = send_many(Alice, Texts),
    Bob1 = receive_many(Bob, APackets),
    {BPackets, Bob2} = send_many(Bob1, Replies),
    Alice2 = receive_many(Alice1, BPackets),
    ?assertEqual(10, maps:get(recv_total, latch_session:to_map(Alice2))),
    ?assertEqual(10, maps:get(recv_total, latch_session:to_map(Bob2))).

fresh_key_per_message_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {H1, B1, Alice1} = latch_session:encrypt(<<"same">>, Alice),
    {H2, B2, Alice2} = latch_session:encrypt(<<"same">>, Alice1),
    ?assertNotEqual(B1, B2),
    {ok, <<"same">>, _} = latch_session:decrypt(H1, B1, Bob),
    {ok, <<"same">>, _} = latch_session:decrypt(H2, B2, Bob),
    ?assertEqual(2, maps:get(sent_total, latch_session:to_map(Alice2))).

ratchet_roundtrip_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    %% the first message ratchets the responder; the reply ratchets back
    {APackets1, Alice1} = send_many(Alice, [<<"a1">>, <<"a2">>, <<"a3">>]),
    Bob1 = receive_many(Bob, APackets1),
    {BPackets1, Bob2} = send_many(Bob1, [<<"b1">>, <<"b2">>]),
    Alice2 = receive_many(Alice1, BPackets1),
    %% a second full round keeps the ratchets alternating
    {APackets2, Alice3} = send_many(Alice2, [<<"a4">>, <<"a5">>]),
    Bob3 = receive_many(Bob2, APackets2),
    {BPackets2, _Bob4} = send_many(Bob3, [<<"b3">>]),
    Alice4 = receive_many(Alice3, BPackets2),
    ?assertEqual(5, maps:get(recv_total, latch_session:to_map(Bob3))),
    ?assertEqual(3, maps:get(recv_total, latch_session:to_map(Alice4))),
    %% the ratchet moved both roots forward
    ?assertNotEqual(latch_session:root_hash(Alice), latch_session:root_hash(Alice4)),
    ?assertNotEqual(latch_session:root_hash(Bob), latch_session:root_hash(Bob3)).

ratchet_header_pn_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {P1, Alice1} = send_many(Alice, [<<"a1">>, <<"a2">>, <<"a3">>]),
    Bob1 = receive_many(Bob, P1),
    {BP1, Bob2} = send_many(Bob1, [<<"b1">>]),
    Alice2 = receive_many(Alice1, BP1),
    {Header, Blob, _Alice3} = latch_session:encrypt(<<"a4">>, Alice2),
    %% alice sent 3 messages before her ratchet, so pn is 3
    ?assertEqual(3, Header#latch_header.pn),
    ?assertEqual(0, Header#latch_header.n),
    {ok, <<"a4">>, _} = latch_session:decrypt(Header, Blob, Bob2).

root_key_advances_on_ratchet_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    Root0 = latch_session:root_hash(Alice),
    {P1, Alice1} = send_many(Alice, [<<"a1">>, <<"a2">>]),
    Bob1 = receive_many(Bob, P1),
    {BP1, Bob2} = send_many(Bob1, [<<"b1">>]),
    Alice2 = receive_many(Alice1, BP1),
    Root1 = latch_session:root_hash(Alice2),
    ?assertNotEqual(Root0, Root1),
    ?assertNotEqual(Root1, latch_session:root_hash(Bob2)).

responder_cannot_send_first_test() ->
    {_Alice, Bob} = latch_test_helpers:pair(),
    ?assertError({latch, not_initialized}, latch_session:encrypt(<<"early">>, Bob)).

out_of_order_within_chain_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    Texts = [<<"m0">>, <<"m1">>, <<"m2">>, <<"m3">>, <<"m4">>],
    {Packets, _Alice1} = send_many(Alice, Texts),
    [P0, P1, P2, P3, P4] = Packets,
    Shuffled = [P2, P4, P1, P0, P3],
    Bob1 = receive_many(Bob, Shuffled),
    ?assertEqual(5, maps:get(recv_total, latch_session:to_map(Bob1))),
    ?assertEqual(0, maps:get(skipped_keys, latch_session:to_map(Bob1))).

skipped_keys_used_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    Texts = [<<"m0">>, <<"m1">>, <<"m2">>, <<"m3">>],
    {Packets, _Alice1} = send_many(Alice, Texts),
    [P0, P1, P2, P3] = Packets,
    %% receive message 2 first: messages 0 and 1 are skipped and stored
    {ok, <<"m2">>, Bob1} =
        latch_session:decrypt(element(1, P2), element(2, P2), Bob),
    ?assertEqual(2, maps:get(skipped_keys, latch_session:to_map(Bob1))),
    %% now message 0 arrives via the skipped-key store
    {ok, <<"m0">>, Bob2} =
        latch_session:decrypt(element(1, P0), element(2, P0), Bob1),
    ?assertEqual(1, maps:get(skipped_keys, latch_session:to_map(Bob2))),
    {ok, <<"m1">>, Bob3} =
        latch_session:decrypt(element(1, P1), element(2, P1), Bob2),
    ?assertEqual(0, maps:get(skipped_keys, latch_session:to_map(Bob3))),
    {ok, <<"m3">>, _Bob4} =
        latch_session:decrypt(element(1, P3), element(2, P3), Bob3).

gap_too_large_test() ->
    Opts = #{max_skip => 2},
    {Alice, Bob} = latch_test_helpers:pair(Opts),
    Texts = [<<"m0">>, <<"m1">>, <<"m2">>, <<"m3">>],
    {Packets, _Alice1} = send_many(Alice, Texts),
    %% message 3 is 3 ahead of the current position; max_skip is 2
    {H3, B3, _Text} = lists:nth(4, Packets),
    ?assertEqual({error, gap_too_large}, latch_session:decrypt(H3, B3, Bob)).

replay_rejected_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {Header, Blob, _Alice1} = latch_session:encrypt(<<"once">>, Alice),
    {ok, <<"once">>, Bob1} = latch_session:decrypt(Header, Blob, Bob),
    ?assertEqual({error, message_too_old}, latch_session:decrypt(Header, Blob, Bob1)).

tampered_ciphertext_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {Header, Blob, _Alice1} = latch_session:encrypt(<<"important">>, Alice),
    Size = byte_size(Blob) - 1,
    <<Head:Size/binary, Last:8>> = Blob,
    Bad = <<Head/binary, (Last bxor 16#FF):8>>,
    ?assertEqual({error, authentication_failed},
                 latch_session:decrypt(Header, Bad, Bob)).

tampered_header_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    {Header, Blob, _Alice1} = latch_session:encrypt(<<"important">>, Alice),
    Tampered = Header#latch_header{n = Header#latch_header.n + 1},
    ?assertEqual({error, authentication_failed},
                 latch_session:decrypt(Tampered, Blob, Bob)).

wrong_session_test() ->
    {Alice, _} = latch_test_helpers:pair(),
    {OtherA, OtherB} = latch_test_helpers:pair(),
    {Header, Blob, _} = latch_session:encrypt(<<"for bob">>, Alice),
    ?assertEqual({error, authentication_failed},
                 latch_session:decrypt(Header, Blob, OtherB)),
    {OHeader, OBlob, _} = latch_session:encrypt(<<"from other">>, OtherA),
    ?assertEqual({error, authentication_failed},
                 latch_session:decrypt(OHeader, OBlob, Alice)).

random_access_test() ->
    {Alice, Bob} = latch_test_helpers:pair(),
    Texts = [<<"n", (integer_to_binary(I))/binary>> || I <- lists:seq(0, 9)],
    {Packets, _Alice1} = send_many(Alice, Texts),
    [P0, P1, P2, P3, P4, P5, P6, P7, P8, P9] = Packets,
    %% random-ish access order
    Order = [P5, P0, P9, P2, P7, P1, P8, P3, P6, P4],
    Bob1 = receive_many(Bob, Order),
    ?assertEqual(10, maps:get(recv_total, latch_session:to_map(Bob1))).

to_map_fields_test() ->
    {Alice, _} = latch_test_helpers:pair(),
    M = latch_session:to_map(Alice),
    ?assertEqual(initiator, maps:get(role, M)),
    ?assert(is_binary(maps:get(root_hash, M))),
    ?assert(is_binary(maps:get(dh_send_pub, M))),
    ?assert(is_binary(maps:get(dh_recv_pub, M))),
    ?assertEqual(0, maps:get(send_count, M)),
    ?assertEqual(0, maps:get(recv_count, M)).

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

send_many(Session, Texts) ->
    lists:mapfoldl(
        fun(Text, S) ->
            {Header, Blob, S2} = latch_session:encrypt(Text, S),
            {{Header, Blob, Text}, S2}
        end,
        Session, Texts).

receive_many(Session, Packets) ->
    lists:foldl(
        fun({Header, Blob, Expected}, S) ->
            {ok, Plain, S2} = latch_session:decrypt(Header, Blob, S),
            ?assertEqual(Expected, Plain),
            S2
        end,
        Session, Packets).
