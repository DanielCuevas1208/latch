%% @doc Tests for latch_sender_key: group messaging.
-module(latch_sender_key_tests).

-include("latch.hrl").
-include_lib("eunit/include/eunit.hrl").

setup_test() ->
    latch_test_helpers:setup().

sender_receiver_roundtrip_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    {Header, Frame, _Sender1} = latch_sender_key:encrypt(<<"group hello">>, Sender),
    {ok, <<"group hello">>, _Receiver1} =
        latch_sender_key:decrypt(Header, Frame, Receiver).

sequence_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    Messages = [<<"msg ", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 20)],
    {Frames, Sender1} = send_many(Sender, Messages),
    Receiver1 = receive_many(Receiver, Frames),
    ?assertEqual(20, length(Frames)),
    ?assertMatch(#{iter := 20}, latch_sender_key:to_map(Sender1)),
    ?assertMatch(#{iter := 20}, latch_sender_key:to_map(Receiver1)).

out_of_order_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    Messages = [<<"m", (integer_to_binary(I))/binary>> || I <- lists:seq(0, 6)],
    {Frames, _Sender1} = send_many(Sender, Messages),
    [F0, F1, F2, F3, F4, F5, F6] = Frames,
    %% shuffled delivery
    Shuffled = [F4, F1, F6, F0, F3, F2, F5],
    Receiver1 = receive_many(Receiver, Shuffled),
    ?assertMatch(#{skipped_keys := 0}, latch_sender_key:to_map(Receiver1)).

skipped_keys_used_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    {F0, S1} = send(Sender, <<"m0">>),
    {F1, S2} = send(S1, <<"m1">>),
    {F2, _S3} = send(S2, <<"m2">>),
    %% receiver processes frame 2 first; frames 0 and 1 are stored as skipped
    {ok, <<"m2">>, Receiver1} = decrypt(F2, Receiver),
    ?assertMatch(#{skipped_keys := 2}, latch_sender_key:to_map(Receiver1)),
    %% then frame 0 decrypts from the store
    {ok, <<"m0">>, Receiver2} = decrypt(F0, Receiver1),
    ?assertMatch(#{skipped_keys := 1}, latch_sender_key:to_map(Receiver2)),
    {ok, <<"m1">>, _Receiver3} = decrypt(F1, Receiver2).

gap_too_large_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    {_Dummy, S1} = send_many_n(Sender, 1001),
    {Header, Frame, _} = latch_sender_key:encrypt(<<"late">>, S1),
    ?assertEqual({error, gap_too_large},
                 latch_sender_key:decrypt(Header, Frame, Receiver)).

replay_rejected_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    {Header, Frame, _Sender1} = latch_sender_key:encrypt(<<"once">>, Sender),
    {ok, <<"once">>, Receiver1} = latch_sender_key:decrypt(Header, Frame, Receiver),
    ?assertEqual({error, message_too_old},
                 latch_sender_key:decrypt(Header, Frame, Receiver1)).

tampered_frame_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender)),
    {Header, Frame, _Sender1} = latch_sender_key:encrypt(<<"keep safe">>, Sender),
    Size = byte_size(Frame) - 1,
    <<Head:Size/binary, Last:8>> = Frame,
    Bad = <<Head/binary, (Last bxor 1):8>>,
    ?assertEqual({error, bad_signature},
                 latch_sender_key:decrypt(Header, Bad, Receiver)).

wrong_key_id_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    Other = latch_sender_key:new_sender(#{}),
    Receiver = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Other)),
    {Header, Frame, _Sender1} = latch_sender_key:encrypt(<<"group hello">>, Sender),
    ?assertEqual({error, unknown_key_id},
                 latch_sender_key:decrypt(Header, Frame, Receiver)).

sender_cannot_receive_test() ->
    Sender = latch_sender_key:new_sender(#{}),
    {Header, Frame, Sender1} = latch_sender_key:encrypt(<<"self">>, Sender),
    %% a sender session has no receiver chain
    ?assertError(function_clause, latch_sender_key:decrypt(Header, Frame, Sender1)).

header_codec_test() ->
    Header = #latch_sheader{key_id = binary:copy(<<16#AB>>, 32), iter = 7},
    ?assertEqual(36, byte_size(latch_sender_key:encode_sheader(Header))),
    ?assertEqual(Header, latch_sender_key:decode_sheader(latch_sender_key:encode_sheader(Header))).

deterministic_key_id_test() ->
    KeyId = binary:copy(<<16#01>>, 32),
    Chain = binary:copy(<<16#02>>, 32),
    Opts = #{key_id => KeyId, chain_key => Chain},
    Sender1 = latch_sender_key:new_sender(Opts),
    Sender2 = latch_sender_key:new_sender(Opts),
    Receiver1 = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender1)),
    Receiver2 = latch_sender_key:new_receiver(latch_sender_key:sender_seed(Sender2)),
    {H1, F1, _} = latch_sender_key:encrypt(<<"same">>, Sender1),
    {H2, F2, _} = latch_sender_key:encrypt(<<"same">>, Sender2),
    {ok, Plain1, _} = latch_sender_key:decrypt(H1, F1, Receiver1),
    {ok, Plain2, _} = latch_sender_key:decrypt(H2, F2, Receiver2),
    ?assertEqual(<<"same">>, Plain1),
    ?assertEqual(<<"same">>, Plain2),
    ?assertEqual(H1#latch_sheader.key_id, H2#latch_sheader.key_id).

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

send_many(Sender, Messages) ->
    lists:mapfoldl(
        fun(Text, S) ->
            {Header, Frame, S2} = latch_sender_key:encrypt(Text, S),
            {{Header, Frame, Text}, S2}
        end,
        Sender, Messages).

receive_many(Receiver, Frames) ->
    lists:foldl(
        fun({Header, Frame, Expected}, R) ->
            {ok, Plain, R2} = latch_sender_key:decrypt(Header, Frame, R),
            ?assertEqual(Expected, Plain),
            R2
        end,
        Receiver, Frames).

send(Sender, Text) ->
    {Header, Frame, Sender2} = latch_sender_key:encrypt(Text, Sender),
    {{Header, Frame}, Sender2}.

decrypt({Header, Frame}, Receiver) ->
    latch_sender_key:decrypt(Header, Frame, Receiver).

send_many_n(Sender, N) ->
    send_many_n(Sender, N, []).

send_many_n(Sender, 0, Frames) ->
    {lists:reverse(Frames), Sender};
send_many_n(Sender, N, Frames) ->
    {Header, Frame, Sender2} = latch_sender_key:encrypt(<<"skip">>, Sender),
    send_many_n(Sender2, N - 1, [{Header, Frame} | Frames]).
