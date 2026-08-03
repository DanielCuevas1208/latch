%% @doc Integration tests for latch_peer over real loopback TCP.
-module(latch_peer_tests).

-include("latch.hrl").
-include_lib("eunit/include/eunit.hrl").

setup_test() ->
    latch_test_helpers:setup().

handshake_and_exchange_test() ->
    {Alice, Bob} = connect_pair(),
    %% the initiator (bob, the dialer) sends the first message
    {ok, Bob2} = latch_peer:send(Bob, <<"hello alice">>),
    {ok, _H1, <<"hello alice">>, Alice2} = latch_peer:recv(Alice),
    {ok, Alice3} = latch_peer:send(Alice2, <<"hi bob">>),
    {ok, _H2, <<"hi bob">>, Bob3} = latch_peer:recv(Bob2),
    latch_peer:close(Alice3),
    latch_peer:close(Bob3).

sequence_test() ->
    {Alice, Bob} = connect_pair(),
    Count = 10,
    %% bob sends, alice receives
    Bob2 =
        lists:foldl(
            fun(I, B) ->
                {ok, B2} = latch_peer:send(B, payload(I)),
                B2
            end,
            Bob, lists:seq(1, Count)),
    Alice2 =
        lists:foldl(
            fun(I, A) ->
                {ok, _H, Payload, A2} = latch_peer:recv(A),
                ?assertEqual(payload(I), Payload),
                A2
            end,
            Alice, lists:seq(1, Count)),
    ?assertEqual(Count, maps:get(recv_total, session_map(Alice2))),
    %% then alice replies
    Alice3 =
        lists:foldl(
            fun(I, A) ->
                {ok, A2} = latch_peer:send(A, payload(100 + I)),
                A2
            end,
            Alice2, lists:seq(1, Count)),
    Bob3 =
        lists:foldl(
            fun(I, B) ->
                {ok, _H, Payload, B2} = latch_peer:recv(B),
                ?assertEqual(payload(100 + I), Payload),
                B2
            end,
            Bob2, lists:seq(1, Count)),
    ?assertEqual(Count, maps:get(recv_total, session_map(Bob3))),
    latch_peer:close(Alice3),
    latch_peer:close(Bob3).

ratchet_over_socket_test() ->
    {Alice, Bob} = connect_pair(),
    {ok, Bob2} = latch_peer:send(Bob, <<"b1">>),
    {ok, _H1, <<"b1">>, Alice2} = latch_peer:recv(Alice),
    ?assertEqual(0, _H1#latch_header.pn),
    %% alice replies; bob's next message then arrives on a new ratchet
    {ok, Alice3} = latch_peer:send(Alice2, <<"a1">>),
    {ok, _H2, <<"a1">>, Bob3} = latch_peer:recv(Bob2),
    {ok, Bob4} = latch_peer:send(Bob3, <<"b2">>),
    {ok, H3, <<"b2">>, Alice4} = latch_peer:recv(Alice3),
    ?assertEqual(1, H3#latch_header.pn),
    ?assertEqual(0, H3#latch_header.n),
    ?assertNotEqual(_H2#latch_header.dh, H3#latch_header.dh),
    latch_peer:close(Alice4),
    latch_peer:close(Bob4).

out_of_order_processing_test() ->
    {Alice, Bob} = connect_pair(),
    Bob2 =
        lists:foldl(
            fun(I, B) ->
                {ok, B2} = latch_peer:send(B, payload(I)),
                B2
            end,
            Bob, lists:seq(1, 6)),
    {Frames, Alice2} = read_raw(Alice, 6),
    %% process frames in a scrambled order; the skipped-key store covers it
    [P0, P1, P2, P3, P4, P5] = Frames,
    Alice3 = decrypt_frames(Alice2, [P4, P1, P5, P0, P3, P2]),
    ?assertEqual(6, maps:get(recv_total, session_map(Alice3))),
    ?assertEqual(0, maps:get(skipped_keys, session_map(Alice3))),
    latch_peer:close(Bob2),
    latch_peer:close(Alice3).

tampered_frame_rejected_test() ->
    {Alice, Bob} = connect_pair(),
    {ok, Bob2} = latch_peer:send(Bob, <<"integrity">>),
    {ok, Header, Blob, Alice2} = latch_peer:recv_frame(Alice),
    Size = byte_size(Blob) - 1,
    <<Head:Size/binary, Last:8>> = Blob,
    Bad = <<Head/binary, (Last bxor 16#01):8>>,
    ?assertEqual({error, authentication_failed},
                 latch_peer:decrypt(Alice2, Header, Bad)),
    %% the real blob still decrypts
    {ok, <<"integrity">>, Alice3} = latch_peer:decrypt(Alice2, Header, Blob),
    latch_peer:close(Bob2),
    latch_peer:close(Alice3).

close_signal_test() ->
    {Alice, Bob} = connect_pair(),
    latch_peer:close(Bob),
    ?assertEqual({error, closed}, latch_peer:recv(Alice)).

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

connect_pair() ->
    {ok, LSock, Port} = latch_peer:listen(),
    Me = self(),
    spawn_link(fun() ->
        Result =
            case latch_peer:accept(LSock) of
                {ok, Peer} ->
                    ok = latch_peer:hand_over(Peer, Me),
                    {ok, Peer};
                Error ->
                    Error
            end,
        Me ! {accepted, Result}
    end),
    {ok, Bob} = latch_peer:connect("127.0.0.1", Port),
    receive
        {accepted, {ok, Alice}} ->
            {Alice, Bob};
        {accepted, Other} ->
            error(Other)
    after 5000 ->
        error(accept_timeout)
    end.

payload(I) ->
    iolist_to_binary(io_lib:format("payload ~2..0B", [I])).

session_map(Peer) ->
    latch_session:to_map(latch_peer:session(Peer)).

read_raw(Peer, N) ->
    read_raw(Peer, N, []).

read_raw(Peer, 0, Acc) ->
    {lists:reverse(Acc), Peer};
read_raw(Peer, N, Acc) ->
    {ok, Header, Blob, Peer2} = latch_peer:recv_frame(Peer),
    read_raw(Peer2, N - 1, [{Header, Blob} | Acc]).

decrypt_frames(Peer, Frames) ->
    lists:foldl(
        fun({Header, Blob}, P) ->
            {ok, _Plain, P2} = latch_peer:decrypt(P, Header, Blob),
            P2
        end,
        Peer, Frames).
