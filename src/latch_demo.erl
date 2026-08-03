%% @doc Local demos for Latch.
%%
%% Three demos run on one machine over loopback TCP:
%%
%% * {@link pairwise/1.} Two peers exchange messages over a direct socket.
%%   They rotate the DH ratchet during the conversation.
%% * {@link shuffled/1.} Two peers exchange messages through a relay that
%%   delivers frames out of order. The skipped-key store handles it.
%% * {@link group/0.} Three members chat over a TCP hub using sender keys.
-module(latch_demo).

-include("latch.hrl").

-export([pairwise/1, shuffled/1, group/0, info/0]).

-define(SHUFFLE_BATCH, 3).
-define(TAG_DATA, 2).

%% @doc Run the pairwise socket demo. Count is the number of messages each
%% peer sends.
-spec pairwise(pos_integer()) -> ok.
pairwise(Count) ->
    title("Latch pairwise demo", "Two peers over a loopback TCP socket"),
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
    io:format("  bob listens on 127.0.0.1:~p~n", [Port]),
    case latch_peer:connect("127.0.0.1", Port) of
        {ok, Alice0} ->
            receive
                {accepted, {ok, Bob0}} ->
                    pairwise_main(Alice0, Bob0, Count);
                {accepted, {error, Error}} ->
                    io:format("  accept failed: ~p~n", [Error])
            end;
        {error, Error} ->
            io:format("  connect failed: ~p~n", [Error])
    end,
    ok.

%% @doc Run the out-of-order socket demo.
-spec shuffled(pos_integer()) -> ok.
shuffled(Count) ->
    title("Latch out-of-order demo", "A relay delivers frames out of order"),
    {ok, LSock} = latch_wire:listen(0),
    {ok, Port} = inet:port(LSock),
    Me = self(),
    spawn_link(fun() -> relay_main(LSock, Me) end),
    spawn_link(fun() -> Me ! {peer_a, connect_via(initiator, Port, Me)} end),
    spawn_link(fun() -> Me ! {peer_b, connect_via(responder, Port, Me)} end),
    receive relay_ready -> ok end,
    {ok, Alice0} = await(peer_a),
    {ok, Bob0} = await(peer_b),
    io:format("  relay on 127.0.0.1:~p delivers out of order in batches of ~p~n",
              [Port, ?SHUFFLE_BATCH]),
    shuffled_main(Alice0, Bob0, Count),
    ok.

%% @doc Run the group chat demo over a TCP hub.
-spec group() -> ok.
group() ->
    title("Latch group demo", "Three members, one sender key per member"),
    Members = [alice, bob, carol],
    Senders =
        maps:from_list([{Name, latch_sender_key:new_sender(#{})} || Name <- Members]),
    Seeds =
        maps:map(fun(_Name, Sender) -> latch_sender_key:sender_seed(Sender) end, Senders),
    Receivers =
        maps:from_list([{Name, other_receivers(Name, Members, Seeds)} || Name <- Members]),
    {ok, LSock} = latch_wire:listen(0),
    {ok, HubPort} = inet:port(LSock),
    Me = self(),
    spawn_link(fun() -> hub_main(LSock, 3, Me) end),
    Pids =
        maps:from_list([
            {Name,
             spawn_link(fun() ->
                 member_main(Name, HubPort, maps:get(Name, Senders),
                             maps:get(Name, Receivers))
             end)}
            || Name <- Members
        ]),
    receive hub_ready -> ok after 5000 -> ok end,
    timer:sleep(200),
    chat_script(Pids),
    timer:sleep(300),
    ok.

%% @doc Print environment information.
-spec info() -> ok.
info() ->
    io:format("Latch ~s~n", [latch:version()]),
    io:format("  OTP   ~s (ERTS ~s)~n", [erlang:system_info(otp_release),
                                        erlang:system_info(version)]),
    io:format("  crypto backend ~p~n", [crypto:info_lib()]),
    ok.

%% ---------------------------------------------------------------------------
%% Pairwise demo
%% ---------------------------------------------------------------------------

pairwise_main(Alice, Bob, Count) ->
    Burst = 2,
    Rounds = Count div Burst,
    Total = Rounds * Burst,
    io:format("  handshake complete. alice=initiator bob=responder~n"),
    io:format("  each round sends ~p messages. the DH ratchet advances when a~n"
              "      peer sees a new key, so keys stay fresh~n", [Burst]),
    Roots0 = {latch_session:root_hash(latch_peer:session(Alice)),
              latch_session:root_hash(latch_peer:session(Bob))},
    io:format("~n  [1] conversation with ~p messages each way~n", [Total]),
    {Alice2, Bob2, FirstRaw} = interleaved(Alice, Bob, Rounds, Burst),
    io:format("~n  [2] session summary~n"),
    show_pair("alice", Alice2),
    show_pair("bob", Bob2),
    forward_secrecy_check(Bob2, FirstRaw, Roots0),
    latch_peer:close(Alice2),
    latch_peer:close(Bob2).

interleaved(Alice, Bob, Rounds, Burst) ->
    lists:foldl(
        fun(Round, {A0, B0, FirstRaw}) ->
            A1 = send_burst(A0, Round, "alice", Burst),
            {B1, Raw} = recv_burst(B0, Round, "bob", Burst, FirstRaw),
            B2 = send_burst(B1, Round, "bob", Burst),
            {A2, _} = recv_burst(A1, Round, "alice", Burst, Raw),
            {A2, B2, Raw}
        end,
        {Alice, Bob, undefined}, lists:seq(1, Rounds)).

send_burst(Peer, Round, Name, Burst) ->
    lists:foldl(
        fun(K, P) ->
            Msg = message_payload(Name, (Round - 1) * Burst + K),
            {ok, P2} = latch_peer:send(P, Msg),
            io:format("    ~s -> : ~s [n=~p]~n", [Name, Msg, send_count(P2) - 1]),
            P2
        end,
        Peer, lists:seq(1, Burst)).

recv_burst(Peer, _Round, Name, Burst, FirstRaw) ->
    lists:foldl(
        fun(_K, {P, Raw}) ->
            case Raw of
                undefined ->
                    {ok, H0, Blob0, P0} = latch_peer:recv_frame(P),
                    {ok, Plain0, P1} = latch_peer:decrypt(P0, H0, Blob0),
                    print_received(Name, H0, Plain0,
                                   " (raw frame kept for the forward secrecy check)"),
                    {P1, {H0, Blob0}};
                _ ->
                    {ok, H, Plain, P1} = latch_peer:recv(P),
                    print_received(Name, H, Plain, ""),
                    {P1, Raw}
            end
        end,
        {Peer, FirstRaw}, lists:seq(1, Burst)).

print_received(Name, Header, Plain, Note) ->
    Ratchet =
        case Header#latch_header.pn > 0 of
            true -> " [DH ratchet]";
            false -> ""
        end,
    io:format("    ~s <- : ~s [dh=~s n=~p pn=~p]~s~s~n",
              [Name, Plain, short_pub(Header#latch_header.dh),
               Header#latch_header.n, Header#latch_header.pn, Ratchet, Note]).

forward_secrecy_check(Peer, {Header, Blob}, {RootBefore, _RootAfter}) ->
    io:format("~n  [3] forward secrecy check~n"),
    RootNow = latch_session:root_hash(latch_peer:session(Peer)),
    io:format("    bob root ratchet: ~s... -> ~s...~n",
              [hex_prefix(RootBefore), hex_prefix(RootNow)]),
    io:format("    bob tries to decrypt message 1 again with the current session: "),
    case latch_peer:decrypt(Peer, Header, Blob) of
        {error, _} ->
            io:format("failed. the old message key is gone.~n");
        {ok, _Plain, _} ->
            io:format("decrypted. forward secrecy does not hold!~n")
    end.

show_pair(Name, Peer) ->
    M = latch_session:to_map(latch_peer:session(Peer)),
    io:format("    ~-5s root=~s dh_send=~s dh_recv=~s send=~p recv=~p pn=~p skipped=~p~n",
              [Name, hex_prefix(maps:get(root_hash, M)),
               short_pub(maps:get(dh_send_pub, M)),
               short_pub(maps:get(dh_recv_pub, M)),
               maps:get(send_count, M), maps:get(recv_count, M),
               maps:get(prev_chain_length, M), maps:get(skipped_keys, M)]).

%% ---------------------------------------------------------------------------
%% Shuffled demo
%% ---------------------------------------------------------------------------

connect_via(Role, Port, Parent) ->
    case latch_wire:connect("127.0.0.1", Port) of
        {ok, Sock} ->
            case latch_peer:from_socket(Sock, Role) of
                {ok, Peer} ->
                    ok = latch_peer:hand_over(Peer, Parent),
                    {ok, Peer};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

await(Key) ->
    receive
        {Key, Result} -> Result
    after 10000 -> {error, timeout}
    end.

shuffled_main(Alice, Bob, Count) ->
    io:format("  handshake complete.~n"),
    io:format("  [1] alice sends ~p messages in one sending chain~n", [Count]),
    Alice2 =
        lists:foldl(
            fun(I, Peer1) ->
                Msg = message_payload("alice", I),
                {ok, Peer2} = latch_peer:send(Peer1, Msg),
                Peer2
            end,
            Alice, lists:seq(1, Count)),
    latch_peer:close(Alice2),
    io:format("  [2] bob receives them in shuffled order~n"),
    {Decrypted, MaxSkipped} = recv_until_closed(Bob, Count, 0, 0),
    io:format("  [3] result~n"),
    case Decrypted of
        Count ->
            io:format("    all ~p messages decrypted. max skipped keys held: ~p~n",
                      [Decrypted, MaxSkipped]);
        _ ->
            io:format("    only ~p of ~p decrypted~n", [Decrypted, Count])
    end,
    io:format("    bob session: ~p skipped keys remain~n",
              [maps:get(skipped_keys,
                        latch_session:to_map(latch_peer:session(Bob)))]),
    latch_peer:close(Bob).

recv_until_closed(Peer, Want, Acc, MaxSkipped) ->
    case latch_peer:recv(Peer) of
        {ok, Header, Plain, Peer2} ->
            SkippedBefore =
                maps:get(skipped_keys, latch_session:to_map(latch_peer:session(Peer))),
            io:format("    bob <- : ~s [n=~p] (skipped store: ~p)~n",
                      [Plain, Header#latch_header.n, SkippedBefore]),
            SkippedAfter =
                maps:get(skipped_keys, latch_session:to_map(latch_peer:session(Peer2))),
            recv_until_closed(Peer2, Want, Acc + 1, max(MaxSkipped, SkippedAfter));
        {error, closed} ->
            {Acc, MaxSkipped};
        {error, Reason} ->
            io:format("    receive ended: ~p~n", [Reason]),
            {Acc, MaxSkipped}
    end.

relay_main(LSock, Parent) ->
    {ok, SA} = latch_wire:accept(LSock),
    {ok, SB} = latch_wire:accept(LSock),
    Parent ! relay_ready,
    %% data frames shuffle in both directions. only the burst sender matters
    %% here, so this is deterministic regardless of connect order.
    spawn_link(fun() -> relay_forward(SA, SB, shuffle) end),
    relay_forward(SB, SA, shuffle).

relay_forward(Src, Dst, Mode) ->
    relay_loop(Src, Dst, Mode, []).

relay_loop(Src, Dst, Mode, Buffer) ->
    case latch_wire:recv(Src) of
        {ok, Frame} ->
            case latch_wire:decode_frame(Frame) of
                {?TAG_DATA, _} ->
                    case Mode of
                        in_order ->
                            ok = latch_wire:send(Dst, Frame),
                            relay_loop(Src, Dst, Mode, []);
                        shuffle ->
                            Buffer2 = [Frame | Buffer],
                            case length(Buffer2) >= ?SHUFFLE_BATCH of
                                true ->
                                    flush(Buffer2, Dst),
                                    relay_loop(Src, Dst, Mode, []);
                                false ->
                                    relay_loop(Src, Dst, Mode, Buffer2)
                            end
                    end;
                {_, _} ->
                    %% handshake and control frames stay in order
                    ok = latch_wire:send(Dst, Frame),
                    relay_loop(Src, Dst, Mode, [])
            end;
        {error, closed} ->
            flush(Buffer, Dst),
            gen_tcp:close(Dst),
            ok;
        _ ->
            ok
    end.

flush(Frames, Dst) ->
    lists:foreach(fun(Frame) -> ok = latch_wire:send(Dst, Frame) end, Frames).

%% ---------------------------------------------------------------------------
%% Group demo
%% ---------------------------------------------------------------------------

other_receivers(Name, Members, Seeds) ->
    maps:from_list([
        {Other, latch_sender_key:new_receiver(maps:get(Other, Seeds))}
        || Other <- Members, Other =/= Name
    ]).

hub_main(LSock, MemberCount, Parent) ->
    Socks =
        [begin
             {ok, Sock} = latch_wire:accept(LSock),
             Sock
         end
         || _ <- lists:seq(1, MemberCount)],
    Parent ! hub_ready,
    [spawn_link(fun() -> hub_relay(Sock, Others) end)
     || {Sock, Others} <- broadcast_pairs(Socks)],
    %% keep this process alive so the member sockets stay open
    receive
        stop -> ok
    end.

broadcast_pairs(Socks) ->
    [{Sock, [Other || Other <- Socks, Other =/= Sock]} || Sock <- Socks].

hub_relay(Sock, Others) ->
    case latch_wire:recv(Sock) of
        {ok, Frame} ->
            lists:foreach(fun(Other) -> ok = latch_wire:send(Other, Frame) end, Others),
            hub_relay(Sock, Others);
        _ ->
            ok
    end.

member_main(Name, Port, Sender, Receivers) ->
    case latch_wire:connect("127.0.0.1", Port) of
        {ok, Sock} ->
            spawn_link(fun() -> member_recv_loop(Sock, Receivers, Name) end),
            member_send_loop(Sock, Sender, Name);
        {error, Reason} ->
            io:format("  ~s failed to join the hub: ~p~n", [Name, Reason])
    end.

member_send_loop(Sock, Sender0, Name) ->
    receive
        {send, Message} ->
            {Header, Frame, Sender2} =
                latch_sender_key:encrypt(iolist_to_binary(Message), Sender0),
            Wire = <<(member_tag(Name)):8,
                     (latch_sender_key:encode_sheader(Header))/binary,
                     Frame/binary>>,
            ok = latch_wire:send(Sock, Wire),
            io:format("    ~s -> group: ~s~n", [Name, Message]),
            member_send_loop(Sock, Sender2, Name);
        stop ->
            ok
    end.

member_recv_loop(Sock, Receivers, Name) ->
    case latch_wire:recv(Sock) of
        {ok, <<FromTag:8, HeaderBin:36/binary, Rest/binary>>} ->
            From = member_name(FromTag),
            case maps:find(From, Receivers) of
                {ok, Receiver0} ->
                    Header = latch_sender_key:decode_sheader(HeaderBin),
                    case latch_sender_key:decrypt(Header, Rest, Receiver0) of
                        {ok, Plain, Receiver1} ->
                            io:format("    ~s <- group (~s): ~s~n",
                                      [Name, From, Plain]),
                            member_recv_loop(Sock,
                                             maps:put(From, Receiver1, Receivers), Name);
                        {error, Reason} ->
                            io:format("    ~s: rejected ~s message: ~p~n",
                                      [Name, From, Reason]),
                            member_recv_loop(Sock, Receivers, Name)
                    end;
                error ->
                    io:format("    ~s: no receiver for sender ~s~n", [Name, From]),
                    member_recv_loop(Sock, Receivers, Name)
            end;
        {error, closed} ->
            ok;
        _ ->
            ok
    end.

chat_script(Pids) ->
    io:format("~n  a short chat over the hub~n"),
    tell(Pids, alice, "hello everyone, this is alice"),
    timer:sleep(120),
    tell(Pids, bob, "hi alice, bob here"),
    timer:sleep(120),
    tell(Pids, carol, "yo bob, carol here"),
    timer:sleep(120),
    tell(Pids, alice, "each message is signed and uses a fresh key"),
    timer:sleep(120),
    tell(Pids, bob, "confirmed"),
    timer:sleep(300).

tell(Pids, Name, Message) ->
    Pid = maps:get(Name, Pids),
    Pid ! {send, Message},
    ok.

%% ---------------------------------------------------------------------------
%% Display helpers
%% ---------------------------------------------------------------------------

title(Name, Subtitle) ->
    io:format("~n~ts~n~ts~n", [Name, string:copies("-", length(Name))]),
    io:format("~ts~n~n", [Subtitle]).

message_payload(Name, I) ->
    iolist_to_binary(io_lib:format("~s message ~2..0B", [Name, I])).

send_count(Peer) ->
    maps:get(send_count, latch_session:to_map(latch_peer:session(Peer))).

short_pub(undefined) ->
    "none";
short_pub(Bin) when is_binary(Bin), byte_size(Bin) >= 4 ->
    <<A, B, C, D, _/binary>> = Bin,
    iolist_to_binary(io_lib:format("~2.16.0B~2.16.0B~2.16.0B~2.16.0B", [A, B, C, D])).

hex_prefix(Hex) ->
    case byte_size(Hex) >= 8 of
        true ->
            binary:part(Hex, 0, 8);
        false ->
            Hex
    end.

member_tag(alice) -> 1;
member_tag(bob) -> 2;
member_tag(carol) -> 3.

member_name(1) -> alice;
member_name(2) -> bob;
member_name(3) -> carol.
