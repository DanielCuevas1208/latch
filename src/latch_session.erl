%% @doc The Latch double ratchet session.
%%
%% A session encrypts messages from one peer to another. Every message uses a
%% fresh symmetric key from a chain (the symmetric ratchet). The DH ratchet
%% runs when a peer receives a message with a new DH public key. It derives a
%% new root key and new chains from a fresh X25519 output. Old root keys and
%% old chain keys are deleted. This gives forward secrecy.
%%
%% The initiator performs the first DH ratchet at session start. The
%% responder runs it on the first received message. After that the ratchet
%% alternates naturally with each reply.
%%
%% The receiving side stores skipped message keys. Out-of-order messages and
%% gaps up to `max_skip' decrypt from that store. Messages older than the
%% current chain position are rejected.
-module(latch_session).

-include("latch.hrl").

-export([new/2, encrypt/2, decrypt/3]).
-export([encode_header/1, decode_header/1, to_map/1, root_hash/1]).

-define(AAD_TAG, <<"latch:ratchet:v1">>).
-define(CURVE, x25519).

-opaque session() :: #latch_session{}.
-export_type([session/0]).

%% @doc Create a session from a 32-byte shared secret.
%%
%% Options:
%% <ul>
%% <li>`role' (`initiator' or `responder') - required.</li>
%% <li>`init_dh_pair' - the initial sending DH key pair, as {Pub, Priv}.</li>
%% <li>`peer_dh' - the peer's initial DH public key.</li>
%% <li>`max_skip' - maximum skipped messages kept for out-of-order delivery.</li>
%% </ul>
-spec new(binary(), map()) -> session().
new(SharedSecret, Opts) when is_binary(SharedSecret), byte_size(SharedSecret) =:= 32 ->
    Role = maps:get(role, Opts),
    DhSend = maps:get(init_dh_pair, Opts),
    MaxSkip = maps:get(max_skip, Opts, ?DEFAULT_MAX_SKIP),
    case Role of
        initiator ->
            PeerDh = maps:get(peer_dh, Opts),
            DHOutput = crypto:compute_key(ecdh, PeerDh, element(2, DhSend), ?CURVE),
            {Root2, SendChain} = latch_kdf:root_key_step(SharedSecret, DHOutput),
            #latch_session{
                role = initiator,
                root = Root2,
                dh_send = DhSend,
                dh_recv_pub = PeerDh,
                chain_send = SendChain,
                chain_recv = undefined,
                max_skip = MaxSkip
            };
        responder ->
            %% The responder derives its chains when it receives the first
            %% message. Before that it cannot send.
            #latch_session{
                role = responder,
                root = SharedSecret,
                dh_send = DhSend,
                dh_recv_pub = undefined,
                chain_send = undefined,
                chain_recv = undefined,
                max_skip = MaxSkip
            }
    end.

%% @doc Encrypt a binary message. Returns {Header, CipherBlob, Session2}.
%%
%% The header must reach the peer verbatim. It authenticates the ciphertext.
%% A responder cannot encrypt before it has received the first message.
-spec encrypt(binary(), session()) -> {latch_header(), binary(), session()}.
encrypt(Plain, Session0 = #latch_session{chain_send = Chain}) when is_binary(Chain) ->
    {Chain2, MsgKey} = latch_kdf:chain_key_step(Chain),
    Header = #latch_header{
        dh = element(1, Session0#latch_session.dh_send),
        pn = Session0#latch_session.prev_chain_length,
        n = Session0#latch_session.send_count
    },
    Blob = latch_crypto:encrypt(MsgKey, Plain, aad(Header)),
    Session2 = Session0#latch_session{
        chain_send = Chain2,
        send_count = Session0#latch_session.send_count + 1,
        sent_total = Session0#latch_session.sent_total + 1
    },
    {Header, Blob, Session2};
encrypt(_Plain, _Session) ->
    error({latch, not_initialized}).

%% @doc Decrypt a message. Returns {ok, Plain, Session2} or {error, Reason}.
-spec decrypt(latch_header(), binary(), session()) -> {ok, binary(), session()} | {error, term()}.
decrypt(Header = #latch_header{dh = Dh, n = N}, Blob, Session0) ->
    case maps:find({Dh, N}, Session0#latch_session.skipped) of
        {ok, MsgKey} ->
            Session1 = Session0#latch_session{
                skipped = maps:remove({Dh, N}, Session0#latch_session.skipped)
            },
            decrypt_with(Session1, Header, Blob, MsgKey);
        error ->
            case Dh =:= Session0#latch_session.dh_recv_pub of
                true ->
                    decrypt_from_chain(Session0, Header, Blob);
                false ->
                    ratchet_and_decrypt(Session0, Header, Blob)
            end
    end.

%% @doc Encode a header to its 40-byte wire form.
-spec encode_header(latch_header()) -> binary().
encode_header(#latch_header{dh = Dh, pn = Pn, n = N}) ->
    <<Dh/binary, Pn:32, N:32>>.

%% @doc Decode a 40-byte wire header.
-spec decode_header(binary()) -> latch_header().
decode_header(<<Dh:32/binary, Pn:32, N:32>>) ->
    #latch_header{dh = Dh, pn = Pn, n = N}.

%% @doc Inspect a session. Returns a map with non-secret values.
-spec to_map(session()) -> map().
to_map(S = #latch_session{}) ->
    #{role => S#latch_session.role,
      root_hash => root_hash(S),
      dh_send_pub => element(1, S#latch_session.dh_send),
      dh_recv_pub => S#latch_session.dh_recv_pub,
      send_count => S#latch_session.send_count,
      recv_count => S#latch_session.recv_count,
      prev_chain_length => S#latch_session.prev_chain_length,
      max_skip => S#latch_session.max_skip,
      skipped_keys => maps:size(S#latch_session.skipped),
      sent_total => S#latch_session.sent_total,
      recv_total => S#latch_session.recv_total}.

%% @doc Hex digest of the current root key. For displays and tests.
-spec root_hash(session()) -> binary().
root_hash(S) ->
    binary:encode_hex(crypto:hash(sha256, S#latch_session.root)).

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

aad(Header) ->
    <<?AAD_TAG/binary, (encode_header(Header))/binary>>.

decrypt_with(Session, Header, Blob, MsgKey) ->
    case latch_crypto:decrypt(MsgKey, Blob, aad(Header)) of
        {ok, Plain} ->
            Session2 = Session#latch_session{recv_total = Session#latch_session.recv_total + 1},
            {ok, Plain, Session2};
        error ->
            {error, authentication_failed}
    end.

decrypt_from_chain(S = #latch_session{recv_count = Nr, max_skip = Max, dh_recv_pub = Dh},
                   Header = #latch_header{n = N}, Blob) ->
    case N < Nr of
        true ->
            {error, message_too_old};
        false when N - Nr > Max ->
            {error, gap_too_large};
        false ->
            S1 = skip_forward(S, Dh, N),
            {Chain2, MsgKey} = latch_kdf:chain_key_step(S1#latch_session.chain_recv),
            S2 = S1#latch_session{chain_recv = Chain2, recv_count = N + 1},
            decrypt_with(S2, Header, Blob, MsgKey)
    end.

ratchet_and_decrypt(S = #latch_session{}, Header = #latch_header{dh = NewDh, pn = Pn}, Blob) ->
    S1 = skip_own_send(S, Pn),
    S2 = do_dh_ratchet(S1, NewDh),
    decrypt_from_chain(S2, Header, Blob).

skip_own_send(S = #latch_session{chain_send = undefined}, _Pn) ->
    S;
skip_own_send(S = #latch_session{send_count = Ns}, Pn) when Pn > Ns ->
    DhPub = element(1, S#latch_session.dh_send),
    S2 = skip_own_loop(S, DhPub, Ns, Pn),
    S2#latch_session{send_count = Pn};
skip_own_send(S, _Pn) ->
    S.

skip_own_loop(S = #latch_session{chain_send = Chain}, DhPub, I, Pn) when I < Pn ->
    {Chain2, MsgKey} = latch_kdf:chain_key_step(Chain),
    Skipped2 = maps:put({DhPub, I}, MsgKey, S#latch_session.skipped),
    skip_own_loop(S#latch_session{chain_send = Chain2, skipped = Skipped2}, DhPub, I + 1, Pn);
skip_own_loop(S, _DhPub, _I, _Pn) ->
    S.

do_dh_ratchet(S = #latch_session{dh_send = SendPair, root = Root}, NewDh) ->
    {_SendPub, SendPriv} = SendPair,
    DHOut1 = crypto:compute_key(ecdh, NewDh, SendPriv, ?CURVE),
    {Root1, NewRecvChain} = latch_kdf:root_key_step(Root, DHOut1),
    {NewPub2, NewPriv2} = crypto:generate_key(ecdh, ?CURVE),
    DHOut2 = crypto:compute_key(ecdh, NewDh, NewPriv2, ?CURVE),
    {Root2, NewSendChain} = latch_kdf:root_key_step(Root1, DHOut2),
    S#latch_session{
        root = Root2,
        dh_recv_pub = NewDh,
        chain_recv = NewRecvChain,
        recv_count = 0,
        prev_chain_length = S#latch_session.send_count,
        dh_send = {NewPub2, NewPriv2},
        chain_send = NewSendChain,
        send_count = 0
    }.

skip_forward(S = #latch_session{recv_count = Nr}, Dh, UntilN) when UntilN > Nr ->
    skip_forward_loop(S, Dh, Nr, UntilN);
skip_forward(S, _Dh, _UntilN) ->
    S.

skip_forward_loop(S = #latch_session{chain_recv = Chain}, Dh, I, UntilN) when I < UntilN ->
    {Chain2, MsgKey} = latch_kdf:chain_key_step(Chain),
    Skipped2 = maps:put({Dh, I}, MsgKey, S#latch_session.skipped),
    skip_forward_loop(S#latch_session{chain_recv = Chain2, skipped = Skipped2}, Dh, I + 1, UntilN);
skip_forward_loop(S, _Dh, _I, _UntilN) ->
    S.
