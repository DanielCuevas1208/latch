%% @doc A Latch peer that talks over a TCP socket.
%%
%% A peer owns one socket and one double ratchet session. The module performs
%% the key agreement handshake, then encrypts and decrypts messages over the
%% socket.
%%
%% The dialing peer is the session `initiator'. The accepting peer is the
%% `responder'. Roles are fixed at connect time.
%%
%% The handshake is signed. Each peer proves its identity signing key before
%% the session starts. A peer with an invalid signature is rejected with
%% `{error, bad_signature}'. Call {@link identity/1.} to read the verified
%% signing key of the remote peer.
-module(latch_peer).

-include("latch.hrl").

-define(TAG_HELLO, 1).
-define(TAG_DATA, 2).
-define(TAG_BYE, 3).

-export([listen/0, accept/1, connect/2, from_socket/2]).
-export([send/2, recv/1, recv_frame/1, decrypt/3, close/1]).
-export([session/1, identity/1, fingerprint/1, confirm_fingerprint/2, hand_over/2]).

-export_type([peer/0]).

-record(latch_peer, {
    sock :: gen_tcp:socket(),
    session :: latch_session:session(),
    role :: initiator | responder,
    identity :: binary() | undefined
}).

-opaque peer() :: #latch_peer{}.

%% @doc Open a listener on a free loopback port. Returns {ok, LSock, Port}.
-spec listen() -> {ok, gen_tcp:socket(), inet:port_number()} | {error, term()}.
listen() ->
    case latch_wire:listen(0) of
        {ok, LSock} ->
            {ok, Port} = inet:port(LSock),
            {ok, LSock, Port};
        Error ->
            Error
    end.

%% @doc Accept one connection and complete the responder handshake.
-spec accept(gen_tcp:socket()) -> {ok, peer()} | {error, term()}.
accept(LSock) ->
    case latch_wire:accept(LSock) of
        {ok, Sock} ->
            from_socket(Sock, responder);
        Error ->
            Error
    end.

%% @doc Dial a peer and complete the initiator handshake.
-spec connect(inet:hostname(), inet:port_number()) -> {ok, peer()} | {error, term()}.
connect(Host, Port) ->
    case latch_wire:connect(Host, Port) of
        {ok, Sock} ->
            from_socket(Sock, initiator);
        Error ->
            Error
    end.

%% @doc Wrap an existing connected socket and run the handshake for Role.
-spec from_socket(gen_tcp:socket(), initiator | responder) -> {ok, peer()} | {error, term()}.
from_socket(Sock, Role) ->
    Identity = latch_agreement:new_identity_signed(),
    EphKey = latch_agreement:new_ephemeral(),
    case Role of
        initiator ->
            Hello = signed_hello(Identity, EphKey),
            case latch_wire:send(
                   Sock,
                   latch_wire:encode_frame(latch_wire:tag_hello(), Hello)) of
                ok ->
                    finish_handshake(Sock, Role, Identity, EphKey);
                Error ->
                    Error
            end;
        responder ->
            finish_handshake(Sock, Role, Identity, EphKey)
    end.

%% @doc Encrypt and send one message. Returns {ok, Peer2}.
-spec send(peer(), iodata()) -> {ok, peer()} | {error, term()}.
send(#latch_peer{sock = Sock, session = Session0} = Peer, Plain) ->
    {Header, Blob, Session2} = latch_session:encrypt(iolist_to_binary(Plain), Session0),
    Body = <<(latch_session:encode_header(Header))/binary, Blob/binary>>,
    case latch_wire:send(Sock, latch_wire:encode_frame(latch_wire:tag_data(), Body)) of
        ok ->
            {ok, Peer#latch_peer{session = Session2}};
        Error ->
            Error
    end.

%% @doc Receive and decrypt one message. Returns {ok, Header, Plain, Peer2}.
-spec recv(peer()) -> {ok, latch_header(), binary(), peer()} | {error, term()}.
recv(#latch_peer{session = Session0} = Peer) ->
    case recv_frame(Peer) of
        {ok, Header, Blob, Peer1} ->
            case latch_session:decrypt(Header, Blob, Session0) of
                {ok, Plain, Session2} ->
                    {ok, Header, Plain, Peer1#latch_peer{session = Session2}};
                {error, Reason} ->
                    {error, Reason}
            end;
        Error ->
            Error
    end.

%% @doc Receive one raw encrypted frame without decrypting.
-spec recv_frame(peer()) -> {ok, latch_header(), binary(), peer()} | {error, term()}.
recv_frame(#latch_peer{sock = Sock} = Peer) ->
    case latch_wire:recv(Sock) of
        {ok, Frame} ->
            case latch_wire:decode_frame(Frame) of
                {?TAG_DATA, <<HeaderBin:40/binary, Blob/binary>>} ->
                    {ok, latch_session:decode_header(HeaderBin), Blob, Peer};
                {?TAG_BYE, _} ->
                    {error, closed};
                _ ->
                    {error, protocol_error}
            end;
        {error, closed} ->
            {error, closed};
        Error ->
            Error
    end.

%% @doc Decrypt a raw frame with the peer session.
-spec decrypt(peer(), latch_header(), binary()) -> {ok, binary(), peer()} | {error, term()}.
decrypt(#latch_peer{session = Session0} = Peer, Header, Blob) ->
    case latch_session:decrypt(Header, Blob, Session0) of
        {ok, Plain, Session2} ->
            {ok, Plain, Peer#latch_peer{session = Session2}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Transfer socket ownership to Pid.
%%
%% Useful when a helper process finishes a handshake and hands the peer to
%% the caller. Without this, the socket closes when the helper exits.
-spec hand_over(peer(), pid()) -> ok.
hand_over(#latch_peer{sock = Sock}, Pid) ->
    ok = gen_tcp:controlling_process(Sock, Pid),
    ok.

%% @doc Close the underlying socket.
-spec close(peer()) -> ok.
close(#latch_peer{sock = Sock}) ->
    gen_tcp:close(Sock).

%% @doc The current session of the peer.
-spec session(peer()) -> latch_session:session().
session(#latch_peer{session = Session}) ->
    Session.

%% @doc The remote peer's verified identity signing key.
-spec identity(peer()) -> binary() | undefined.
identity(#latch_peer{identity = Identity}) ->
    Identity.

%% @doc The remote peer's signing-key fingerprint.
%%
%% Returns a grouped hex string. Use it to confirm the peer out of band.
-spec fingerprint(peer()) -> string() | undefined.
fingerprint(#latch_peer{identity = undefined}) ->
    undefined;
fingerprint(#latch_peer{identity = SignPub}) ->
    latch_agreement:fingerprint(SignPub).

%% @doc Confirm the remote peer against an expected fingerprint.
%%
%% The expected value may use any case and spacing. Returns `ok' on a match.
%% Returns `{error, mismatch}' when the fingerprint differs.
-spec confirm_fingerprint(peer(), string() | binary()) -> ok | {error, mismatch | no_identity}.
confirm_fingerprint(#latch_peer{identity = undefined}, _Expected) ->
    {error, no_identity};
confirm_fingerprint(#latch_peer{identity = SignPub}, Expected) ->
    case latch_agreement:fingerprints_match(
           latch_agreement:fingerprint(SignPub), Expected) of
        true -> ok;
        false -> {error, mismatch}
    end.

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

signed_hello(Identity, EphKey) ->
    #latch_identity{id = {IdPub, _IdPriv},
                    sign = {SignPub, _SignPriv}} = Identity,
    {EphPub, _EphPriv} = EphKey,
    latch_wire:encode_hello_signed(
      IdPub, SignPub, EphPub,
      latch_agreement:sign_hello(Identity, EphPub)).

finish_handshake(Sock, Role, Identity, EphKey) ->
    case latch_wire:recv(Sock) of
        {ok, Frame} ->
            case latch_wire:decode_frame(Frame) of
                {?TAG_HELLO, Hello} ->
                    verify_hello_and_finish(Sock, Role, Identity, EphKey, Hello);
                _ ->
                    {error, protocol_error}
            end;
        Error ->
            Error
    end.

verify_hello_and_finish(Sock, Role, Identity, EphKey, Hello) ->
    try latch_wire:decode_hello_signed(Hello) of
        {PeerIdPub, PeerSignPub, PeerEphPub, Sig} ->
            case latch_agreement:verify_hello(PeerIdPub, PeerSignPub, PeerEphPub, Sig) of
                false ->
                    {error, bad_signature};
                true ->
                    send_reply(Role, Sock, Identity, EphKey),
                    Session = latch_agreement:session(
                                Role,
                                {Identity#latch_identity.id, EphKey},
                                {PeerIdPub, PeerEphPub}),
                    {ok, #latch_peer{sock = Sock, session = Session, role = Role,
                                     identity = PeerSignPub}}
            end
    catch
        error:function_clause ->
            {error, protocol_error}
    end.

send_reply(responder, Sock, Identity, EphKey) ->
    ok = latch_wire:send(
           Sock,
           latch_wire:encode_frame(latch_wire:tag_hello(),
                                   signed_hello(Identity, EphKey)));
send_reply(initiator, _Sock, _Identity, _EphKey) ->
    ok.
