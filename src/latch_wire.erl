%% @doc Framing and socket helpers for Latch transports.
%%
%% Sockets use the `{packet, 4}' option. gen_tcp prefixes each packet with a
%% 4-byte length. This keeps every frame atomic on the wire.
%%
%% Every application frame is `<<Tag:8, Body/binary>>'.
%% Tag 1 is a handshake hello. Tag 2 is an encrypted message. Tag 3 is bye.
-module(latch_wire).

-export([tag_hello/0, tag_data/0, tag_bye/0]).
-export([encode_frame/2, decode_frame/1, encode_hello/2, decode_hello/1]).
-export([encode_hello_signed/4, decode_hello_signed/1]).
-export([listen/1, accept/1, connect/2, send/2, recv/1]).

-define(TAG_HELLO, 1).
-define(TAG_DATA, 2).
-define(TAG_BYE, 3).

%% @doc Frame tag for a handshake hello.
-spec tag_hello() -> byte().
tag_hello() -> ?TAG_HELLO.

%% @doc Frame tag for an encrypted message.
-spec tag_data() -> byte().
tag_data() -> ?TAG_DATA.

%% @doc Frame tag for a close.
-spec tag_bye() -> byte().
tag_bye() -> ?TAG_BYE.

%% @doc Wrap a tag and body into a wire frame.
-spec encode_frame(byte(), binary()) -> binary().
encode_frame(Tag, Body) ->
    <<Tag:8, Body/binary>>.

%% @doc Split a wire frame into {Tag, Body}.
-spec decode_frame(binary()) -> {byte(), binary()}.
decode_frame(<<Tag:8, Body/binary>>) ->
    {Tag, Body}.

%% @doc Encode a handshake hello body.
-spec encode_hello(binary(), binary()) -> binary().
encode_hello(IdentityPub, EphPub) ->
    <<IdentityPub/binary, EphPub/binary>>.

%% @doc Decode a handshake hello body into {IdentityPub, EphPub}.
-spec decode_hello(binary()) -> {binary(), binary()}.
decode_hello(<<IdentityPub:32/binary, EphPub:32/binary>>) ->
    {IdentityPub, EphPub}.

%% @doc Encode a signed handshake hello body.
%%
%% The body carries the identity key, the signing key, the ephemeral key, and
%% a 64-byte Ed25519 signature over those three keys.
-spec encode_hello_signed(binary(), binary(), binary(), binary()) -> binary().
encode_hello_signed(IdentityPub, SignPub, EphPub, Signature) ->
    <<IdentityPub/binary, SignPub/binary, EphPub/binary, Signature/binary>>.

%% @doc Decode a signed handshake hello body.
-spec decode_hello_signed(binary()) -> {binary(), binary(), binary(), binary()}.
decode_hello_signed(<<IdentityPub:32/binary, SignPub:32/binary,
                      EphPub:32/binary, Signature:64/binary>>) ->
    {IdentityPub, SignPub, EphPub, Signature}.

%% @doc Open a TCP listener on a port. Port 0 picks a free port.
-spec listen(inet:port_number()) -> {ok, gen_tcp:socket()} | {error, term()}.
listen(Port) ->
    gen_tcp:listen(Port, socket_opts()).

%% @doc Accept one TCP connection.
-spec accept(gen_tcp:socket()) -> {ok, gen_tcp:socket()} | {error, term()}.
accept(LSock) ->
    gen_tcp:accept(LSock, 10000).

%% @doc Connect to a TCP listener.
-spec connect(inet:hostname(), inet:port_number()) -> {ok, gen_tcp:socket()} | {error, term()}.
connect(Host, Port) ->
    gen_tcp:connect(Host, Port, socket_opts(), 10000).

%% @doc Send one frame.
-spec send(gen_tcp:socket(), iodata()) -> ok | {error, term()}.
send(Sock, IoData) ->
    gen_tcp:send(Sock, IoData).

%% @doc Receive one frame.
-spec recv(gen_tcp:socket()) -> {ok, binary()} | {error, term()}.
recv(Sock) ->
    gen_tcp:recv(Sock, 0).

socket_opts() ->
    [binary, {packet, 4}, {active, false}, {nodelay, true}, {reuseaddr, true}].
