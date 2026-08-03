%% @doc Key agreement for two Latch peers.
%%
%% The handshake uses two X25519 key pairs per peer. A peer holds an identity
%% key and an ephemeral key. Peers exchange the public halves over the
%% transport. Each peer derives the same shared secret from three DH outputs:
%%
%% * ephemeral of A with ephemeral of B
%% * ephemeral of A with identity of B
%% * identity of A with ephemeral of B
%%
%% The three DH outputs are sorted and fed to HKDF-SHA256. Sorting makes the
%% derivation independent of which peer speaks first. The shared secret seeds
%% the double ratchet session.
%%
%% Note: release one does not sign the handshake. The identity is therefore
%% not authenticated against an active attacker on an untrusted network.
-module(latch_agreement).

-export([new_identity/0, new_ephemeral/0, shared_secret/4, session/3, session/4]).

-define(CURVE, x25519).
-define(INFO, <<"latch:v1:agreement">>).
-define(ZERO_SALT, <<0:256>>).

%% @doc Generate a new X25519 identity key pair. Returns {Pub, Priv}.
-spec new_identity() -> {binary(), binary()}.
new_identity() ->
    crypto:generate_key(ecdh, ?CURVE).

%% @doc Generate a new X25519 ephemeral key pair. Returns {Pub, Priv}.
-spec new_ephemeral() -> {binary(), binary()}.
new_ephemeral() ->
    crypto:generate_key(ecdh, ?CURVE).

%% @doc Derive the shared secret between two peers.
%%
%% Args are MyIdPriv, MyEphPriv, PeerIdPub, PeerEphPub. Both peers compute the
%% same secret.
-spec shared_secret(binary(), binary(), binary(), binary()) -> binary().
shared_secret(MyIdPriv, MyEphPriv, PeerIdPub, PeerEphPub) ->
    Dh1 = crypto:compute_key(ecdh, PeerEphPub, MyEphPriv, ?CURVE),
    Dh2 = crypto:compute_key(ecdh, PeerIdPub, MyEphPriv, ?CURVE),
    Dh3 = crypto:compute_key(ecdh, PeerEphPub, MyIdPriv, ?CURVE),
    [A, B, C] = lists:sort([Dh1, Dh2, Dh3]),
    latch_kdf:hkdf(?ZERO_SALT, <<A/binary, B/binary, C/binary>>, ?INFO, 32).

%% @doc Build a double ratchet session from the handshake material.
%%
%% MyKeys are {IdentityKey, EphemeralKey} where each key is {Pub, Priv}.
%% PeerKeys are {PeerIdentityPub, PeerEphemeralPub}.
-spec session(initiator | responder, {tuple(), tuple()}, {binary(), binary()}) -> latch_session:session().
session(Role, MyKeys, PeerKeys) ->
    session(Role, MyKeys, PeerKeys, #{}).

%% @doc Build a double ratchet session with extra options.
%%
%% Extra options are passed through to {@link latch_session:new/2.}
-spec session(initiator | responder, {tuple(), tuple()}, {binary(), binary()}, map()) -> latch_session:session().
session(Role, {IdKey, EphKey}, {PeerIdPub, PeerEphPub}, Opts) ->
    {_IdPub, IdPriv} = IdKey,
    {EphPub, EphPriv} = EphKey,
    Shared = shared_secret(IdPriv, EphPriv, PeerIdPub, PeerEphPub),
    latch_session:new(Shared, Opts#{role => Role, init_dh_pair => {EphPub, EphPriv}, peer_dh => PeerEphPub}).
