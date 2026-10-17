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
%% The handshake is signed. A peer authenticates its key-exchange material
%% with an Ed25519 identity signing key. The peer binds its X25519 identity
%% key, its signing key, and its ephemeral key in one signature. The other
%% peer verifies the signature before it derives a session. A peer that
%% cannot prove the signing key is rejected. There is no external trust root,
%% so a caller must still verify the peer's signing key out of band.
-module(latch_agreement).

-include("latch.hrl").

-export([new_identity/0, new_identity_signed/0, new_ephemeral/0]).
-export([sign_hello/2, verify_hello/4, hello_payload/3]).
-export([fingerprint/1, fingerprint_digest/1, fingerprints_match/2]).
-export([shared_secret/4, session/3, session/4]).
-export_type([latch_identity/0]).

-define(CURVE, x25519).
-define(SIGN_CURVE, ed25519).
-define(INFO, <<"latch:v1:agreement">>).
-define(HELLO_TAG, <<"latch:v1:hello">>).
-define(ZERO_SALT, <<0:256>>).

%% @doc Generate a new X25519 identity key pair. Returns {Pub, Priv}.
-spec new_identity() -> {binary(), binary()}.
new_identity() ->
    crypto:generate_key(ecdh, ?CURVE).

%% @doc Generate a signed identity for a peer.
%%
%% The identity holds an X25519 pair for key agreement and an Ed25519 pair
%% for signing the handshake.
-spec new_identity_signed() -> latch_identity().
new_identity_signed() ->
    #latch_identity{
        id = crypto:generate_key(ecdh, ?CURVE),
        sign = crypto:generate_key(eddsa, ?SIGN_CURVE)
    }.

%% @doc Generate a new X25519 ephemeral key pair. Returns {Pub, Priv}.
-spec new_ephemeral() -> {binary(), binary()}.
new_ephemeral() ->
    crypto:generate_key(ecdh, ?CURVE).

%% @doc The exact bytes the handshake signature covers.
%%
%% The payload binds the identity key, the signing key, and the ephemeral key
%% of one peer. A peer cannot substitute another ephemeral key without
%% breaking the signature.
-spec hello_payload(binary(), binary(), binary()) -> binary().
hello_payload(IdPub, SignPub, EphPub) ->
    <<?HELLO_TAG/binary, IdPub/binary, SignPub/binary, EphPub/binary>>.

%% @doc Sign the peer's hello with its identity signing key.
%% Returns a 64-byte Ed25519 signature.
-spec sign_hello(latch_identity(), binary()) -> binary().
sign_hello(#latch_identity{id = {IdPub, _IdPriv},
                           sign = {SignPub, SignPriv}}, EphPub) ->
    crypto:sign(eddsa, none, hello_payload(IdPub, SignPub, EphPub),
                [SignPriv, ?SIGN_CURVE]).

%% @doc Verify a peer's signed hello. Returns true or false.
-spec verify_hello(binary(), binary(), binary(), binary()) -> boolean().
verify_hello(IdPub, SignPub, EphPub, Sig) ->
    crypto:verify(eddsa, none, hello_payload(IdPub, SignPub, EphPub),
                  Sig, [SignPub, ?SIGN_CURVE]).

%% @doc The SHA-256 digest of a signing public key.
%%
%% The digest is the raw fingerprint. Use {@link fingerprint/1.} for a
%% human-readable form.
-spec fingerprint_digest(binary()) -> binary().
fingerprint_digest(SignPub) when is_binary(SignPub), byte_size(SignPub) =:= 32 ->
    crypto:hash(sha256, SignPub).

%% @doc Format a signing public key as a grouped fingerprint string.
%%
%% The string has 16 groups of four uppercase hex digits. Peers can read the
%% groups aloud to confirm an identity out of band.
-spec fingerprint(binary()) -> string().
fingerprint(SignPub) ->
    format_fingerprint(fingerprint_digest(SignPub)).

%% @doc Compare two fingerprint strings. Ignores case and whitespace.
-spec fingerprints_match(string() | binary(), string() | binary()) -> boolean().
fingerprints_match(Left, Right) ->
    normalize_fingerprint(Left) =:= normalize_fingerprint(Right).

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

format_fingerprint(Digest) ->
    Hex = binary_to_list(string:uppercase(binary:encode_hex(Digest))),
    Groups = [lists:sublist(Hex, I, 4) || I <- lists:seq(1, length(Hex), 4)],
    string:join(Groups, " ").

normalize_fingerprint(Value) when is_binary(Value) ->
    normalize_fingerprint(binary_to_list(Value));
normalize_fingerprint(Value) when is_list(Value) ->
    string:uppercase(
      re:replace(string:trim(Value),
                 "[^0-9A-Fa-f]", "", [global, {return, list}])).
