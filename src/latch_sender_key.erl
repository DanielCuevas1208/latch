%% @doc Group messaging with a shared sender key.
%%
%% A sender key is a single chain key that one member owns. The owner ratchets
%% the chain for every message it sends. The other members hold a receiver
%% session for that chain. They can decrypt but they cannot send with it.
%% Every member creates its own sender session for its own messages.
%%
%% Each message carries:
%%
%% * a header with a key id and a message iteration
%% * an AES-256-GCM ciphertext bound to the header
%% * an Ed25519 signature over the header and ciphertext
%%
%% Receivers store skipped message keys, so out-of-order group messages
%% decrypt correctly within the skip window.
-module(latch_sender_key).

-include("latch.hrl").

-export([new_sender/1, new_receiver/1, sender_seed/1, encrypt/2, decrypt/3]).
-export([encode_sheader/1, decode_sheader/1, to_map/1]).
-export_type([latch_sheader/0]).

-define(MAX_SKIP, 1000).
-define(CURVE, ed25519).

-record(latch_sk_sender, {
    key_id :: binary(),
    chain :: binary(),
    sign_pub :: binary(),
    sign_priv :: binary(),
    iter = 0 :: non_neg_integer()
}).

-record(latch_sk_receiver, {
    key_id :: binary(),
    sign_pub :: binary(),
    chain :: binary(),
    iter = 0 :: non_neg_integer(),
    skipped = #{} :: map()
}).

%% @doc Create a sender session.
%%
%% Options `key_id' and `chain_key' make the session deterministic for tests.
-spec new_sender(map()) -> tuple().
new_sender(Opts) ->
    {SignPub, SignPriv} = crypto:generate_key(eddsa, ?CURVE),
    #latch_sk_sender{
        key_id = maps:get(key_id, Opts, latch_crypto:random_bytes(32)),
        chain = maps:get(chain_key, Opts, latch_crypto:random_bytes(32)),
        sign_pub = SignPub,
        sign_priv = SignPriv
    }.

%% @doc Create a receiver session from a sender seed.
-spec new_receiver(map()) -> tuple().
new_receiver(#{key_id := KeyId, chain_key := Chain, sign_pub := SignPub}) ->
    #latch_sk_receiver{key_id = KeyId, chain = Chain, sign_pub = SignPub}.

%% @doc The seed a sender distributes to the group members.
-spec sender_seed(tuple()) -> map().
sender_seed(#latch_sk_sender{key_id = KeyId, chain = Chain, sign_pub = SignPub}) ->
    #{key_id => KeyId, chain_key => Chain, sign_pub => SignPub}.

%% @doc Encrypt a message for the group. Returns {Header, Frame, Sender2}.
-spec encrypt(binary(), tuple()) -> {latch_sheader(), binary(), tuple()}.
encrypt(Plain, S = #latch_sk_sender{chain = Chain, iter = Iter}) ->
    {Chain2, MsgKey} = latch_kdf:chain_key_step(Chain),
    Header = #latch_sheader{key_id = S#latch_sk_sender.key_id, iter = Iter},
    AAD = encode_sheader(Header),
    Blob = latch_crypto:encrypt(MsgKey, Plain, AAD),
    Sig = crypto:sign(eddsa, none, <<AAD/binary, Blob/binary>>, [S#latch_sk_sender.sign_priv, ?CURVE]),
    {Header, <<Sig/binary, Blob/binary>>, S#latch_sk_sender{chain = Chain2, iter = Iter + 1}}.

%% @doc Decrypt a group message. Returns {ok, Plain, Receiver2} or {error, Reason}.
-spec decrypt(latch_sheader(), binary(), tuple()) -> {ok, binary(), tuple()} | {error, term()}.
decrypt(Header = #latch_sheader{key_id = KeyId, iter = Iter}, <<Sig:64/binary, Blob/binary>>,
        R0 = #latch_sk_receiver{}) ->
    case KeyId =:= R0#latch_sk_receiver.key_id of
        false ->
            {error, unknown_key_id};
        true ->
            case maps:find({KeyId, Iter}, R0#latch_sk_receiver.skipped) of
                {ok, MsgKey} ->
                    R1 = R0#latch_sk_receiver{
                        skipped = maps:remove({KeyId, Iter}, R0#latch_sk_receiver.skipped)
                    },
                    decrypt_with(R1, Header, Blob, Sig, MsgKey);
                error ->
                    decrypt_from_chain(R0, Header, Blob, Sig)
            end
    end.

%% @doc Encode a sender-key header to its 36-byte wire form.
-spec encode_sheader(latch_sheader()) -> binary().
encode_sheader(#latch_sheader{key_id = KeyId, iter = Iter}) ->
    <<KeyId/binary, Iter:32>>.

%% @doc Decode a 36-byte sender-key header.
-spec decode_sheader(binary()) -> latch_sheader().
decode_sheader(<<KeyId:32/binary, Iter:32>>) ->
    #latch_sheader{key_id = KeyId, iter = Iter}.

%% @doc Inspect a sender-key session.
-spec to_map(tuple()) -> map().
to_map(#latch_sk_sender{key_id = KeyId, iter = Iter}) ->
    #{kind => sender, key_id => KeyId, iter => Iter};
to_map(#latch_sk_receiver{key_id = KeyId, iter = Iter, skipped = Skipped}) ->
    #{kind => receiver, key_id => KeyId, iter => Iter, skipped_keys => maps:size(Skipped)}.

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

decrypt_with(R = #latch_sk_receiver{}, Header, Blob, Sig, MsgKey) ->
    case verify_signature(R#latch_sk_receiver.sign_pub, Header, Blob, Sig) of
        true ->
            case latch_crypto:decrypt(MsgKey, Blob, encode_sheader(Header)) of
                {ok, Plain} ->
                    {ok, Plain, R};
                error ->
                    {error, authentication_failed}
            end;
        false ->
            {error, bad_signature}
    end.

decrypt_from_chain(R = #latch_sk_receiver{iter = Nr, key_id = KeyId},
                   Header = #latch_sheader{iter = Iter}, Blob, Sig) ->
    case Iter < Nr of
        true ->
            {error, message_too_old};
        false when Iter - Nr > ?MAX_SKIP ->
            {error, gap_too_large};
        false ->
            R1 = skip_forward(R, KeyId, Iter),
            {Chain2, MsgKey} = latch_kdf:chain_key_step(R1#latch_sk_receiver.chain),
            R2 = R1#latch_sk_receiver{chain = Chain2, iter = Iter + 1},
            decrypt_with(R2, Header, Blob, Sig, MsgKey)
    end.

skip_forward(R = #latch_sk_receiver{iter = Nr}, KeyId, UntilIter) when UntilIter > Nr ->
    skip_forward_loop(R, KeyId, Nr, UntilIter);
skip_forward(R, _KeyId, _UntilIter) ->
    R.

skip_forward_loop(R = #latch_sk_receiver{chain = Chain}, KeyId, I, UntilIter) when I < UntilIter ->
    {Chain2, MsgKey} = latch_kdf:chain_key_step(Chain),
    Skipped2 = maps:put({KeyId, I}, MsgKey, R#latch_sk_receiver.skipped),
    skip_forward_loop(R#latch_sk_receiver{chain = Chain2, skipped = Skipped2}, KeyId, I + 1, UntilIter);
skip_forward_loop(R, _KeyId, _I, _UntilIter) ->
    R.

verify_signature(SignPub, Header, Blob, Sig) ->
    AAD = encode_sheader(Header),
    crypto:verify(eddsa, none, <<AAD/binary, Blob/binary>>, Sig, [SignPub, ?CURVE]).
