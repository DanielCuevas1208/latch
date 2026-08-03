%% @doc Key derivation for the Latch ratchet.
%%
%% Latch uses HKDF-SHA256 (RFC 5869) for key derivation.
%% The module exposes three operations:
%%
%% * {@link hkdf/4.} General HKDF with a caller-supplied salt, info, and length.
%% * {@link chain_key_step/1.} The symmetric ratchet. One message key and one
%%   next chain key derive from the current chain key.
%% * {@link root_key_step/2.} The DH ratchet. A new root key and a new chain
%%   key derive from the root key and a fresh DH output.
%%
%% The symmetric ratchet follows the Double Ratchet specification. HMAC-SHA256
%% with the constant byte 0x02 derives the message key. HMAC-SHA256 with the
%% constant byte 0x01 derives the next chain key.
-module(latch_kdf).

-export([hkdf/4, hkdf_extract/2, hkdf_expand/3, chain_key_step/1, root_key_step/2]).

-define(HASH, sha256).
-define(OUT_LEN, 32).
-define(CHAIN_NEXT, <<1:8>>).
-define(CHAIN_MSG, <<2:8>>).
-define(INFO_ROOT, <<"latch:v1:root">>).

%% @doc HKDF extract step. Returns the pseudorandom key (PRK).
-spec hkdf_extract(binary(), binary()) -> binary().
hkdf_extract(Salt, IKM) ->
    crypto:mac(hmac, ?HASH, Salt, IKM).

%% @doc HKDF expand step. Returns the requested output length.
-spec hkdf_expand(binary(), binary(), pos_integer()) -> binary().
hkdf_expand(PRK, Info, Len) when Len > 0, Len =< 255 * ?OUT_LEN ->
    expand(PRK, Info, Len, <<>>, 1).

%% @doc Full HKDF-SHA256.
-spec hkdf(binary(), binary(), binary(), pos_integer()) -> binary().
hkdf(Salt, IKM, Info, Len) ->
    hkdf_expand(hkdf_extract(Salt, IKM), Info, Len).

%% @doc Advance the symmetric ratchet one message.
%% Returns {NextChainKey, MessageKey}.
-spec chain_key_step(binary()) -> {binary(), binary()}.
chain_key_step(ChainKey) ->
    Next = crypto:mac(hmac, ?HASH, ChainKey, ?CHAIN_NEXT),
    MsgKey = crypto:mac(hmac, ?HASH, ChainKey, ?CHAIN_MSG),
    {Next, MsgKey}.

%% @doc Advance the DH ratchet with a fresh DH output.
%% Returns {NextRootKey, NewChainKey}, each 32 bytes.
-spec root_key_step(binary(), binary()) -> {binary(), binary()}.
root_key_step(RootKey, DHOutput) ->
    Out = hkdf(RootKey, DHOutput, ?INFO_ROOT, 64),
    split64(Out).

expand(PRK, Info, Len, Acc, Ctr) ->
    Prev = prev_block(Acc),
    Block = crypto:mac(hmac, ?HASH, PRK, <<Prev/binary, Info/binary, Ctr:8>>),
    NewAcc = <<Acc/binary, Block/binary>>,
    case byte_size(NewAcc) >= Len of
        true ->
            binary:part(NewAcc, 0, Len);
        false ->
            expand(PRK, Info, Len, NewAcc, Ctr + 1)
    end.

prev_block(<<>>) ->
    <<>>;
prev_block(Acc) ->
    binary:part(Acc, byte_size(Acc) - ?OUT_LEN, ?OUT_LEN).

split64(Out) ->
    {binary:part(Out, 0, 32), binary:part(Out, 32, 32)}.
