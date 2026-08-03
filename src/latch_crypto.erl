%% @doc Authenticated encryption for Latch messages.
%%
%% Each message is encrypted with AES-256-GCM from the standard `crypto'
%% module. The ciphertext carries the 12-byte random IV, the ciphertext, and
%% the 16-byte GCM tag. The caller passes the associated data (AAD).
%% Authentication covers both the ciphertext and the AAD.
-module(latch_crypto).

-export([encrypt/3, encrypt/4, decrypt/3, random_bytes/1]).

-define(CIPHER, aes_256_gcm).
-define(IV_LEN, 12).
-define(TAG_LEN, 16).

%% @doc Encrypt Plain with a fresh random IV.
-spec encrypt(binary(), binary(), binary()) -> binary().
encrypt(Key, Plain, AAD) ->
    encrypt(Key, random_bytes(?IV_LEN), Plain, AAD).

%% @doc Encrypt Plain with an explicit IV.
%% Deterministic for fixed inputs. Useful for tests and vectors.
-spec encrypt(binary(), binary(), binary(), binary()) -> binary().
encrypt(Key, IV, Plain, AAD) ->
    {Ct, Tag} = crypto:crypto_one_time_aead(?CIPHER, Key, IV, Plain, AAD, ?TAG_LEN, true),
    <<IV/binary, Ct/binary, Tag/binary>>.

%% @doc Decrypt an encrypted blob produced by {@link encrypt/3}.
-spec decrypt(binary(), binary(), binary()) -> {ok, binary()} | error.
decrypt(Key, <<IV:12/binary, Rest/binary>>, AAD) ->
    CipherLen = byte_size(Rest) - ?TAG_LEN,
    case CipherLen >= 0 of
        false ->
            error;
        true ->
            <<Ct:CipherLen/binary, Tag:16/binary>> = Rest,
            decrypt(Key, IV, Ct, Tag, AAD)
    end;
decrypt(_Key, _Blob, _AAD) ->
    error.

%% @doc Decrypt with the IV, ciphertext, and tag separated.
-spec decrypt(binary(), binary(), binary(), binary(), binary()) -> {ok, binary()} | error.
decrypt(Key, IV, Ct, Tag, AAD) ->
    case crypto:crypto_one_time_aead(?CIPHER, Key, IV, Ct, AAD, Tag, false) of
        error ->
            error;
        Plain ->
            {ok, Plain}
    end.

%% @doc Strong random bytes from the OS CSPRNG.
-spec random_bytes(pos_integer()) -> binary().
random_bytes(N) ->
    crypto:strong_rand_bytes(N).
