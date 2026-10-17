%% Latch shared record definitions.

-ifndef(LATCH_HRL).
-define(LATCH_HRL, true).

-define(DEFAULT_MAX_SKIP, 1000).

%% Wire header of one double-ratchet message.
%% dh   - public key of the sender's current sending ratchet
%% pn   - number of messages in the sender's previous sending chain
%% n    - message number inside the current sending chain
-record(latch_header, {
    dh :: binary(),
    pn :: non_neg_integer(),
    n :: non_neg_integer()
}).

-type latch_header() :: #latch_header{}.

%% Wire header of one sender-key (group) message.
-record(latch_sheader, {
    key_id :: binary(),
    iter :: non_neg_integer()
}).

-type latch_sheader() :: #latch_sheader{}.

%% Long-term identity of a Latch peer.
%% id   - X25519 identity pair {Pub, Priv}, used for key agreement
%% sign - Ed25519 signing pair {Pub, Priv}, used to authenticate the handshake
-record(latch_identity, {
    id :: {binary(), binary()},
    sign :: {binary(), binary()}
}).

-type latch_identity() :: #latch_identity{}.

%% State of one double-ratchet session.
-record(latch_session, {
    role :: initiator | responder,
    root :: binary(),
    dh_send :: {binary(), binary()},
    dh_recv_pub :: binary() | undefined,
    chain_send :: binary() | undefined,
    chain_recv :: binary() | undefined,
    send_count = 0 :: non_neg_integer(),
    recv_count = 0 :: non_neg_integer(),
    prev_chain_length = 0 :: non_neg_integer(),
    skipped = #{} :: map(),
    max_skip = ?DEFAULT_MAX_SKIP :: pos_integer(),
    sent_total = 0 :: non_neg_integer(),
    recv_total = 0 :: non_neg_integer()
}).

-endif.
