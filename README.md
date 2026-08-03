# Latch

Latch is an Erlang library for secure messages between two peers.

Each message uses a fresh key from a ratchet. The ratchet runs on the
standard `crypto` module. Latch has no external dependencies.

## What Latch provides

Latch sets up a shared secret between two peers. The setup uses X25519 key
agreement. The shared secret seeds a double ratchet session.

The double ratchet advances a fresh key for every message. Messages use
AES-256-GCM authenticated encryption. The header of each message
authenticates the ciphertext.

This release adds two capabilities:

* Out-of-order message handling with skipped keys.
* Group messages with a shared sender key.

## How it works

Each peer holds an identity key and an ephemeral key. Peers exchange the
public halves over the transport. Both peers derive the same shared secret.

The double ratchet has two parts:

* The symmetric ratchet derives one message key per message.
* The DH ratchet derives new root and chain keys from a fresh X25519 output.

The initiator performs the first DH ratchet at session start. The responder
runs its first DH ratchet on the first received message. The ratchet then
alternates with each reply.

The receiving side stores skipped message keys. It decrypts out-of-order
messages and gaps up to `max_skip`. It rejects older messages. Messages from
a superseded chain that arrive after a DH ratchet are dropped.

Group messaging uses a sender key. Each member owns one sending chain. The
other members hold receiver sessions for that chain. Every message carries an
Ed25519 signature.

## Security properties

Forward secrecy holds. After a DH ratchet, old message keys no longer exist.
A captured old ciphertext fails authentication.

Authenticated encryption detects tampering. A changed ciphertext or header
fails decryption.

The handshake is not signed in this release. An active attacker on an
untrusted network can impersonate a peer. Use this release on a trusted
transport.

## Repository layout

```
src/                library modules
  latch.erl           top-level API and demo entry point
  latch_kdf.erl       HKDF and ratchet key derivation
  latch_crypto.erl    AES-256-GCM wrapper
  latch_agreement.erl key agreement and session setup
  latch_session.erl   the double ratchet session
  latch_sender_key.erl group messaging with a sender key
  latch_wire.erl      socket framing
  latch_peer.erl      a peer that talks over a TCP socket
  latch_demo.erl      the local demos
test/               EUnit tests
include/latch.hrl   shared record definitions
.github/workflows   continuous integration
```

## Requirements

* Erlang/OTP 26 or newer.
* rebar3 3.22 or newer.

## Build

Run this command from the repository root:

```
rebar3 compile
```

## Test

Run this command from the repository root:

```
rebar3 eunit
```

The suite runs 66 tests. It covers key derivation, authenticated encryption,
the ratchet, out-of-order delivery, forward secrecy, group messaging, and the
socket transport.

Run the static analysis:

```
rebar3 dialyzer
```

Dialyzer reports no warnings.

## Run the demos

The demos run on one machine over loopback TCP. No secrets are needed.

Build the demo script once:

```
rebar3 escriptize
```

### Pairwise demo

Two peers exchange messages over a direct socket. The ratchet advances with
every reply.

```
./_build/default/bin/latch pairwise
```

Sample output:

```
Latch pairwise demo
-------------------
Two peers over a loopback TCP socket

  bob listens on 127.0.0.1:60004
  handshake complete. alice=initiator bob=responder

  [1] conversation with 8 messages each way
    alice -> : alice message 01 [n=0]
    alice -> : alice message 02 [n=1]
    bob <- : alice message 01 [dh=2A94FCD9 n=0 pn=0]
    bob <- : alice message 02 [dh=2A94FCD9 n=1 pn=0]
    bob -> : bob message 01 [n=0]
    bob -> : bob message 02 [n=1]
    alice <- : bob message 01 [dh=93C22FA0 n=0 pn=0]
    alice <- : bob message 02 [dh=93C22FA0 n=1 pn=0]
    alice -> : alice message 03 [n=0]
    bob <- : alice message 03 [dh=D9BB5FA1 n=0 pn=2] [DH ratchet]
    ...

  [2] session summary
    alice root=9D864614 dh_send=4A7CCC4B dh_recv=CE203122 send=0 recv=2
    bob   root=F734C290 dh_send=CE203122 dh_recv=51A0ABB6 send=2 recv=2

  [3] forward secrecy check
    bob root ratchet: A2794B19... -> F734C290...
    bob tries to decrypt message 1 again with the current session:
      failed. the old message key is gone.
```

The `dh` value changes with each ratchet. The `pn` value reports the previous
chain length. The forward secrecy check shows that the first message key no
longer exists.

### Out-of-order demo

A relay delivers frames out of order. Bob decrypts them with skipped keys.

```
./_build/default/bin/latch shuffled
```

Sample output:

```
Latch out-of-order demo
-----------------------
A relay delivers frames out of order

  [1] alice sends 9 messages in one sending chain
  [2] bob receives them in shuffled order
    bob <- : alice message 03 [n=2] (skipped store: 0)
    bob <- : alice message 02 [n=1] (skipped store: 2)
    bob <- : alice message 01 [n=0] (skipped store: 1)
    bob <- : alice message 06 [n=5] (skipped store: 0)
    ...
  [3] result
    all 9 messages decrypted. max skipped keys held: 2
    bob session: 0 skipped keys remain
```

The skipped store grows when Bob jumps ahead. It shrinks when Bob consumes
the stored keys.

### Group demo

Three members chat over a TCP hub. Each member uses its own sender key.

```
./_build/default/bin/latch group
```

Sample output:

```
Latch group demo
----------------
Three members, one sender key per member

  a short chat over the hub
    alice -> group: hello everyone, this is alice
    bob <- group (alice): hello everyone, this is alice
    carol <- group (alice): hello everyone, this is alice
    bob -> group: hi alice, bob here
    ...
```

### Environment info

Print the runtime environment:

```
./_build/default/bin/latch info
```

## Test status

* EUnit: 66 tests, 0 failures.
* Dialyzer: no warnings.
* Demos: all three run locally on loopback TCP.

## Limitations

* The handshake is not signed. Use a trusted transport.
* The skip window covers one sending chain. Late messages from a superseded
  chain are dropped.
* Sessions live in memory. There is no persistence.
* The demos use loopback TCP. They do not use TLS.

## Roadmap

* Sign the handshake and authenticate identities.
* Add session persistence and resumption.
* Add test vectors from the Double Ratchet reference.
* Add a supervised peer with auto-reconnect.

## License

MIT. See `LICENSE`.
