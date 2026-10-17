#!/usr/bin/env escript
%% -*- erlang -*-
-module(run_eunit).
-mode(compile).

main(_) ->
    Root = filename:dirname(filename:dirname(escript:script_name())),
    code:add_patha(filename:join([Root, "_build", "test", "lib", "latch", "ebin"])),
    {ok, _} = application:ensure_all_started(crypto),
    Modules = [
        latch_agreement_tests,
        latch_crypto_tests,
        latch_kdf_tests,
        latch_session_tests,
        latch_forward_secrecy_tests,
        latch_sender_key_tests,
        latch_peer_tests
    ],
    Result = eunit:test(Modules, [verbose]),
    halt(case Result of ok -> 0; error -> 1 end).
