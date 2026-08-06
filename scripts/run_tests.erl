#!/usr/bin/env escript
%% Run the Latch EUnit suite without rebar3.
-mode(compile).

main(_) ->
    Root = filename:dirname(filename:dirname(escript:script_name())),
    ok = file:set_cwd(Root),
    ok = compile_all(Root),
    Ebin = filename:join([Root, "_build", "test", "lib", "latch", "ebin"]),
    code:add_patha(Ebin),
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
    Results = eunit:test(Modules, [verbose, {report, {module, eunit_surefire}}]),
    case Results of
        ok -> halt(0);
        error -> halt(1)
    end.

compile_all(Root) ->
    SrcDir = filename:join(Root, "src"),
    TestDir = filename:join(Root, "test"),
    Ebin = filename:join([Root, "_build", "test", "lib", "latch", "ebin"]),
    ok = filelib:ensure_dir(filename:join(Ebin, "dummy.beam")),
    Opts = [debug_info, warnings_as_errors,
            {i, filename:join(Root, "include")},
            {outdir, Ebin}],
    Srcs = filelib:wildcard("*.erl", SrcDir) ++ filelib:wildcard("*.erl", TestDir),
    {ok, _} = compile:file(Srcs, Opts),
    ok.
