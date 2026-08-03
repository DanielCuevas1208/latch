%% @doc Latch top-level API and escript entry point.
%%
%% Latch is a ratchet-based secure messaging library for two peers. Each peer
%% derives a shared secret by key agreement. A double ratchet advances a fresh
%% key for every message. Messages use authenticated encryption. Group
%% messaging uses a shared sender key per member.
-module(latch).

-export([version/0, demo/1, info/0, main/1]).

-define(VERSION, "0.1.0").

%% @doc The Latch version.
-spec version() -> string().
version() ->
    ?VERSION.

%% @doc Run a demo from the Erlang shell.
%% Valid values: `pairwise', `shuffled', `group', `info'.
-spec demo(pairwise | shuffled | group | info) -> ok.
demo(Which) ->
    {ok, _} = application:ensure_all_started(latch),
    run(Which).

%% @doc Print environment information.
-spec info() -> ok.
info() ->
    latch_demo:info().

%% @doc escript entry point. Run `latch help' for usage.
-spec main(list(string())) -> no_return().
main(Args) ->
    {ok, _} = application:ensure_all_started(latch),
    case Args of
        ["pairwise"] -> run(pairwise);
        ["pairwise", "--messages", Count] -> latch_demo:pairwise(pos_int(Count));
        ["shuffled"] -> run(shuffled);
        ["shuffled", "--messages", Count] -> latch_demo:shuffled(pos_int(Count));
        ["group"] -> run(group);
        ["info"] -> info();
        ["help"] -> usage();
        ["--help"] -> usage();
        _ -> usage()
    end,
    halt(0).

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

run(pairwise) ->
    latch_demo:pairwise(8);
run(shuffled) ->
    latch_demo:shuffled(9);
run(group) ->
    latch_demo:group();
run(info) ->
    info().

-spec pos_int(string()) -> pos_integer().
pos_int(Value) ->
    try list_to_integer(Value) of
        N when N > 0 -> N;
        _ -> usage_fail()
    catch
        error:badarg -> usage_fail()
    end.

-spec usage_fail() -> no_return().
usage_fail() ->
    usage(),
    halt(1).

usage() ->
    io:format(
        "Latch ~s - ratchet-based secure messaging~n~n"
        "usage: latch <demo> [--messages N]~n~n"
        "demos:~n"
        "  pairwise             two peers exchange messages over a socket~n"
        "  pairwise --messages N   as above with N messages each way~n"
        "  shuffled             a relay delivers messages out of order~n"
        "  shuffled --messages N   as above with N messages~n"
        "  group                three members chat over a TCP hub~n"
        "  info                 print the runtime environment~n",
        [?VERSION]).
