%% @doc Latch application callback.
-module(latch_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    latch_sup:start_link().

stop(_State) ->
    ok.
