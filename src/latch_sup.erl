%% @doc Latch top-level supervisor.
%%
%% Latch is a library. The supervisor owns no workers.
-module(latch_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, {{one_for_one, 5, 10}, []}}.
