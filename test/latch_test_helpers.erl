%% @doc Shared helpers for the Latch test suite.
-module(latch_test_helpers).

-export([setup/0, pair/0, pair/1, unhex/1, hex/1, sessions_from_keys/3]).

setup() ->
    {ok, _} = application:ensure_all_started(crypto),
    ok.

%% @doc A fresh pair of sessions with default options.
pair() ->
    pair(#{}).

%% @doc A fresh pair of sessions with extra options for both sides.
pair(Opts) ->
    IdA = latch_agreement:new_identity(),
    EphA = latch_agreement:new_ephemeral(),
    IdB = latch_agreement:new_identity(),
    EphB = latch_agreement:new_ephemeral(),
    sessions_from_keys(Opts, {IdA, EphA, IdB, EphB}, {initiator, responder}).

%% @doc Build sessions from prepared key material and roles.
sessions_from_keys(Opts, {IdA, EphA, IdB, EphB}, {RoleA, RoleB}) ->
    Alice = latch_agreement:session(RoleA, {IdA, EphA},
                                    {element(1, IdB), element(1, EphB)}, Opts),
    Bob = latch_agreement:session(RoleB, {IdB, EphB},
                                  {element(1, IdA), element(1, EphA)}, Opts),
    {Alice, Bob}.

%% @doc Hex string to binary.
unhex(Hex) when is_list(Hex) ->
    unhex(unicode:characters_to_binary(Hex));
unhex(Hex) when is_binary(Hex) ->
    << <<(list_to_integer([A, B], 16)):8>> || <<A:8, B:8>> <= Hex >>.

%% @doc Binary to lowercase hex string.
hex(Bin) ->
    binary:encode_hex(Bin, lowercase).
