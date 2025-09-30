%%--------------------------------------------------------------------
%% %CopyrightBegin%
%%
%% SPDX-License-Identifier: Apache-2.0
%%
%% Copyright Ericsson AB 2012-2025. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%
%%----------------------------------------------------------------------
%% File: cover_SUITE.erl
%%
%% Description:
%%    This file contains the test cases for the code coverage support
%%
%% Test  of code coverage support in common_test
%%----------------------------------------------------------------------
%%----------------------------------------------------------------------
-module(cover_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile(export_all).

%% Default timetrap timeout (set in init_per_testcase).
-define(default_timeout, test_server:minutes(1)).

suite() ->
    [].

all() ->
    [].

init_per_suite(Config) ->
    Config.

end_per_suite(Config) ->
    Config.

init_per_testcase(_Case, Config) ->
    Dog = test_server:timetrap(?default_timeout),
    [{watchdog, Dog}|Config].

end_per_testcase(Case, Config) ->
    try apply(?MODULE,Case,[cleanup,Config])
    catch error:undef -> ok
    end,

    Dog=?config(watchdog, Config),
    test_server:timetrap_cancel(Dog),
    ok.

%%%-----------------------------------------------------------------
%%% Test cases
break(_Config) ->
    test_server:break(""),
    ok.

default(_Config) ->
    cover_compiled = code:which(cover_test_mod),
    cover_test_mod:foo(),
    ok.

default_no_cover(_Config) ->
    cover_test_mod:foo(),
    ok.

%% Node name for the peer/1 test, which will be spawned
-define(peer_CONTROL_NODE, cover_SUITE_peer_node).

peer(_Config) ->
    cover_compiled = code:which(cover_test_mod),
    cover_test_mod:foo(),
    N1 = nodename(?FUNCTION_NAME, 1),
    {ok, Node} = start_peer_node(N1),
    cover_compiled = rpc:call(Node, code, which, [cover_test_mod]),
    rpc:call(Node, cover_test_mod, foo, []),
    {ok, Node} = ct_slave:stop(N1),
    ok.
peer(cleanup,_Config) ->
    stop_peer_nodes([nodename(cover_SUITE_peer_node,1)]).

peer_start_peer(_Config) ->
    cover_compiled = code:which(cover_test_mod),
    cover_test_mod:foo(),
    N1 = nodename(?FUNCTION_NAME,1),
    N2 = nodename(?FUNCTION_NAME,2),
    {ok,Node} = start_peer_node(N1),
    cover_compiled = rpc:call(Node,code,which,[cover_test_mod]),
    rpc:call(Node,cover_test_mod,foo,[]),
    {ok,Node2} = start_peer_node(Node,N2), % start slave N2 from node Node
    rpc:call(Node2,cover_test_mod,foo,[]),
    {ok,Node2} = rpc:call(Node,ct_slave,stop,[N2]),
    {ok,Node} = ct_slave:stop(N1),
    ok.
peer_start_peer(cleanup,_Config) ->
    stop_peer_nodes([nodename(?FUNCTION_NAME,1),
		 nodename(?FUNCTION_NAME,2)]).

cover_node_option(_Config) ->
    cover_compiled = code:which(cover_test_mod),
    cover_test_mod:foo(),
    Node = fullname(existing_node_1),
    cover_compiled = rpc:call(Node,code,which,[cover_test_mod]),
    rpc:call(Node,cover_test_mod,foo,[]),
    ok.

ct_cover_add_remove_nodes(_Config) ->
    cover_compiled = code:which(cover_test_mod),
    cover_test_mod:foo(),
    Node = fullname(existing_node_2),
    Beam = rpc:call(Node,code,which,[cover_test_mod]),
    false = (Beam == cover_compiled),

    rpc:call(Node,cover_test_mod,foo,[]), % should not be collected
    {ok,[Node]} = ct_cover:add_nodes([Node]),
    cover_compiled = rpc:call(Node,code,which,[cover_test_mod]),
    rpc:call(Node,cover_test_mod,foo,[]), % should be collected
    ok = ct_cover:remove_nodes([Node]),
    rpc:call(Node,cover_test_mod,foo,[]), % should not be collected

    Beam = rpc:call(Node,code,which,[cover_test_mod]),

    ok.

otp_9956(Config) ->
    cover_compiled = code:which(?MODULE),
    DataDir = ?config(data_dir,Config),
    absolute = filename:pathtype(DataDir),
    true = filelib:is_dir(DataDir),
    ok.


%%%-----------------------------------------------------------------
%%% Internal

any_to_list(A) when is_atom(A) -> atom_to_list(A);
any_to_list(S) when is_list(S) -> S.

%% Can use either any atom or ?FUNCTION_NAME for Case
nodename(Case,N) ->
    list_to_atom(nodeprefix(Case) ++ integer_to_list(N)).

%% Can use either any atom or ?FUNCTION_NAME for Case
nodeprefix(Case) ->
    any_to_list(?MODULE) ++ "_" ++ any_to_list(Case) ++ "_node".


fullname(Name) ->
    {ok,Host} = inet:gethostname(),
    list_to_atom(atom_to_list(Name) ++ "@" ++ Host).

stop_peer_nodes([Name|Names]) ->
    _ = rpc:call(fullname(Name),erlang,halt,[]),
    stop_peer_nodes(Names);
stop_peer_nodes([]) ->
    ok.

start_peer_node(Name) ->
    start_peer_node(node(), Name).

start_peer_node(FromNode,Name) ->
    {ok, HostStr}=inet:gethostname(),
    Host = list_to_atom(HostStr),
    rpc:call(FromNode,ct_slave,start,
	     [Host,Name,
	      [{boot_timeout,15}, % extending some timers for slow test hosts
	       {init_timeout,15},
	       {startup_timeout,15}]]).
