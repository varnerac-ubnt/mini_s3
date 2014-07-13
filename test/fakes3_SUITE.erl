-module(fakes3_SUITE).

%% CT callbacks
-export([all/0,
         init_per_suite/1,
         end_per_suite/1]).

%% test callbacks
-export([t_basic_s3_test/1]).

-include_lib("common_test/include/ct.hrl").

-define(FAKES3_PORT, 7689).

%%%------------------------------------------------------------------------
%%% Callback functions from CT
%%%------------------------------------------------------------------------

all() ->
    [t_basic_s3_test].

init_per_suite(Config) ->
    % ok = case is_gem_installed() orelse is_fakes3_install_global() of
    %    true  -> ok;
    %    false -> error_no_gem_or_fakes3()
    %end,
    %InstallType = get_fakes3_install_type(Config),
    %{ok, _} = start_fakes3(InstallType, Config),
    Config.

end_per_suite(Config) ->
    %ok = fakes3_server:stop(),
    Config.

%%%------------------------------------------------------------------------
%%% test cases
%%%------------------------------------------------------------------------

t_basic_s3_test(Config) ->
    S3Conf = test_config(),
    ct:pal("S3Conf:~p~n", [S3Conf]),
    _ImgFilename = get_test_file_path(Config, "erlang.png"),
    ok = mini_s3:create_bucket("test_bucket", private, none, S3Conf),
    ok.

%%%------------------------------------------------------------------------
%%% Private Test Helper Methods
%%%------------------------------------------------------------------------

test_config() ->
    URI ="http://localhost:"++ integer_to_list(?FAKES3_PORT),
    mini_s3:new(fake_credentials(), URI).

fake_credentials() ->
    {credentials, baked_in, "123", "abc"}.

get_test_file_path(Config, Filename) ->
    Name = filename:join([get_data_dir(Config), "test_files", Filename]),
    ct:pal(Name),
    true = filelib:is_file(Name),
    Name.

%%%------------------------------------------------------------------------
%%% Private
%%%------------------------------------------------------------------------

is_gem_installed() ->
    case os:find_executable("gem") of
        false ->
            ct:pal("*************************************~n"),
            ct:pal("* Ruby's gem command not installed! *~n"),
            ct:pal("*************************************~n"),
            false;
        _ ->
            true
    end.

get_fakes3_install_type(Config) ->
    case {is_fakes3_install_global(),is_fakes3_install_local(Config)} of
        {true, _} ->
            global;
        {_, true} ->
            local;
        {false, false} ->
            ok = install_fakes3_local(Config),
            local
    end.

is_fakes3_install_local(Config) ->
    filelib:is_dir(local_fakes3_bin_dir(Config)).

is_fakes3_install_global() ->
    case os:find_executable("fakes3") of
        false -> false;
        [_|_] -> true
    end.

get_data_dir(Config) ->
    proplists:get_value(data_dir, Config).
    
local_fakes3_install_dir(Config) ->
    filename:join(get_data_dir(Config), "fakes3") ++ "/".

local_fakes3_bin_dir(Config) ->
    filename:join([local_fakes3_install_dir(Config), "bin"])++"/".

install_fakes3_local(Config) ->
    Dir = local_fakes3_install_dir(Config),
    Cmd = iolib:format("gem install --install-dir ~p fakes3", [Dir]),
    Output = os:cmd(Cmd),
    ct:pal("Local install output: ~p~n",[Output]),
    ok.

-spec start_fakes3(global|local, list()) -> {ok,pid()} | ignore | {error,any()}.
start_fakes3(InstallType, Config) ->
    Root = filename:join(get_data_dir(Config), "fake_s3_root") ++ "/",
    ok = prepare_fakes3_root(Root),
    BaseCmd0 = "fakes3 --root \"" ++ Root,
    BaseCmd1 = "\" --port " ++ integer_to_list(?FAKES3_PORT),
    BaseCmd = BaseCmd0 ++ BaseCmd1,
    Cmd = case InstallType of
        global ->
            BaseCmd;
        local ->
            filename:join(local_fakes3_bin_dir(Config), BaseCmd)
    end,
    fakes3_server:start(Cmd).

error_no_gem_or_fakes3() ->
    Msg = "*******************************************************\n"
          "* Skipping FakeS3 Test Suite.                         *\n"
          "* Either `gem` or `fakes3` be installed and on the    *\n"
          "* PATH to run this test suite.                        *\n"
          "*******************************************************\n",
    ct:pal(Msg),
    error_no_gem_or_fakes3_installed.

prepare_fakes3_root(Dir) ->
    ok = maybe_del_dir_all(Dir),
    ok = filelib:ensure_dir(filename:join(Dir, "dummy")).

maybe_del_dir_all(Dir) ->
    case filelib:is_dir(Dir) of
        true ->
            del_dir_all(Dir);
        false ->
            case filelib:is_file(Dir) of
                true ->
                    error_dir_is_really_a_file;
                false ->
                    ok
            end
    end.

del_dir_all(Dir) ->
    {ok, Filenames} = file:list_dir_all(Dir),
    case Filenames of 
        [] ->
            file:del_dir(Dir);
        [_|_] ->
            lists:foreach(fun(X) ->
                              case filelib:is_dir(X) of
                                  true ->
                                      del_dir_all(X);
                                  false ->
                                      Fname = filename:join(Dir,X),
                                      ok = file:delete(Fname)
                              end
                          end,
                          Filenames)
    end. 
    
