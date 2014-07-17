-module(httpc_impl).

-export([start/0]).
-export([send_req/5]).

-type headers()          :: mini_s3:headers().
-type chunk_size_bytes() :: pos_integer().
-type filename()         :: file:filename().
-spec start() -> ok.
start() ->
    ok = application:start(dispcount),
    ok = dlhttpc:start(),
    ok.

-spec send_req(URI     :: string(),
               Method  :: mini_s3:method(),
               Headers :: headers(),
               Body    :: iolist()
                        | {stream, filename(), chunk_size_bytes()},
               Timeout :: pos_integer()) ->  
    mini_s3:response() | {error, any()}.
send_req(URI, Method, Headers, {stream, Filename, ChunkSize}, Timeout) ->
        {ok, File} = file:open(Filename, [read, binary]),
        case file:read(File, ChunkSize) of
            {ok, Data} ->
                {ok, State} = dlhttpc:request(URI,
                                              Method,
                                              Headers,
                                              Data,
                                              Timeout,
                                              [{partial_upload, 1}]),
                stream_file(File, ChunkSize, {ok,Data}, State);
            eof ->
                 % On an empty file, don't try to stream.
                 dlhttpc:request(URI, Method, Headers, [], Timeout);
            {error, Error} ->
                {error, Error}
        end;
send_req(URI, Method, Headers, Body, Timeout) ->
    Resp = dlhttpc:request(URI, Method, Headers, Body, Timeout),
    wrap_response(Resp).

-spec stream_file(File      :: file:file(),
                  ChunkSize :: pos_integer(),
                  Data      :: {ok, [byte()]} | eof | {error, any()},
                  State     :: any()) ->
    ok | {error, any()}.
stream_file(File, _ChunkSize, {error, Reason}, State) ->
    {ok, _} = dlhttpc:send_body_part(State, http_eob, infinity),
    _ = file:close(File),
    {error, Reason};
stream_file(File, ChunkSize, {ok, Data}, State) ->
    {ok, NextState} = dlhttpc:send_body_part(State, [Data], infinity),
    Read = file:read(File, ChunkSize),
    stream_file(File, ChunkSize, Read, NextState);
stream_file(File, _ChunkSize, eof, State) ->
    _ = file:close(File),
    Resp = dlhttpc:send_body_part(State, http_eob, infinity),
    wrap_response(Resp).

-spec wrap_response({ok, {{integer(), string()}, headers(), binary()}}
                  | {error,any()}) ->
    {ok, {string(), headers(), binary()}} | {error, any()}.
wrap_response({ok, {{Code, _Reason}, Hdrs, Payload}}) ->
    {ok, {Code, Hdrs, Payload}};
wrap_response({error,Reason}) ->
    {error, Reason}.
    