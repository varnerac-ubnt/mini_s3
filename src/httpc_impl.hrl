-define(SEND_REQ, case dlhttpc:request(Uri, Method, Headers, Body, 5000) of
                      {ok, {{Code, _Reason}, Hdrs, Resp}} ->
                          {ok, {Code, Hdrs, Resp}};
                      {error, Reason} ->
                          {error, Reason}
                  end
       ).
-define(START_HTTPC, ok = application:start(dispcount),
                     ok = dlhttpc:start()
       ).
