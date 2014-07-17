%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Copyright 2014 UBNT Networks All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%

-module(ms3_signature).

-export([string_to_sign/7]).

-type http_method() :: httpc:method().

-type header_name() :: string() | atom().
-type header_value() :: string() | undefined.

-type header() :: {header_name(), header_value()}.
-type headers() :: [header()].

-ifdef(TEST).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% @doc This method is Task 2 of the Anmazon Web Services Signature
%%      Version 4 signing process. Note that the Erlang implemntation
%%      doesn't actually return a string(), but an iolist().
%%      This saves us from having to join the lists together and it
%%      prevents us from breaking the string() typespec if we were
%%      to include integers greater than 255 (some unicode characters).
-spec string_to_sign(Algorithm              :: crypto:hash_algorithms(),
                     LocationConstraint     :: mini_s3:location_constraint(),
                     Service                :: mini_s3:service(),
                     Method                 :: http_method(),
                     URI                    :: string(),
                     Headers                :: headers(),
                     RequestPayload         :: iodata()) ->
    StringToSign::iolist().
string_to_sign(Algorithm,
               LocationConstraint,
               Service,
               Method,
               URI,
               Headers,
               RequestPayload) ->
    {Date, Time} = now_utc(),
    RequestDateTime = iso_8601_date_time_fmt({Date, Time}),
    HashedCRequest = hashed_canonical_request(Method,
                                              URI,
                                              Headers,
                                              RequestPayload,
                                              Algorithm),
    [hash_algorithm_to_string(Algorithm), $\n,
     RequestDateTime, $\n,
     credential_scope(Date, LocationConstraint, Service), $\n,
     HashedCRequest
    ].

-spec credential_scope(Date               :: calendar:date(),
                       LocationConstraint :: mini_s3:location_constraint(),
                       Service            :: mini_s3:service()) -> iolist().
credential_scope(Date, LocationConstraint, Service) ->
    [iso_8601_date_fmt(Date), $/,
     atom_to_unicode_binary(LocationConstraint), $/,
     atom_to_unicode_binary(Service), $/,
     "aws4_request\n"].

 %% @doc This method is Task 1 of the Anmazon Web Services Signature
 %%      Version 4 signing process.   
-spec hashed_canonical_request(Method         :: http_method(),
                               URI            :: string(),
                               Headers        :: headers(),
                               RequestPayload :: iodata(),
                               HashAlgorithm  :: crypto:hash_algorithms()) ->
    string().
hashed_canonical_request(Method,URI,Headers,RequestPayload,HashAlgorithm) ->
    CReq = canonical_request(Method,URI,Headers,RequestPayload,HashAlgorithm),
    hash_and_hex_encode(HashAlgorithm, CReq).

-spec canonical_request(Method         :: http_method(),
                        URI            :: string(),
                        Headers        :: headers(),
                        RequestPayload :: iodata(),
                        HashAlgorithm  :: crypto:hash_algorithms()) -> string().
canonical_request(Method, URI, Headers, RequestPayload, HashAlgorithm) ->
    {ok, {_, _, _, _, Path, Query}} = http_uri:parse(URI),
    CURI = case Path of
      "" -> "/";
      _  -> Path
    end,
    CQueryString = canonicalize_query_string(Query),
    {header_names, SignedHdrs, headers, CHdrs} = canonicalize_headers(Headers),
    canonical_request(Method,
                      CURI,
                      CQueryString,
                      CHdrs,
                      SignedHdrs,
                      RequestPayload,
                      HashAlgorithm).

-spec canonical_request(Method       :: http_method(),
                        CUR          :: string(),
                        CQueryString :: string(),
                        CHdrs        :: string(),
                        SignedHdrs   :: string(),
                        Payload      :: iodata(),
                        HashAlg      :: crypto:hash_algorithms()) -> string().
canonical_request(Method,CURI,CQueryString,CHdrs,SignedHdrs,Payload,HashAlg) ->
    HashedAndHexedPayload = hash_and_hex_encode(HashAlg, Payload),
    HTTPRequestMethod = string:to_upper(atom_to_list(Method)),
    string:join([HTTPRequestMethod,
                 CURI,
                 CQueryString,
                 CHdrs,
                 SignedHdrs,
                 HashedAndHexedPayload],
                 "\n").

-spec canonicalize_headers(headers()) ->
    {header_names, string(), headers, string()}.
canonicalize_headers([]) ->
    {error, headers_cannot_be_empty};
canonicalize_headers(Headers) ->
    canonicalize_headers(Headers, []).

-spec canonicalize_headers(headers(), headers()) ->
    {header_names, string(), headers, string()}.
canonicalize_headers([], Acc) ->
    Headers = lists:keysort(1, Acc),
    HeaderNames = proplists:get_keys(Headers),
    Headers1 = case length(HeaderNames) =:= length(Headers) of
        true ->
            Headers;
        false ->
            % Merge duplicate headers
            [{HN, proplists:get_all_values(HN, Headers)} || HN <- HeaderNames]
    end,
    HString = lists:flatten([[Name,$:,Value,$\n] || {Name, Value} <- Headers1]),
    HNamesString = string:join(HeaderNames, ";"),
    {header_names, HNamesString, headers, HString};
canonicalize_headers([{_, undefined} | Rest], Acc) ->
    % ignore undefined headers
    canonicalize_headers(Rest, Acc);
canonicalize_headers([Header | Rest], Acc) ->
    canonicalize_headers(Rest, [canonicalize_header(Header) | Acc]).

canonicalize_header({Name, Value}) when is_atom(Name) ->
    canonicalize_header({atom_to_list(Name), Value});
canonicalize_header({Name, Value})  ->
    Name1 = string:to_lower(Name),
    Value1 = strip_non_quoted_spaces(Value),
    {Name1, Value1}.

%%  removes excess white space before and after values and from inside
%%  non-quoted strings, per RFC 2616 Section 4.2.
%%  http://tools.ietf.org/html/rfc2616#page-32
-spec strip_non_quoted_spaces(String::string()) -> Result::string().
strip_non_quoted_spaces(String) ->
    strip_non_quoted_spaces(none, string:strip(String), "").

%% The states mean:
%% * none  =  Nothing special is going on
%% * quote =  I'm inside a quoted string
%% * space =  I'm inside linear whitespace
%% 
%% If you're inside a quoted string, it doesn't matter
%% that you are in linear whitespace, and whitespace is
%% treated like any other character.
-spec strip_non_quoted_spaces(State  :: none | space | quote,
                              String :: string(),
                              Acc    :: string()) -> string().
strip_non_quoted_spaces(none, [$\s | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, [$\s | Acc]);
strip_non_quoted_spaces(none, [$\t | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, [$\s | Acc]);
strip_non_quoted_spaces(none, [$" | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [$" | Acc]);
strip_non_quoted_spaces(none, [Char | Rest], Acc) ->
    strip_non_quoted_spaces(none,  Rest, [Char | Acc]);
strip_non_quoted_spaces(space, [$\s | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, Acc);
strip_non_quoted_spaces(space, [$\t | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, Acc);
strip_non_quoted_spaces(space, [$" | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [$" | Acc]);
strip_non_quoted_spaces(space, [Char | Rest], Acc) ->
    strip_non_quoted_spaces(none,  Rest, [Char | Acc]);
strip_non_quoted_spaces(quote, [$" | Rest], Acc) ->
    strip_non_quoted_spaces(none,  Rest, [$" | Acc]);
strip_non_quoted_spaces(quote, [Char | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [Char | Acc]);
strip_non_quoted_spaces(_, "", Acc) ->
        lists:reverse(Acc).

-spec canonicalize_query_string(string()) -> string().
canonicalize_query_string("") ->
    "";
canonicalize_query_string("?") ->
    "";
canonicalize_query_string([$?| QueryString]) ->
    Tokens0 = string:tokens(QueryString, "&"),
    Tokens1 = [maybe_append_equal(T) || T <- Tokens0],
    SortedTokens = lists:sort(Tokens1),
    string:join(SortedTokens, "&").

-spec maybe_append_equal(String::string()) -> string().
maybe_append_equal(String) ->
    case string:chr(String, $=) =:= 0 of
        true  -> String ++ "=";
        false -> String
    end.

-spec hash_and_hex_encode(HashAlgorithm :: crypto:hash_algorithms(),
                          Data          :: iodata()) -> 
    string().
hash_and_hex_encode(HashAlgorithm, Data) ->
    Hashed = crypto:hash(HashAlgorithm, Data),
    hex_encode(Hashed).

-spec hex_encode(Binary::binary()) -> string().
hex_encode(Binary) ->
    lists:flatten([io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Binary]).

now_utc() ->
    erlang:localtime_to_universaltime(erlang:localtime()).

iso_8601_date_time_fmt({{Year,Month,Day}, {Hour,Min,Sec}}) ->
    io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ",
                  [Year, Month, Day, Hour, Min, Sec]).

iso_8601_date_fmt({Year,Month,Day}) ->
    io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B", [Year, Month, Day]).

-spec hash_algorithm_to_string(crypto:hash_algorithms()) -> string().
hash_algorithm_to_string(sha224) -> "AWS4-HMAC-SHA224";
hash_algorithm_to_string(sha256) -> "AWS4-HMAC-SHA256";
hash_algorithm_to_string(sha384) -> "AWS4-HMAC-SHA384";
hash_algorithm_to_string(sha512) -> "AWS4-HMAC-SHA512".

-spec atom_to_unicode_binary(Atom::atom()) -> binary().
atom_to_unicode_binary(Atom) ->
    unicode:characters_to_binary(atom_to_list(Atom), latin1).

-ifdef(TEST).

strip_non_quoted_spaces_test_() ->
    Tests = [
             {"abc"           , "abc"        },
             {"a  b  c"       , "a b c"      },
             {"  \"a  b  c\"" , "\"a  b  c\""},
             {"a\tb\tc"       , "a b c"      },
             {"\"a\tb\tc\""   , "\"a\tb\tc\""},
             {"  abc    "     , "abc"        },
             {"  a  \t bc    ", "a bc"       }
            ],
    [ ?_assertEqual(Expect, strip_non_quoted_spaces(String)) ||
                    {String, Expect} <- Tests].
-endif.