%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Copyright 2014 Drew Varner All Rights Reserved.
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

-export([canonical_request/5]).

-type http_method() :: httpc:method().

-type header_name() :: string() | atom().
-type header_value() :: string() | undefined.

-type header() :: {header_name(), header_value()}.
-type headers() :: [header()].

-ifdef(TEST).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-endif.

-spec canonical_request(Method         :: http_method(),
                        Uri            :: string(),
                        Headers        :: headers(),
                        RequestPayload :: iodata(),
                        HashAlgorithm  :: crypto:hash_algorithms()) -> string().
canonical_request(Method,
                  Uri,
                  Headers,
                  RequestPayload,
                  HashAlgorithm) ->
    ParsedUri = http_uri:parse(Uri),
    {_Scheme, _UserInfo, _Host, _Port, Path, Query} = ParsedUri,
    CanonicalUri = case Path of
      "" -> "/";
      _  -> Path
    end,
    CanonicalQueryString = canonicalize_query_string(Query),
    HdrResult = canonicalize_headers(Headers),
    {header_names, SignedHeaders, headers, CanonicalHeaders} = HdrResult,
    canonical_request(Method,
                      CanonicalUri,
                      CanonicalQueryString,
                      CanonicalHeaders,
                      SignedHeaders,
                      RequestPayload,
                      HashAlgorithm).

-spec canonical_request(Method               :: http_method(),
                        CanonicalURI         :: string(),
                        CanonicalQueryString :: string(),
                        CanonicalHeaders     :: string(),
                        SignedHeaders        :: string(),
                        RequestPayload       :: iodata(),
                        HashAlgorithm        :: crypto:hash_algorithms()) ->
    string().
canonical_request(Method,
                  CanonicalURI,
                  CanonicalQueryString,
                  CanonicalHeaders,
                  SignedHeaders,
                  RequestPayload,
                  HashAlgorithm) ->
    Payload = hash_and_hex_encode_payload(RequestPayload, HashAlgorithm),
    HTTPRequestMethod = string:to_upper(atom_to_list(Method)),
    string:join([HTTPRequestMethod,
                 CanonicalURI,
                 CanonicalQueryString,
                 CanonicalHeaders,
                 SignedHeaders,
                 Payload],
                 "\n").

-spec canonicalize_headers(headers()) -> string().
canonicalize_headers([]) ->
    {error, headers_cannot_be_empty};
canonicalize_headers(Headers) ->
    canonicalize_headers(Headers, []).

-spec canonicalize_headers(Headers::headers(), Acc::headers()) -> string().
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

-spec strip_non_quoted_spaces(State  :: none | space | quote,
                              String :: string(),
                              Acc    :: string()) -> string().
% Character code 32=space, 9=horizontal tab
strip_non_quoted_spaces(none, [32 | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, [32 | Acc]);
strip_non_quoted_spaces(none, [9 | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, [32 | Acc]);
strip_non_quoted_spaces(none, [$" | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [$" | Acc]);
strip_non_quoted_spaces(none, [Char | Rest], Acc) ->
    strip_non_quoted_spaces(none,  Rest, [Char | Acc]);
strip_non_quoted_spaces(space, [32 | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, Acc);
strip_non_quoted_spaces(space, [9 | Rest], Acc) ->
    strip_non_quoted_spaces(space,  Rest, Acc);
strip_non_quoted_spaces(space, [$" | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [$" | Acc]);
strip_non_quoted_spaces(space, [Char | Rest], Acc) ->
    strip_non_quoted_spaces(none,  Rest, [Char | Acc]);
strip_non_quoted_spaces(quote, [32 | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [32 | Acc]);
strip_non_quoted_spaces(quote, [9 | Rest], Acc) ->
    strip_non_quoted_spaces(quote,  Rest, [9 | Acc]);
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

-spec hash_and_hex_encode_payload(Payload       :: iodata(),
                                  HashAlgorithm :: crypto:hash_algorithms()) -> 
    string().
hash_and_hex_encode_payload(Payload, HashAlgorithm) ->
    HashedPayload = crypto:hash(HashAlgorithm, Payload),
    hex_encode(HashedPayload).

-spec hex_encode(Binary::binary()) -> string().
hex_encode(Binary) ->
    lists:flatten([io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Binary]).

-ifdef(TEST).
strip_non_quoted_spaces_test_() ->
    Tests = [
             {"abc"           , "abc"        },
             {"a  b  c"       , "a b c"      },
             {"  \"a  b  c\"" , "\"a  b  c\""},
             {"a\tb\tc"       , "a b c"    },
             {"\"a\tb\tc\""   , "\"a\tb\tc\""},
             {"  abc    "     , "abc"        },
             {"  a  \t bc    ", "a bc"       }
            ],
    [ ?_assertEqual(Expect, strip_non_quoted_spaces(String)) ||
                    {String, Expect} <- Tests].
-endif.