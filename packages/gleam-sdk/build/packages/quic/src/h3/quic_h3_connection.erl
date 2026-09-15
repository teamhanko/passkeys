%%% -*- erlang -*-
%%%
%%% HTTP/3 connection state machine (RFC 9114)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc HTTP/3 connection management.
%%%
%%% This module implements the HTTP/3 connection layer on top of QUIC.
%%% It manages critical unidirectional streams (control, QPACK encoder/decoder),
%%% request/response streams, and the HTTP/3 protocol state machine.
%%% @end

-module(quic_h3_connection).

-behaviour(gen_statem).

%% API
-export([
    start_link/3,
    start_link/4,
    prime/1,
    request/2,
    request/3,
    open_bidi_stream/2,
    send_response/4,
    respond/5,
    send_data/3,
    send_data/4,
    send_trailers/3,
    cancel_stream/2,
    cancel_stream/3,
    goaway/1,
    close/1,
    get_settings/1,
    get_peer_settings/1,
    get_quic_conn/1,
    %% Server Push API (RFC 9114 Section 4.6)
    push/3,
    send_push_response/4,
    send_push_data/4,
    %% Client Push API
    set_max_push_id/2,
    cancel_push/2,
    %% Per-stream handler registration
    set_stream_handler/3,
    set_stream_handler/4,
    unset_stream_handler/2,
    %% HTTP Datagrams (RFC 9297)
    send_datagram/3,
    h3_datagrams_enabled/1,
    max_datagram_size/2
]).

%% gen_statem callbacks
-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4
]).

%% State functions
-export([
    bootstrapping/3,
    awaiting_quic/3,
    early_data/3,
    h3_connecting/3,
    connected/3,
    goaway_sent/3,
    goaway_received/3,
    closing/3
]).

-include("quic.hrl").
-include("quic_h3.hrl").

%% Test exports - only available when compiled with TEST defined
-ifdef(TEST).
-export([
    handle_stream_data/4,
    handle_stream_closed/2,
    handle_stream_closed/3,
    handle_control_frame/2,
    handle_request_frame/5,
    handle_new_stream/3,
    is_critical_stream/2,
    partition_blocked_streams/2,
    validate_trailer_headers/2,
    validate_request_headers/2,
    calculate_field_section_size/1,
    validate_outbound_headers/2,
    cleanup_blocked_streams_on_goaway/1,
    process_push_stream_id/4,
    update_stream_with_headers/4,
    allocate_push_id/1,
    validate_push_response_headers/1,
    cleanup_push_stream/3,
    validate_push_promise_duplicate/3,
    goaway_id_to_send/1,
    validate_promised_request_headers/2,
    handle_push_frame/5,
    handle_priority_update_frame/2,
    handle_priority_update_push_frame/2,
    do_send_trailers/3,
    do_respond/5,
    pre_claim_bidi_stream/3,
    assign_uni_stream/3,
    validate_peer_h3_datagram_with/1
]).
-endif.

%% Exposed for tests and introspection; not part of the public H3 API.
-export([test_discarded_uni_streams/1, test_stream/2, test_push_stream/2]).

%%====================================================================
%% Types
%%====================================================================

-type role() :: client | server.
-type stream_id() :: non_neg_integer().
-type error_code() :: non_neg_integer().

-record(state, {
    %% Underlying QUIC connection. `undefined' only in test state.
    quic_conn :: pid() | undefined,
    quic_ref :: reference() | undefined,

    %% Role: client or server
    role :: role(),

    %% Owner process (receives events)
    owner :: pid(),
    owner_monitor :: reference(),

    %% Critical unidirectional streams (local)
    local_control_stream :: stream_id() | undefined,
    local_encoder_stream :: stream_id() | undefined,
    local_decoder_stream :: stream_id() | undefined,

    %% Critical unidirectional streams (peer)
    peer_control_stream :: stream_id() | undefined,
    peer_encoder_stream :: stream_id() | undefined,
    peer_decoder_stream :: stream_id() | undefined,

    %% QPACK state
    qpack_encoder :: quic_qpack:state(),
    qpack_decoder :: quic_qpack:state(),

    %% Settings
    local_settings :: map(),
    peer_settings :: map() | undefined,
    settings_sent = false :: boolean(),
    settings_received = false :: boolean(),

    %% GOAWAY state
    goaway_id :: stream_id() | undefined,
    last_stream_id = 0 :: stream_id(),

    %% Request streams: StreamId -> #h3_stream{}
    streams = #{} :: #{stream_id() => #h3_stream{}},

    %% Next stream ID for client-initiated requests
    next_stream_id :: stream_id(),

    %% Pending data buffers for partial frame decoding
    stream_buffers = #{} :: #{stream_id() => binary()},

    %% Pending uni stream type detection
    %% Value is binary() for regular streams, or {push_pending, binary()} for push streams
    uni_stream_buffers = #{} :: #{stream_id() => binary() | {push_pending, binary()}},

    %% Uni streams classified as unknown type; subsequent bytes are
    %% discarded per RFC 9114 §6.2.3.
    discarded_uni_streams = sets:new([{version, 2}]) :: sets:set(stream_id()),

    %% QPACK instruction buffers for partial instructions (RFC 9204 Section 4.5)
    encoder_buffer = <<>> :: binary(),
    decoder_buffer = <<>> :: binary(),

    %% Blocked streams waiting for encoder instructions (RFC 9204 Section 2.2.2)
    %% Maps StreamId -> {RequiredInsertCount, HeaderBlock, Fin}
    blocked_streams = #{} :: #{stream_id() => {non_neg_integer(), binary(), boolean()}},

    %% Peer settings enforcement (RFC 9114 Section 7.2.4.1)
    peer_max_field_section_size = ?H3_DEFAULT_MAX_FIELD_SECTION_SIZE :: non_neg_integer(),
    peer_max_blocked_streams = 0 :: non_neg_integer(),
    peer_connect_enabled = false :: boolean(),

    %% Local settings enforcement (validate inbound data - RFC 9114 Section 7.2.4.1)
    local_max_field_section_size = ?H3_DEFAULT_MAX_FIELD_SECTION_SIZE :: non_neg_integer(),
    local_max_blocked_streams = 0 :: non_neg_integer(),

    %% Server-side push state (RFC 9114 Section 4.6)
    %% max_push_id: Maximum push ID allowed by client (from MAX_PUSH_ID frame)
    max_push_id :: non_neg_integer() | undefined,
    %% next_push_id: Next push ID to allocate for server push
    next_push_id = 0 :: non_neg_integer(),
    %% push_streams: Active push streams - maps PushId to {StreamId, #h3_stream{}}
    push_streams = #{} :: #{non_neg_integer() => {non_neg_integer(), #h3_stream{}}},
    %% cancelled_pushes: Set of push IDs cancelled by client
    cancelled_pushes = sets:new([{version, 2}]) :: sets:set(non_neg_integer()),

    %% Client-side push state (RFC 9114 Section 4.6)
    %% local_max_push_id: Maximum push ID we've sent to server
    local_max_push_id :: non_neg_integer() | undefined,
    %% promised_pushes: Push promises received - maps PushId to {RequestStreamId, Headers}
    promised_pushes = #{} :: #{non_neg_integer() => {non_neg_integer(), [{binary(), binary()}]}},
    %% received_pushes: Active push streams from server - maps PushId to a
    %% full #h3_stream{} so content-length / body / frame_state tracking
    %% matches regular request streams (RFC 9114 §4.1.2, §4.6).
    received_pushes = #{} :: #{non_neg_integer() => #h3_stream{}},
    %% local_cancelled_pushes: Set of push IDs we've cancelled
    local_cancelled_pushes = sets:new([{version, 2}]) :: sets:set(non_neg_integer()),
    %% last_accepted_push_id: highest push ID we have validated a
    %% PUSH_PROMISE for. Used on client-sent GOAWAY to compute the
    %% first-refused push ID monotonically, independent of whether the
    %% entry is still in promised_pushes or received_pushes.
    last_accepted_push_id :: non_neg_integer() | undefined,

    %% Per-stream handler registration (Option A for body data routing)
    %% Maps StreamId -> {Pid, MonitorRef} for streams with registered handlers
    stream_handlers = #{} :: #{stream_id() => {pid(), reference()}},
    %% Buffers data received before handler registers (with size limit)
    stream_data_buffers = #{} :: #{stream_id() => {[binary()], non_neg_integer(), boolean()}},
    %% Maximum bytes to buffer per stream before handler registers (64KB default)
    stream_buffer_limit = 65536 :: non_neg_integer(),

    %% RFC 9220: extended CONNECT enabled locally (advertised in our SETTINGS).
    %% Used on the server side to validate inbound :protocol pseudo-headers.
    %% Placed at the end so prior tuple positions stay stable for tests.
    local_connect_enabled = false :: boolean(),

    %% Extension hook. When set, `handle_uni_stream_type/4' consults
    %% this function for unknown stream types and, on `claim', routes
    %% subsequent bytes to the owner as `{stream_type_*, ...}` events
    %% instead of discarding them.
    stream_type_handler ::
        fun((uni | bidi, stream_id(), non_neg_integer()) -> claim | ignore) | undefined,

    %% Uni streams that the stream_type_handler claimed; maps StreamId
    %% to the advertised varint stream type so owner messages can
    %% include it.
    claimed_uni_streams = #{} :: #{stream_id() => non_neg_integer()},

    %% RFC 9297 HTTP Datagrams. Both sides must advertise
    %% SETTINGS_H3_DATAGRAM = 1 AND non-zero max_datagram_frame_size on
    %% their QUIC transport parameters for the extension to go live.
    h3_datagram_enabled = false :: boolean(),
    peer_h3_datagram_enabled = false :: boolean(),

    %% Peer-initiated bidi streams pending varint-peek classification.
    %% Populated when stream_type_handler is set so the handler can
    %% decide whether to claim the stream (e.g. WebTransport
    %% WT_BIDI_SIGNAL 0x41) or fall through to HTTP/3 request parsing.
    bidi_type_buffers = #{} :: #{stream_id() => binary()},

    %% Bidi streams the stream_type_handler claimed; maps StreamId to
    %% the advertised varint type.
    claimed_bidi_streams = #{} :: #{stream_id() => non_neg_integer()},

    %% Final-response HEADERS frames buffered until the first body chunk so
    %% they coalesce into one QUIC packet (StreamId -> encoded HEADERS frame).
    %% Placed at the end so prior tuple positions stay stable for tests.
    pending_response_headers = #{} :: #{stream_id() => binary()},

    %% Set in bootstrapping(cast, prime, ...) from quic:has_early_keys/1.
    has_early_keys = false :: boolean(),

    %% Set when {quic, _, {connected, _}} arrives. Used by early_data
    %% convergence logic to detect when 1-RTT is up.
    quic_connected = false :: boolean()
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start an HTTP/3 connection as a client.
-spec start_link(pid(), binary(), pos_integer()) ->
    {ok, pid()} | {error, term()}.
start_link(QuicConn, Host, Port) ->
    start_link(QuicConn, Host, Port, #{}).

%% @doc Start an HTTP/3 connection with options.
-spec start_link(pid(), binary(), pos_integer(), map()) ->
    {ok, pid()} | {error, term()}.
start_link(QuicConn, Host, Port, Opts) ->
    gen_statem:start_link(?MODULE, {client, QuicConn, Host, Port, Opts, self()}, []).

%% @doc Prime a client H3 connection after ownership transfer.
%%
%% Called by `quic_h3:connect/3' once `quic:set_owner_sync/2' returns
%% so the H3 process can inspect the underlying QUIC connection (via
%% `quic:has_early_keys/1') and route to either the 0-RTT `early_data'
%% path or the regular `awaiting_quic' wait.
-spec prime(pid()) -> ok.
prime(Conn) ->
    gen_statem:cast(Conn, prime).

%% @doc Send a request (client only).
%% Returns the stream ID for tracking the response.
-spec request(pid(), [{binary(), binary()}]) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Headers) ->
    request(Conn, Headers, #{}).

-spec request(pid(), [{binary(), binary()}], map()) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Headers, Opts) ->
    gen_statem:call(Conn, {request, Headers, Opts}).

%% @doc Open a client-initiated bidirectional stream outside the H3
%% request/response flow. When `SignalType' is a non-negative integer,
%% the stream is pre-claimed so inbound data is delivered as
%% `stream_type_data' owner messages. When `undefined', behaves as a
%% plain unclaimed stream.
-spec open_bidi_stream(pid(), non_neg_integer() | undefined) ->
    {ok, stream_id()} | {error, term()}.
open_bidi_stream(Conn, SignalType) ->
    gen_statem:call(Conn, {open_bidi_stream, SignalType}).

%% @doc Send a response (server only).
-spec send_response(pid(), stream_id(), pos_integer(), [{binary(), binary()}]) ->
    ok | {error, term()}.
send_response(Conn, StreamId, Status, Headers) ->
    gen_statem:call(Conn, {send_response, StreamId, Status, Headers}).

%% @doc Send a full response (status, headers and body) in one call (server only).
-spec respond(pid(), stream_id(), pos_integer(), [{binary(), binary()}], binary()) ->
    ok | {error, term()}.
respond(Conn, StreamId, Status, Headers, Body) ->
    gen_statem:call(Conn, {respond, StreamId, Status, Headers, Body}).

%% @doc Send body data on a stream.
-spec send_data(pid(), stream_id(), binary()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data) ->
    send_data(Conn, StreamId, Data, false).

-spec send_data(pid(), stream_id(), binary(), boolean()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    gen_statem:call(Conn, {send_data, StreamId, Data, Fin}).

%% @doc Send trailers on a stream.
-spec send_trailers(pid(), stream_id(), [{binary(), binary()}]) ->
    ok | {error, term()}.
send_trailers(Conn, StreamId, Trailers) ->
    gen_statem:call(Conn, {send_trailers, StreamId, Trailers}).

%% @doc Cancel a stream.
-spec cancel_stream(pid(), stream_id()) -> ok.
cancel_stream(Conn, StreamId) ->
    cancel_stream(Conn, StreamId, ?H3_REQUEST_CANCELLED).

-spec cancel_stream(pid(), stream_id(), error_code()) -> ok.
cancel_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:cast(Conn, {cancel_stream, StreamId, ErrorCode}).

%% @doc Initiate graceful shutdown.
-spec goaway(pid()) -> ok.
goaway(Conn) ->
    gen_statem:cast(Conn, goaway).

%% @doc Close the connection.
-spec close(pid()) -> ok.
close(Conn) ->
    gen_statem:cast(Conn, close).

%% @doc Get local settings.
-spec get_settings(pid()) -> map().
get_settings(Conn) ->
    gen_statem:call(Conn, get_settings).

%% @doc Get peer settings.
-spec get_peer_settings(pid()) -> map() | undefined.
get_peer_settings(Conn) ->
    gen_statem:call(Conn, get_peer_settings).

%% @doc Get the underlying QUIC connection pid.
-spec get_quic_conn(pid()) -> pid().
get_quic_conn(Conn) ->
    gen_statem:call(Conn, get_quic_conn).

%%====================================================================
%% Server Push API (RFC 9114 Section 4.6)
%%====================================================================

%% @doc Initiate a server push (server only).
%% Sends a PUSH_PROMISE on the request stream and allocates a push ID.
%% Returns the push ID for subsequent send_push_response/send_push_data calls.
-spec push(pid(), stream_id(), [{binary(), binary()}]) ->
    {ok, non_neg_integer()} | {error, term()}.
push(Conn, RequestStreamId, Headers) ->
    gen_statem:call(Conn, {push, RequestStreamId, Headers}).

%% @doc Send response headers on a push stream (server only).
-spec send_push_response(pid(), non_neg_integer(), pos_integer(), [{binary(), binary()}]) ->
    ok | {error, term()}.
send_push_response(Conn, PushId, Status, Headers) ->
    gen_statem:call(Conn, {send_push_response, PushId, Status, Headers}).

%% @doc Send data on a push stream (server only).
-spec send_push_data(pid(), non_neg_integer(), binary(), boolean()) ->
    ok | {error, term()}.
send_push_data(Conn, PushId, Data, Fin) ->
    gen_statem:call(Conn, {send_push_data, PushId, Data, Fin}).

%%====================================================================
%% Client Push API
%%====================================================================

%% @doc Set the maximum push ID (client only).
%% This enables server push up to the specified push ID.
-spec set_max_push_id(pid(), non_neg_integer()) -> ok | {error, term()}.
set_max_push_id(Conn, MaxPushId) ->
    gen_statem:call(Conn, {set_max_push_id, MaxPushId}).

%% @doc Cancel a push (client only).
%% Sends CANCEL_PUSH to tell server we don't want this push.
-spec cancel_push(pid(), non_neg_integer()) -> ok.
cancel_push(Conn, PushId) ->
    gen_statem:cast(Conn, {cancel_push, PushId}).

%% @doc Send an HTTP Datagram (RFC 9297) associated with a request stream.
-spec send_datagram(pid(), stream_id(), iodata()) -> ok | {error, term()}.
send_datagram(Conn, StreamId, Data) ->
    gen_statem:call(Conn, {send_h3_datagram, StreamId, Data}).

%% @doc Whether both sides negotiated RFC 9297 support.
-spec h3_datagrams_enabled(pid()) -> boolean().
h3_datagrams_enabled(Conn) ->
    gen_statem:call(Conn, h3_datagrams_enabled).

%% @doc Max payload we can fit in one H3 DATAGRAM for this stream, given
%% the peer's max_datagram_frame_size minus the quarter-stream-id prefix.
%% Returns 0 if RFC 9297 isn't live.
-spec max_datagram_size(pid(), stream_id()) -> non_neg_integer().
max_datagram_size(Conn, StreamId) ->
    gen_statem:call(Conn, {h3_max_datagram_size, StreamId}).

%% @doc Register a handler process to receive stream data.
%% The handler will receive `{quic_h3, Conn, {data, StreamId, Data, Fin}}' messages.
%% Any data buffered before registration is returned.
%% @see set_stream_handler/4
-spec set_stream_handler(pid(), stream_id(), pid()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
set_stream_handler(Conn, StreamId, HandlerPid) ->
    set_stream_handler(Conn, StreamId, HandlerPid, #{}).

%% @doc Register a handler with options.
%% Options:
%%   - drain_buffer: If true (default), returns buffered data instead of sending as messages
%% @returns ok if no buffered data, {ok, BufferedChunks} if data was buffered,
%%          or {error, Reason} on failure
-spec set_stream_handler(pid(), stream_id(), pid(), map()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
set_stream_handler(Conn, StreamId, HandlerPid, Opts) ->
    gen_statem:call(Conn, {set_stream_handler, StreamId, HandlerPid, Opts}).

%% @doc Unregister a stream handler.
%% Future data will be sent to the connection owner.
-spec unset_stream_handler(pid(), stream_id()) -> ok.
unset_stream_handler(Conn, StreamId) ->
    gen_statem:call(Conn, {unset_stream_handler, StreamId}).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() ->
    [state_functions, state_enter].

init({client, QuicConn, _Host, _Port, Opts, Owner}) ->
    process_flag(trap_exit, true),
    MonRef = monitor(process, Owner),
    QuicRef = monitor(process, QuicConn),

    LocalSettings = maps:merge(quic_h3_frame:default_settings(), maps:get(settings, Opts, #{})),
    MaxTableCapacity = maps:get(qpack_max_table_capacity, LocalSettings, 0),
    LocalMaxFieldSize = maps:get(
        max_field_section_size, LocalSettings, ?H3_DEFAULT_MAX_FIELD_SECTION_SIZE
    ),
    LocalMaxBlocked = maps:get(qpack_blocked_streams, LocalSettings, 0),
    LocalConnectEnabled = maps:get(enable_connect_protocol, LocalSettings, 0) =:= 1,
    StreamTypeHandler = maps:get(stream_type_handler, Opts, undefined),
    H3DatagramEnabled = maps:get(h3_datagram_enabled, Opts, false),

    State = #state{
        quic_conn = QuicConn,
        quic_ref = QuicRef,
        role = client,
        owner = Owner,
        owner_monitor = MonRef,
        local_settings = LocalSettings,
        %% Encoder starts static: its dynamic table is enabled only once the
        %% peer's SETTINGS are applied (apply_peer_settings/2), never from our
        %% local settings, so 0-RTT early-data requests stay static-only until
        %% the server's remembered capacity is known (RFC 9114 §7.2.4.2). The
        %% decoder is sized by the capacity we advertise, which we must honour.
        qpack_encoder = quic_qpack:new(#{max_allowed_capacity => MaxTableCapacity}),
        qpack_decoder = quic_qpack:new(#{max_dynamic_size => MaxTableCapacity}),
        % Client uses even stream IDs (0, 4, 8, ...)
        next_stream_id = 0,
        local_max_field_section_size = LocalMaxFieldSize,
        local_max_blocked_streams = LocalMaxBlocked,
        local_connect_enabled = LocalConnectEnabled,
        stream_type_handler = StreamTypeHandler,
        h3_datagram_enabled = H3DatagramEnabled
    },

    %% Client starts in `bootstrapping' and waits for the
    %% `prime' cast from quic_h3:connect/3 (sent after
    %% quic:set_owner_sync/2 completes). The prime handler
    %% then routes to early_data (0-RTT) or awaiting_quic.
    {ok, bootstrapping, State};
init({server, QuicConn, Opts, Owner}) ->
    process_flag(trap_exit, true),
    MonRef = monitor(process, Owner),
    QuicRef = monitor(process, QuicConn),

    LocalSettings = maps:merge(quic_h3_frame:default_settings(), maps:get(settings, Opts, #{})),
    MaxTableCapacity = maps:get(qpack_max_table_capacity, LocalSettings, 0),
    LocalMaxFieldSize = maps:get(
        max_field_section_size, LocalSettings, ?H3_DEFAULT_MAX_FIELD_SECTION_SIZE
    ),
    LocalMaxBlocked = maps:get(qpack_blocked_streams, LocalSettings, 0),
    LocalConnectEnabled = maps:get(enable_connect_protocol, LocalSettings, 0) =:= 1,
    Handler = maps:get(handler, Opts, undefined),
    StreamTypeHandler = maps:get(stream_type_handler, Opts, undefined),
    H3DatagramEnabled = maps:get(h3_datagram_enabled, Opts, false),

    State = #state{
        quic_conn = QuicConn,
        quic_ref = QuicRef,
        role = server,
        owner = Owner,
        owner_monitor = MonRef,
        local_settings = LocalSettings,
        %% Encoder starts static: its dynamic table is enabled only once the
        %% peer's SETTINGS are applied (apply_peer_settings/2), never from our
        %% local settings, so 0-RTT early-data requests stay static-only until
        %% the server's remembered capacity is known (RFC 9114 §7.2.4.2). The
        %% decoder is sized by the capacity we advertise, which we must honour.
        qpack_encoder = quic_qpack:new(#{max_allowed_capacity => MaxTableCapacity}),
        qpack_decoder = quic_qpack:new(#{max_dynamic_size => MaxTableCapacity}),
        % Server uses odd stream IDs (1, 5, 9, ...)
        next_stream_id = 1,
        local_max_field_section_size = LocalMaxFieldSize,
        local_max_blocked_streams = LocalMaxBlocked,
        local_connect_enabled = LocalConnectEnabled,
        stream_type_handler = StreamTypeHandler,
        h3_datagram_enabled = H3DatagramEnabled
    },

    %% Store handler in process dictionary for server
    case Handler of
        undefined -> ok;
        _ -> put(h3_handler, Handler)
    end,

    %% Start in awaiting_quic - wait for QUIC connected notification
    %% H3 streams should not be opened until QUIC connection is established
    {ok, awaiting_quic, State}.

terminate(_Reason, _StateName, #state{quic_conn = QuicConn}) ->
    quic:safe_close(QuicConn),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%====================================================================
%% State: bootstrapping
%% Wait for `prime' cast from quic_h3:connect/3 (sent after
%% set_owner_sync returns) before deciding between 0-RTT and
%% fresh-handshake paths.
%%====================================================================

bootstrapping(enter, _OldState, _State) ->
    keep_state_and_data;
bootstrapping(cast, prime, #state{quic_conn = QuicConn} = State) ->
    case quic:has_early_keys(QuicConn) of
        true ->
            {next_state, early_data, State#state{has_early_keys = true}};
        false ->
            {next_state, awaiting_quic, State}
    end;
bootstrapping({call, _From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [postpone]};
bootstrapping({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
bootstrapping({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
bootstrapping({call, From}, get_quic_conn, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [{reply, From, QuicConn}]};
bootstrapping(cast, close, State) ->
    {next_state, closing, State};
bootstrapping(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
bootstrapping(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
bootstrapping(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
bootstrapping(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
bootstrapping(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
%% Postpone QUIC events that can race ahead of `prime' when QUIC resumes
%% (0-RTT/1-RTT handshake completes) before the application has had a
%% chance to cast `prime'. Without postponing, the catch-all clause
%% below would silently drop these and strand the H3 FSM in a state
%% that waits for them to arrive again. RFC 9114 §3.3 ordering.
bootstrapping(info, {quic, QC, {connected, _}}, #state{quic_conn = QC}) ->
    {keep_state_and_data, [postpone]};
bootstrapping(info, {quic, QC, {stream_data, _, _, _}}, #state{quic_conn = QC}) ->
    {keep_state_and_data, [postpone]};
bootstrapping(info, {quic, QC, {new_stream, _, _}}, #state{quic_conn = QC}) ->
    {keep_state_and_data, [postpone]};
bootstrapping(info, {quic, QC, {error, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
bootstrapping(info, {quic, QC, {closed, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
bootstrapping(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: early_data
%% Open critical H3 streams and send SETTINGS as 0-RTT data. Accept
%% request calls and forward HEADERS as 0-RTT. Converge to connected
%% when both QUIC has handshaked AND peer SETTINGS has arrived.
%% RFC 9114 §6.2.1 (SETTINGS-first), §7.2.4.2 (0-RTT initialization).
%%====================================================================

early_data(enter, _OldState, State) ->
    case open_critical_streams(State) of
        {ok, State1} ->
            case send_settings(State1) of
                {ok, State2} -> {keep_state, State2};
                {error, Reason} -> {stop, {error, Reason}}
            end;
        {error, Reason} ->
            {stop, {error, Reason}}
    end;
early_data({call, From}, {request, Headers, Opts}, #state{role = client} = State) ->
    case send_request(Headers, Opts, State) of
        {ok, StreamId, State1} ->
            {keep_state, State1, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
early_data({call, From}, {request, _Headers, _Opts}, #state{role = server}) ->
    {keep_state_and_data, [{reply, From, {error, server_cannot_request}}]};
early_data(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_transition_from_early_data(State1);
        {transition, goaway_received, State1} ->
            {next_state, goaway_received, State1};
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
early_data(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_new_stream(StreamId, Type, State) of
        {ok, State1} ->
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
early_data(
    info,
    {quic, QuicConn, {stream_closed, StreamId, ErrorCode}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_closed(StreamId, ErrorCode, State) of
        {ok, State1} ->
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
early_data(info, {quic, QuicConn, {connected, _Info}}, #state{quic_conn = QuicConn} = State) ->
    maybe_transition_from_early_data(State#state{quic_connected = true});
early_data({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
early_data({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
early_data({call, From}, get_quic_conn, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [{reply, From, QuicConn}]};
early_data(cast, close, State) ->
    {next_state, closing, State};
early_data(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
early_data(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
early_data(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
early_data(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
early_data(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
early_data(info, {quic, QC, {error, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
early_data(info, {quic, QC, {closed, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
early_data(_EventType, _Event, _State) ->
    keep_state_and_data.

%% Convergence helper. Both flags must be true to advance to connected;
%% if only quic_connected is true, hand off to h3_connecting which
%% already knows how to wait for peer SETTINGS.
maybe_transition_from_early_data(
    #state{quic_connected = true, settings_received = true} = State
) ->
    {next_state, connected, State};
maybe_transition_from_early_data(#state{quic_connected = true} = State) ->
    {next_state, h3_connecting, State};
maybe_transition_from_early_data(State) ->
    {keep_state, State}.

%%====================================================================
%% State: awaiting_quic
%% Wait for QUIC connection to be established before opening H3 streams
%%====================================================================

awaiting_quic(enter, _OldState, _State) ->
    %% Wait for QUIC connected notification (ownership transferred by quic_h3:connect)
    keep_state_and_data;
%% Match on quic_conn pid, not quic_ref (which is a monitor reference)
awaiting_quic(info, {quic, QuicConn, {connected, _Info}}, #state{quic_conn = QuicConn} = State) ->
    %% QUIC is ready - transition to h3_connecting to open H3 streams
    {next_state, h3_connecting, State};
%% Postpone stream data received before we're ready
awaiting_quic(info, {quic, QuicConn, {stream_data, _, _, _}}, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [postpone]};
awaiting_quic(info, {quic, QuicConn, {new_stream, _, _}}, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [postpone]};
awaiting_quic({call, From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};
awaiting_quic({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
awaiting_quic({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
awaiting_quic({call, From}, get_quic_conn, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [{reply, From, QuicConn}]};
awaiting_quic(cast, close, State) ->
    {next_state, closing, State};
awaiting_quic(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
awaiting_quic(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
awaiting_quic(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
awaiting_quic(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
awaiting_quic(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
awaiting_quic(info, {quic, QC, {error, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
awaiting_quic(info, {quic, QC, {closed, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
awaiting_quic(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: h3_connecting
%% Open critical H3 streams and exchange SETTINGS
%%====================================================================

h3_connecting(enter, _OldState, #state{settings_sent = true} = _State) ->
    %% Critical streams were already opened and SETTINGS already sent
    %% during the early_data state. Re-running open_critical_streams/1
    %% here would open a second control stream (plus extra QPACK
    %% streams) and emit a second SETTINGS frame, which RFC 9114 §6.2.1
    %% forbids (H3_STREAM_CREATION_ERROR).
    keep_state_and_data;
h3_connecting(enter, _OldState, State) ->
    %% Open critical streams and send SETTINGS
    case open_critical_streams(State) of
        {ok, State1} ->
            case send_settings(State1) of
                {ok, State2} ->
                    {keep_state, State2};
                {error, Reason} ->
                    {stop, {error, Reason}}
            end;
        {error, Reason} ->
            {stop, {error, Reason}}
    end;
h3_connecting(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_transition_connected(State1);
        {transition, goaway_received, State1} ->
            %% GOAWAY received during connecting - transition to goaway_received
            {next_state, goaway_received, State1};
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
h3_connecting(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_new_stream(StreamId, Type, State) of
        {ok, State1} ->
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
h3_connecting(
    info,
    {quic, QuicConn, {stream_closed, StreamId, ErrorCode}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_closed(StreamId, ErrorCode, State) of
        {ok, State1} ->
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
h3_connecting({call, From}, {request, _Headers, _Opts}, _State) ->
    %% Can't send requests until connected
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};
h3_connecting({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
h3_connecting({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
h3_connecting({call, From}, get_quic_conn, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [{reply, From, QuicConn}]};
h3_connecting(cast, close, State) ->
    {next_state, closing, State};
h3_connecting(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
h3_connecting(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
h3_connecting(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
h3_connecting(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
h3_connecting(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
h3_connecting(info, {quic, QC, {error, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
h3_connecting(info, {quic, QC, {closed, Reason}}, #state{quic_conn = QC} = State) ->
    handle_quic_failed(Reason, State);
h3_connecting(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: connected
%%====================================================================

connected(enter, _OldState, #state{owner = Owner} = State) ->
    Owner ! {quic_h3, self(), connected},
    {keep_state, State};
connected(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1};
        {transition, goaway_received, State1} ->
            %% GOAWAY received - transition to goaway_received
            {next_state, goaway_received, State1};
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
connected(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_new_stream(StreamId, Type, State) of
        {ok, State1} ->
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
connected(
    info,
    {quic, QuicConn, {stream_closed, StreamId, ErrorCode}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_closed(StreamId, ErrorCode, State) of
        {ok, State1} ->
            %% For non-claimed streams keep today's generic event;
            %% claimed streams already got stream_type_reset/closed
            %% inside handle_stream_closed/3.
            case claimed_stream_direction(StreamId, State) of
                {ok, _Dir} -> ok;
                error -> notify_stream_reset(StreamId, ErrorCode, State1)
            end,
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
connected(
    info,
    {quic, QuicConn, {stop_sending, StreamId, ErrorCode}},
    #state{quic_conn = QuicConn, owner = Owner} = State
) ->
    case claimed_stream_direction(StreamId, State) of
        {ok, Direction} ->
            Owner !
                {quic_h3, self(), {stream_type_stop_sending, Direction, StreamId, ErrorCode}};
        error ->
            ok
    end,
    {keep_state, State};
connected(
    info,
    {quic, QuicConn, {datagram, Data}},
    #state{quic_conn = QuicConn} = State
) ->
    deliver_h3_datagram(Data, State),
    {keep_state, State};
connected({call, From}, {send_h3_datagram, StreamId, Data}, State) ->
    {keep_state, State, [{reply, From, h3_send_datagram(StreamId, Data, State)}]};
connected({call, From}, h3_datagrams_enabled, State) ->
    {keep_state, State, [{reply, From, h3_datagrams_live(State)}]};
connected(
    {call, From},
    {h3_max_datagram_size, StreamId},
    #state{quic_conn = QuicConn} = State
) ->
    Reply =
        case h3_datagrams_live(State) of
            false ->
                0;
            true ->
                case quic:datagram_max_size(QuicConn) of
                    0 -> 0;
                    Max -> max(0, Max - byte_size(quic_varint:encode(StreamId bsr 2)))
                end
        end,
    {keep_state, State, [{reply, From, Reply}]};
connected({call, From}, {request, Headers, Opts}, #state{role = client} = State) ->
    case send_request(Headers, Opts, State) of
        {ok, StreamId, State1} ->
            {keep_state, State1, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {request, _Headers, _Opts}, #state{role = server}) ->
    {keep_state_and_data, [{reply, From, {error, server_cannot_request}}]};
connected({call, From}, {open_bidi_stream, SignalType}, State) ->
    case do_open_bidi_stream(SignalType, State) of
        {ok, StreamId, State1} ->
            {keep_state, State1, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_response, StreamId, Status, Headers}, State) ->
    case do_send_response(StreamId, Status, Headers, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {respond, StreamId, Status, Headers, Body}, State) ->
    case do_respond(StreamId, Status, Headers, Body, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_trailers, StreamId, Trailers}, State) ->
    case do_send_trailers(StreamId, Trailers, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
connected({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
connected({call, From}, get_quic_conn, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [{reply, From, QuicConn}]};
%% Server Push API
connected({call, From}, {push, RequestStreamId, Headers}, #state{role = server} = State) ->
    case do_push(RequestStreamId, Headers, State) of
        {ok, PushId, State1} ->
            {keep_state, State1, [{reply, From, {ok, PushId}}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {push, _RequestStreamId, _Headers}, #state{role = client}) ->
    {keep_state_and_data, [{reply, From, {error, client_cannot_push}}]};
connected(
    {call, From}, {send_push_response, PushId, Status, Headers}, #state{role = server} = State
) ->
    case do_send_push_response(PushId, Status, Headers, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_push_response, _PushId, _Status, _Headers}, #state{role = client}) ->
    {keep_state_and_data, [{reply, From, {error, client_cannot_push}}]};
connected({call, From}, {send_push_data, PushId, Data, Fin}, #state{role = server} = State) ->
    case do_send_push_data(PushId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_push_data, _PushId, _Data, _Fin}, #state{role = client}) ->
    {keep_state_and_data, [{reply, From, {error, client_cannot_push}}]};
%% Client Push API
connected({call, From}, {set_max_push_id, MaxPushId}, #state{role = client} = State) ->
    case do_set_max_push_id(MaxPushId, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {set_max_push_id, _MaxPushId}, #state{role = server}) ->
    {keep_state_and_data, [{reply, From, {error, server_cannot_set_max_push_id}}]};
%% Per-stream handler registration
connected({call, From}, {set_stream_handler, StreamId, HandlerPid, Opts}, State) ->
    case do_set_stream_handler(StreamId, HandlerPid, Opts, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {ok, BufferedChunks, State1} ->
            {keep_state, State1, [{reply, From, {ok, BufferedChunks}}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {unset_stream_handler, StreamId}, State) ->
    State1 = do_unset_stream_handler(StreamId, State),
    {keep_state, State1, [{reply, From, ok}]};
connected(cast, {cancel_push, PushId}, #state{role = client} = State) ->
    State1 = do_cancel_push(PushId, State),
    {keep_state, State1};
connected(cast, {cancel_push, _PushId}, #state{role = server}) ->
    %% Server can't cancel push as client would
    keep_state_and_data;
connected(cast, {cancel_stream, StreamId, ErrorCode}, State) ->
    State1 = do_cancel_stream(StreamId, ErrorCode, State),
    {keep_state, State1};
connected(cast, goaway, State) ->
    case send_goaway(State) of
        {ok, State1} ->
            {next_state, goaway_sent, State1};
        {error, _Reason} ->
            {next_state, closing, State}
    end;
connected(cast, close, State) ->
    {next_state, closing, State};
connected(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
connected(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
connected(info, {'DOWN', Ref, process, _Pid, _Reason}, #state{stream_handlers = Handlers} = State) ->
    %% Check if this is a stream handler going down
    case find_handler_by_ref(Ref, Handlers) of
        {ok, StreamId} ->
            State1 = do_unset_stream_handler(StreamId, State),
            {keep_state, State1};
        error ->
            %% Unknown monitor, ignore
            keep_state_and_data
    end;
connected(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
connected(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
connected(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
connected(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: goaway_sent
%%====================================================================

goaway_sent(enter, _OldState, #state{owner = Owner, goaway_id = GoawayId}) ->
    Owner ! {quic_h3, self(), {goaway_sent, GoawayId}},
    keep_state_and_data;
goaway_sent(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    %% Route through handle_new_stream so the GOAWAY rejection in
    %% stream_blocked_by_goaway/3 fires for in-progress drain.
    case handle_new_stream(StreamId, Type, State) of
        {ok, State1} -> {keep_state, State1};
        {error, Reason} -> handle_connection_error(Reason, State)
    end;
goaway_sent(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    %% Continue processing existing streams
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_close_if_drained(State1);
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
goaway_sent({call, From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [{reply, From, {error, goaway_sent}}]};
goaway_sent({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    %% Allow completing existing streams
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
goaway_sent(cast, close, State) ->
    {next_state, closing, State};
goaway_sent(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
goaway_sent(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
goaway_sent(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
goaway_sent(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
goaway_sent(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
goaway_sent(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: goaway_received
%%====================================================================

goaway_received(enter, _OldState, #state{owner = Owner, goaway_id = GoawayId}) ->
    Owner ! {quic_h3, self(), {goaway, GoawayId}},
    keep_state_and_data;
goaway_received(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_new_stream(StreamId, Type, State) of
        {ok, State1} -> {keep_state, State1};
        {error, Reason} -> handle_connection_error(Reason, State)
    end;
goaway_received(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_close_if_drained(State1);
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
goaway_received({call, From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [{reply, From, {error, goaway_received}}]};
goaway_received({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
goaway_received(cast, close, State) ->
    {next_state, closing, State};
goaway_received(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
goaway_received(info, {'DOWN', Ref, process, _, Reason}, #state{quic_ref = Ref} = State) ->
    handle_quic_down(Reason, State);
goaway_received(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
goaway_received(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
goaway_received(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
goaway_received(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: closing
%%====================================================================

closing(enter, _OldState, #state{quic_conn = QuicConn, owner = Owner}) ->
    quic:safe_close(QuicConn),
    Owner ! {quic_h3, self(), closed},
    {stop, normal};
closing(
    info,
    {quic, QC, {session_ticket, T}},
    #state{quic_conn = QC} = State
) ->
    ok = forward_session_ticket(T, State),
    keep_state_and_data;
closing(
    info,
    {quic, QC, {early_data_rejected, StreamIds}},
    #state{quic_conn = QC} = State
) ->
    {keep_state, forward_early_data_rejected(StreamIds, State)};
closing(
    {call, From},
    early_data_accepted,
    #state{quic_conn = QC} = _State
) ->
    {keep_state_and_data, [{reply, From, quic:early_data_accepted(QC)}]};
closing(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% Internal: QUIC connection DOWN
%%====================================================================

%% The QUIC connection reported a failure (bad certificate, TLS alert, peer
%% close) before HTTP/3 came up. Pass the reason to the owner so a caller in
%% `quic_h3:wait_connected/2' fails with it instead of timing out.
handle_quic_failed(Reason, #state{owner = Owner} = State) ->
    Owner ! {quic_h3, self(), {closed, Reason}},
    {stop, normal, State}.

%% A cleanly closed QUIC connection must not crash the H3 process:
%% only an abnormal QUIC exit is propagated as {quic_closed, Reason}.
handle_quic_down(Reason, #state{owner = Owner} = State) ->
    Owner ! {quic_h3, self(), closed},
    case Reason of
        normal -> {stop, normal, State};
        shutdown -> {stop, normal, State};
        {shutdown, _} -> {stop, normal, State};
        noproc -> {stop, normal, State};
        _ -> {stop, {quic_closed, Reason}, State}
    end.

%%====================================================================
%% Internal: Critical Streams
%%====================================================================

open_critical_streams(#state{quic_conn = QuicConn} = State) ->
    %% Open control stream
    case quic:open_unidirectional_stream(QuicConn) of
        {ok, ControlStreamId} ->
            %% Send stream type
            TypeData = quic_h3_frame:encode_stream_type(control),
            ok = quic:send_data(QuicConn, ControlStreamId, TypeData, false),

            %% Open QPACK encoder stream
            case quic:open_unidirectional_stream(QuicConn) of
                {ok, EncoderStreamId} ->
                    EncTypeData = quic_h3_frame:encode_stream_type(qpack_encoder),
                    ok = quic:send_data(QuicConn, EncoderStreamId, EncTypeData, false),

                    %% Open QPACK decoder stream
                    case quic:open_unidirectional_stream(QuicConn) of
                        {ok, DecoderStreamId} ->
                            DecTypeData = quic_h3_frame:encode_stream_type(qpack_decoder),
                            ok = quic:send_data(QuicConn, DecoderStreamId, DecTypeData, false),

                            {ok, State#state{
                                local_control_stream = ControlStreamId,
                                local_encoder_stream = EncoderStreamId,
                                local_decoder_stream = DecoderStreamId
                            }};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

send_settings(
    #state{
        quic_conn = QuicConn,
        local_control_stream = ControlStream,
        local_settings = Settings0,
        h3_datagram_enabled = H3DatagramEnabled
    } = State
) ->
    %% RFC 9297 §2.1: advertise SETTINGS_H3_DATAGRAM only when the
    %% caller opted in AND the underlying QUIC connection actually
    %% negotiated a non-zero max_datagram_frame_size. Advertising the
    %% setting without QUIC datagrams is an H3_SETTINGS_ERROR per spec.
    Settings =
        case H3DatagramEnabled andalso quic:datagram_max_size(QuicConn) > 0 of
            true -> Settings0#{h3_datagram => 1};
            false -> Settings0
        end,
    SettingsFrame = quic_h3_frame:encode_settings(Settings),
    case quic:send_data(QuicConn, ControlStream, SettingsFrame, false) of
        ok ->
            {ok, State#state{settings_sent = true}};
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Internal: Stream Handling
%%====================================================================

handle_new_stream(StreamId, unidirectional, State) ->
    %% Unidirectional stream - need to read type first
    {ok, State#state{uni_stream_buffers = maps:put(StreamId, <<>>, State#state.uni_stream_buffers)}};
handle_new_stream(StreamId, bidirectional, #state{role = Role} = State) ->
    %% Note: quic_connection does not emit {new_stream, _, _} in
    %% production, so this clause is currently only exercised by
    %% eunit. Real dispatch for fresh peer-initiated bidi streams
    %% flows through classify_stream_type/2 → handle_bidi_stream_type/4.
    %% RFC 9114 Section 4.1: Validate stream ID parity
    %% Client-initiated streams are even (0, 4, 8...)
    %% Server-initiated streams are odd (1, 5, 9...)
    ExpectedParity =
        case Role of
            %% We're server, peer (client) uses even IDs
            server -> 0;
            %% We're client, peer (server) uses odd IDs
            client -> 1
        end,
    case (StreamId rem 4) =:= ExpectedParity of
        false ->
            {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"invalid stream ID parity">>}};
        true ->
            case stream_blocked_by_goaway(StreamId, Role, State) of
                true ->
                    %% RFC 9114 §5.2: streams at or beyond the GOAWAY ID
                    %% MUST NOT be processed - reset the new stream and keep
                    %% the connection.
                    quic:reset_stream(
                        State#state.quic_conn, StreamId, ?H3_REQUEST_REJECTED
                    ),
                    {ok, State};
                false ->
                    case State#state.stream_type_handler of
                        undefined ->
                            open_bidi_request_stream(StreamId, State);
                        _Fun ->
                            %% Defer request-stream creation until we can
                            %% peek the first varint and ask the handler.
                            Buffers = State#state.bidi_type_buffers,
                            {ok, State#state{
                                bidi_type_buffers = Buffers#{StreamId => <<>>}
                            }}
                    end
            end
    end.

open_bidi_request_stream(
    StreamId, #state{streams = Streams, role = Role} = State
) ->
    Stream = #h3_stream{
        id = StreamId,
        type = request,
        state = open
    },
    NewState = State#state{streams = Streams#{StreamId => Stream}},
    case Role of
        server ->
            {ok, NewState#state{
                last_stream_id = max(StreamId, State#state.last_stream_id)
            }};
        client ->
            {ok, NewState}
    end.

%% RFC 9114 §5.2: a sender MUST NOT initiate, and a receiver MUST treat as
%% rejected, request streams whose ID is at or beyond the locally-sent
%% GOAWAY identifier (server) or the received GOAWAY identifier (client).
stream_blocked_by_goaway(_StreamId, _Role, #state{goaway_id = undefined}) ->
    false;
stream_blocked_by_goaway(StreamId, server, #state{goaway_id = GoawayId}) ->
    StreamId >= GoawayId;
stream_blocked_by_goaway(_StreamId, client, _State) ->
    %% Client receives GOAWAY carrying a push ID; bidi stream IDs are
    %% client-initiated and not constrained by the goaway_id value.
    false.

handle_stream_data(StreamId, Data, Fin, State) ->
    case classify_stream(StreamId, State) of
        {uni, discarded} ->
            %% RFC 9114 §6.2.3: unknown uni-stream bytes are ignored.
            _ = Data,
            _ = Fin,
            {ok, State};
        {uni, {claimed, _Type}} ->
            forward_claimed_uni_data(StreamId, Data, Fin, State),
            {ok, State};
        {uni, pending} ->
            handle_uni_stream_type(StreamId, Data, Fin, State);
        {uni, push_pending} ->
            %% Push stream waiting for push ID parsing
            handle_push_stream_id(StreamId, Data, State);
        {uni, {push, PushId}} ->
            %% Active push stream - process frames
            handle_push_stream_data(StreamId, PushId, Data, Fin, State);
        {uni, control} ->
            %% Control stream may trigger state transition (GOAWAY)
            handle_control_stream_data(StreamId, Data, State);
        {uni, qpack_encoder} ->
            handle_encoder_stream_data(Data, State);
        {uni, qpack_decoder} ->
            handle_decoder_stream_data(Data, State);
        {bidi, pending_type} ->
            handle_bidi_stream_type(StreamId, Data, Fin, State);
        {bidi, {claimed, _Type}} ->
            forward_claimed_bidi_data(StreamId, Data, Fin, State),
            {ok, State};
        {bidi, request} ->
            handle_request_stream_data(StreamId, Data, Fin, State);
        unknown ->
            %% New unidirectional stream
            handle_uni_stream_type(StreamId, Data, Fin, State)
    end.

classify_stream(StreamId, #state{peer_control_stream = StreamId}) ->
    {uni, control};
classify_stream(StreamId, #state{peer_encoder_stream = StreamId}) ->
    {uni, qpack_encoder};
classify_stream(StreamId, #state{peer_decoder_stream = StreamId}) ->
    {uni, qpack_decoder};
classify_stream(StreamId, #state{uni_stream_buffers = Buffers, received_pushes = Received} = State) ->
    case classify_by_extension_tables(StreamId, State) of
        {ok, Classification} -> Classification;
        error -> classify_fresh_uni_stream(StreamId, Buffers, Received, State)
    end.

%% Walk the extension bookkeeping (discarded / claimed uni / claimed
%% bidi / pending bidi) once, keeping classify_stream/2 flat so elvis's
%% no_deep_nesting rule stays happy.
classify_by_extension_tables(StreamId, State) ->
    case sets:is_element(StreamId, State#state.discarded_uni_streams) of
        true ->
            {ok, {uni, discarded}};
        false ->
            classify_by_claim_tables(StreamId, State)
    end.

classify_by_claim_tables(StreamId, State) ->
    case maps:find(StreamId, State#state.claimed_uni_streams) of
        {ok, Type} ->
            {ok, {uni, {claimed, Type}}};
        error ->
            case maps:find(StreamId, State#state.claimed_bidi_streams) of
                {ok, BType} -> {ok, {bidi, {claimed, BType}}};
                error -> classify_pending_bidi(StreamId, State)
            end
    end.

classify_pending_bidi(StreamId, State) ->
    case maps:is_key(StreamId, State#state.bidi_type_buffers) of
        true -> {ok, {bidi, pending_type}};
        false -> error
    end.

classify_fresh_uni_stream(StreamId, Buffers, Received, State) ->
    case maps:is_key(StreamId, Buffers) of
        true ->
            %% Check if this is a push stream pending push ID parsing
            case maps:get(StreamId, Buffers) of
                {push_pending, _} -> {uni, push_pending};
                _ -> {uni, pending}
            end;
        false ->
            %% Check if this is an active push stream (client-side)
            case find_push_by_stream_id(StreamId, Received) of
                {ok, PushId} -> {uni, {push, PushId}};
                error -> classify_stream_type(StreamId, State)
            end
    end.

%% Helper to classify stream by ID pattern. For peer-initiated bidi
%% streams with a stream_type_handler configured, return
%% {bidi, pending_type} so the dispatcher lets handle_bidi_stream_type/4
%% peek the first varint and consult the handler (claim vs. ignore).
%% Without a handler the stream goes straight to the HTTP/3 request path.
classify_stream_type(StreamId, #state{stream_type_handler = Handler}) ->
    %% Check if it's a bidirectional stream (bit 1 = 0 for bidi)
    case StreamId band 2 of
        0 when Handler =/= undefined -> {bidi, pending_type};
        0 -> {bidi, request};
        2 -> unknown
    end.

%% Find push ID by stream ID in received_pushes map (values are #h3_stream{}).
find_push_by_stream_id(StreamId, Received) ->
    maps:fold(
        fun
            (PushId, #h3_stream{id = SId}, _Acc) when SId =:= StreamId ->
                {ok, PushId};
            (_, _, Acc) ->
                Acc
        end,
        error,
        Received
    ).

handle_uni_stream_type(StreamId, Data, Fin, #state{uni_stream_buffers = Buffers} = State) ->
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,
    case quic_h3_frame:decode_stream_type(Combined) of
        {ok, Type, Rest} ->
            State1 = State#state{uni_stream_buffers = maps:remove(StreamId, Buffers)},
            case assign_uni_stream(StreamId, Type, State1) of
                {ok, State2} ->
                    dispatch_remaining_uni_data(StreamId, Type, Rest, Fin, State2);
                {error, Reason} ->
                    {error, Reason, State1}
            end;
        {more, _} ->
            {ok, State#state{uni_stream_buffers = Buffers#{StreamId => Combined}}}
    end.

%% After classifying a uni stream, either hand off to an extension
%% handler (when one claims the type), discard the rest (unknown types
%% with no handler, RFC 9114 §6.2.3), or re-enter stream dispatch so
%% known types process their payload. Fin propagates so a single
%% STREAM frame carrying type-varint + payload + FIN surfaces as one
%% {stream_type_data, uni, _, _, true} event.
dispatch_remaining_uni_data(StreamId, {unknown, Type}, Rest, Fin, State) ->
    case consult_stream_type_handler(uni, StreamId, Type, State) of
        claim ->
            State1 = claim_uni_stream(StreamId, Type, State),
            forward_claimed_uni_data(StreamId, Rest, Fin, State1),
            {ok, State1};
        ignore ->
            {ok, State#state{
                discarded_uni_streams = sets:add_element(
                    StreamId, State#state.discarded_uni_streams
                )
            }}
    end;
dispatch_remaining_uni_data(_StreamId, _Type, <<>>, Fin, State) ->
    _ = Fin,
    {ok, State};
dispatch_remaining_uni_data(StreamId, _Type, Rest, Fin, State) ->
    handle_stream_data(StreamId, Rest, Fin, State).

consult_stream_type_handler(_Direction, _StreamId, _Type, #state{
    stream_type_handler = undefined
}) ->
    ignore;
consult_stream_type_handler(Direction, StreamId, Type, #state{
    stream_type_handler = Fun
}) ->
    case Fun(Direction, StreamId, Type) of
        claim -> claim;
        _ -> ignore
    end.

claim_uni_stream(StreamId, Type, #state{owner = Owner} = State) ->
    Owner ! {quic_h3, self(), {stream_type_open, uni, StreamId, Type}},
    State#state{
        claimed_uni_streams = maps:put(StreamId, Type, State#state.claimed_uni_streams)
    }.

forward_claimed_uni_data(_StreamId, <<>>, false, _State) ->
    ok;
forward_claimed_uni_data(StreamId, Data, Fin, #state{owner = Owner}) ->
    Owner ! {quic_h3, self(), {stream_type_data, uni, StreamId, Data, Fin}},
    ok.

%% First bytes of a peer-initiated bidi stream arrive here when a
%% stream_type_handler is set. Buffer until a full varint is available,
%% then consult the handler. On `claim' record the stream and forward
%% the remainder + any future bytes to the owner. On `ignore' create
%% the HTTP/3 request stream lazily and re-feed every buffered byte
%% (including the already-decoded varint) so HTTP/3 parsing sees a
%% brand-new stream.
handle_bidi_stream_type(StreamId, Data, Fin, State) ->
    Buffers = State#state.bidi_type_buffers,
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,
    case quic_h3_frame:decode_stream_type(Combined) of
        {more, _} ->
            {ok, State#state{bidi_type_buffers = Buffers#{StreamId => Combined}}};
        {ok, Decoded, Rest} ->
            VarintType = stream_type_varint(Decoded),
            case consult_stream_type_handler(bidi, StreamId, VarintType, State) of
                claim ->
                    State1 = claim_bidi_stream(StreamId, VarintType, State),
                    forward_claimed_bidi_data(StreamId, Rest, Fin, State1),
                    {ok, State1};
                ignore ->
                    fall_back_to_request_stream(StreamId, Combined, Fin, State)
            end
    end.

%% decode_stream_type surfaces known codepoints as atoms (control,
%% qpack_encoder, ...) so convert them back to the numeric value the
%% handler contract expects.
stream_type_varint(control) -> ?H3_STREAM_CONTROL;
stream_type_varint(push) -> ?H3_STREAM_PUSH;
stream_type_varint(qpack_encoder) -> ?H3_STREAM_QPACK_ENCODER;
stream_type_varint(qpack_decoder) -> ?H3_STREAM_QPACK_DECODER;
stream_type_varint({unknown, V}) -> V.

claim_bidi_stream(StreamId, Type, #state{owner = Owner} = State) ->
    Owner ! {quic_h3, self(), {stream_type_open, bidi, StreamId, Type}},
    State#state{
        bidi_type_buffers = maps:remove(StreamId, State#state.bidi_type_buffers),
        claimed_bidi_streams = maps:put(
            StreamId, Type, State#state.claimed_bidi_streams
        )
    }.

%% Local-open counterpart of claim_bidi_stream/3. Opens a client-initiated
%% bidi stream on the underlying QUIC connection and, when SignalType is
%% set, pre-claims it so inbound bytes bypass the H3 request parser and
%% land as {stream_type_data, bidi, ...} owner messages.
do_open_bidi_stream(SignalType, #state{quic_conn = QuicConn} = State) ->
    case quic:open_stream(QuicConn) of
        {ok, StreamId} ->
            {ok, StreamId, pre_claim_bidi_stream(StreamId, SignalType, State)};
        {error, _} = Err ->
            Err
    end.

%% Pure half of do_open_bidi_stream/2: given a freshly opened StreamId,
%% record the claim (if any) and notify the owner.
pre_claim_bidi_stream(_StreamId, undefined, State) ->
    State;
pre_claim_bidi_stream(StreamId, Type, #state{owner = Owner} = State) when
    is_integer(Type), Type >= 0
->
    Owner ! {quic_h3, self(), {stream_type_open, bidi, StreamId, Type}},
    State#state{
        claimed_bidi_streams = maps:put(
            StreamId, Type, State#state.claimed_bidi_streams
        )
    }.

forward_claimed_bidi_data(_StreamId, <<>>, false, _State) ->
    ok;
forward_claimed_bidi_data(StreamId, Data, Fin, #state{owner = Owner}) ->
    Owner ! {quic_h3, self(), {stream_type_data, bidi, StreamId, Data, Fin}},
    ok.

%% Handler said `ignore' on the first varint. Promote the pending bidi
%% to a normal H3 request stream and replay every byte we'd buffered,
%% including the varint itself, so the request parser sees the raw
%% original stream.
fall_back_to_request_stream(StreamId, Combined, Fin, State) ->
    Buffers = State#state.bidi_type_buffers,
    {ok, State1} = open_bidi_request_stream(StreamId, State#state{
        bidi_type_buffers = maps:remove(StreamId, Buffers)
    }),
    handle_request_stream_data(StreamId, Combined, Fin, State1).

%% Returns the direction a claimed stream was classified under, if any.
claimed_stream_direction(StreamId, #state{
    claimed_uni_streams = U, claimed_bidi_streams = B
}) ->
    case maps:is_key(StreamId, U) of
        true ->
            {ok, uni};
        false ->
            case maps:is_key(StreamId, B) of
                true -> {ok, bidi};
                false -> error
            end
    end.

assign_uni_stream(StreamId, control, #state{peer_control_stream = undefined} = State) ->
    {ok, State#state{peer_control_stream = StreamId}};
assign_uni_stream(_StreamId, control, _State) ->
    %% Duplicate control stream
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"duplicate control stream">>}};
assign_uni_stream(StreamId, qpack_encoder, #state{peer_encoder_stream = undefined} = State) ->
    {ok, State#state{peer_encoder_stream = StreamId}};
assign_uni_stream(_StreamId, qpack_encoder, _State) ->
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"duplicate encoder stream">>}};
assign_uni_stream(StreamId, qpack_decoder, #state{peer_decoder_stream = undefined} = State) ->
    {ok, State#state{peer_decoder_stream = StreamId}};
assign_uni_stream(_StreamId, qpack_decoder, _State) ->
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"duplicate decoder stream">>}};
assign_uni_stream(_StreamId, push, #state{role = server}) ->
    %% RFC 9114 Section 4.6: only servers can initiate push streams
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"server received push stream">>}};
assign_uni_stream(_StreamId, push, #state{role = client, local_max_push_id = undefined}) ->
    %% Client never sent MAX_PUSH_ID but server is pushing - protocol error
    %% RFC 9114 Section 4.6: server MUST NOT use push until MAX_PUSH_ID received
    {error, {connection_error, ?H3_ID_ERROR, <<"push without MAX_PUSH_ID">>}};
assign_uni_stream(StreamId, push, #state{role = client, uni_stream_buffers = Buffers} = State) ->
    %% Client receiving push stream - buffer for push ID parsing
    %% Push stream format: Type(0x01) already parsed, next is Push ID (varint)
    {ok, State#state{
        uni_stream_buffers = maps:put(StreamId, {push_pending, <<>>}, Buffers)
    }};
assign_uni_stream(_StreamId, {unknown, _Type}, State) ->
    %% Unknown stream types are ignored per RFC 9114
    {ok, State}.

handle_control_stream_data(StreamId, Data, #state{stream_buffers = Buffers} = State) ->
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,
    case process_control_frames(Combined, State) of
        {ok, Rest, State1} ->
            {ok, State1#state{stream_buffers = Buffers#{StreamId => Rest}}};
        {transition, NextState, Rest, State1} ->
            %% State transition requested (e.g., GOAWAY received)
            {transition, NextState, State1#state{stream_buffers = Buffers#{StreamId => Rest}}};
        {error, Reason} ->
            {error, Reason, State}
    end.

process_control_frames(Data, State) ->
    case quic_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            case handle_control_frame(Frame, State) of
                {ok, State1} ->
                    process_control_frames(Rest, State1);
                {transition, NextState, State1} ->
                    %% Signal state transition (e.g., for GOAWAY)
                    {transition, NextState, Rest, State1};
                {error, Reason} ->
                    {error, Reason}
            end;
        %% RFC 9114 Section 7.2.4: duplicate settings use H3_SETTINGS_ERROR
        {error, {frame_error, settings, {duplicate_setting, _Key}}} ->
            {error, {connection_error, ?H3_SETTINGS_ERROR, <<"duplicate setting identifier">>}};
        %% RFC 9114 Section 7.2.4.1: HTTP/2 settings forbidden in HTTP/3
        {error, {frame_error, settings, {forbidden_setting, Id}}} ->
            {error,
                {connection_error, ?H3_SETTINGS_ERROR,
                    iolist_to_binary(io_lib:format("forbidden HTTP/2 setting: 0x~.16B", [Id]))}};
        %% RFC 9114 §7.2.8: HTTP/2 reserved frame types
        {error, {h2_reserved_frame, Type}} ->
            {error,
                {connection_error, ?H3_FRAME_UNEXPECTED,
                    iolist_to_binary(io_lib:format("reserved HTTP/2 frame type: 0x~.16B", [Type]))}};
        {error, {frame_error, FrameType, Reason}} ->
            %% Other frame errors use H3_FRAME_ERROR
            {error,
                {connection_error, ?H3_FRAME_ERROR,
                    iolist_to_binary(io_lib:format("malformed ~p: ~p", [FrameType, Reason]))}};
        {more, _} ->
            {ok, Data, State}
    end.

handle_control_frame({settings, Settings}, #state{settings_received = false} = State) ->
    %% First frame on control stream must be SETTINGS.
    %% apply_peer_settings/2 signals SETTINGS violations with
    %% throw({connection_error, ...}); gen_statem treats a throw from a state
    %% callback as its return value, so let it escape and it crashes the
    %% process with bad_return_from_state_function. Convert it to a returned
    %% error that flows through handle_connection_error/2 for a clean close.
    try apply_peer_settings(Settings, State) of
        State1 ->
            {ok, State1#state{
                peer_settings = Settings,
                settings_received = true
            }}
    catch
        throw:{connection_error, _Code, _Reason} = Err ->
            {error, Err}
    end;
handle_control_frame({settings, _Settings}, #state{settings_received = true}) ->
    %% Duplicate SETTINGS frame
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"duplicate SETTINGS">>}};
handle_control_frame(_Frame, #state{settings_received = false}) ->
    %% SETTINGS must be first
    {error, {connection_error, ?H3_MISSING_SETTINGS, <<"expected SETTINGS">>}};
handle_control_frame({goaway, Id}, #state{role = Role} = State) ->
    %% RFC 9114 Section 7.2.6: GOAWAY identifier type depends on sender
    %%   server-to-client: client-initiated bidirectional stream ID (Id rem 4 =:= 0)
    %%   client-to-server: push ID (no modular constraint)
    case validate_goaway_id(Role, Id) of
        ok ->
            case State#state.goaway_id of
                undefined ->
                    State1 = cleanup_blocked_streams_on_goaway(State),
                    {transition, goaway_received, State1#state{goaway_id = Id}};
                Old when Id > Old ->
                    %% RFC 9114 Section 5.2: GOAWAY ID MUST NOT increase
                    {error, {connection_error, ?H3_ID_ERROR, <<"GOAWAY ID increased">>}};
                _ ->
                    {ok, State#state{goaway_id = Id}}
            end;
        {error, Reason} ->
            {error, {connection_error, ?H3_ID_ERROR, Reason}}
    end;
%% Server receives MAX_PUSH_ID from client (RFC 9114 Section 7.2.7)
handle_control_frame({max_push_id, PushId}, #state{role = server, max_push_id = Old} = State) when
    Old =:= undefined; PushId >= Old
->
    %% Valid MAX_PUSH_ID - enables or extends push capability
    {ok, State#state{max_push_id = PushId}};
handle_control_frame({max_push_id, PushId}, #state{role = server, max_push_id = Old}) when
    PushId < Old
->
    %% MAX_PUSH_ID cannot decrease (RFC 9114 Section 7.2.7)
    {error, {connection_error, ?H3_ID_ERROR, <<"MAX_PUSH_ID decreased">>}};
handle_control_frame({max_push_id, _}, #state{role = client}) ->
    %% Server should never send MAX_PUSH_ID (RFC 9114 Section 7.2.7)
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"server sent MAX_PUSH_ID">>}};
%% Server receives CANCEL_PUSH from client (RFC 9114 Section 7.2.3)
handle_control_frame({cancel_push, PushId}, #state{role = server} = State) ->
    handle_cancel_push_server(PushId, State);
%% Client receives CANCEL_PUSH from server (server withdrawing promise)
handle_control_frame({cancel_push, PushId}, #state{role = client} = State) ->
    handle_cancel_push_client(PushId, State);
handle_control_frame({data, _}, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"DATA on control stream">>}};
handle_control_frame({headers, _}, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"HEADERS on control stream">>}};
handle_control_frame({push_promise, _, _}, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"PUSH_PROMISE on control stream">>}};
handle_control_frame({unknown, Type, Payload}, State) ->
    %% Check for PRIORITY_UPDATE frames (RFC 9218)
    case Type of
        ?H3_FRAME_PRIORITY_UPDATE_REQUEST ->
            handle_priority_update_frame(Payload, State);
        ?H3_FRAME_PRIORITY_UPDATE_PUSH ->
            handle_priority_update_push_frame(Payload, State);
        _ ->
            %% Unknown frame types are ignored (reserved or otherwise)
            {ok, State}
    end.

handle_encoder_stream_data(
    Data,
    #state{
        encoder_buffer = Buffer,
        qpack_decoder = Decoder
    } = State
) ->
    FullData = <<Buffer/binary, Data/binary>>,
    case quic_qpack:process_encoder_instructions(FullData, Decoder) of
        {ok, Decoder1} ->
            %% All instructions processed - retry blocked streams
            State1 = State#state{qpack_decoder = Decoder1, encoder_buffer = <<>>},
            retry_blocked_streams(State1);
        {incomplete, Rest, Decoder1} ->
            %% Partial instruction, buffer remaining data
            State1 = State#state{qpack_decoder = Decoder1, encoder_buffer = Rest},
            %% Still retry blocked streams - some may have become unblocked
            retry_blocked_streams(State1);
        {error, Reason} ->
            %% RFC 9204 §6: errors decoding peer's encoder stream instructions
            %% are QPACK_ENCODER_STREAM_ERROR (0x201), not decompression-failed.
            {error, {connection_error, ?H3_QPACK_ENCODER_STREAM_ERROR, Reason}, State}
    end.

%% Retry blocked streams that may have become unblocked after encoder instructions
retry_blocked_streams(#state{blocked_streams = Blocked} = State) when map_size(Blocked) =:= 0 ->
    {ok, State};
retry_blocked_streams(
    #state{
        blocked_streams = Blocked,
        qpack_decoder = Decoder,
        quic_conn = QuicConn
    } = State
) ->
    InsertCount = quic_qpack:get_insert_count(Decoder),
    %% Find streams that can be unblocked (RIC <= InsertCount)
    {Ready, StillBlocked} = partition_blocked_streams(InsertCount, Blocked),
    State1 = State#state{blocked_streams = StillBlocked},
    %% Re-process each unblocked stream's headers
    case retry_blocked_streams_fold(maps:to_list(Ready), State1) of
        {ok, State2} ->
            {ok, State2};
        {error, {stream_reset, SId, Code}} ->
            quic:reset_stream(QuicConn, SId, Code),
            {ok, State1#state{streams = maps:remove(SId, State1#state.streams)}};
        {error, Reason} ->
            {error, Reason, State1}
    end.

%% Partition blocked streams into ready and still-blocked
partition_blocked_streams(InsertCount, Blocked) ->
    maps:fold(
        fun(StreamId, {RIC, _, _} = Val, {ReadyAcc, BlockedAcc}) ->
            case RIC =< InsertCount of
                true -> {maps:put(StreamId, Val, ReadyAcc), BlockedAcc};
                false -> {ReadyAcc, maps:put(StreamId, Val, BlockedAcc)}
            end
        end,
        {#{}, #{}},
        Blocked
    ).

retry_blocked_streams_fold([], State) ->
    {ok, State};
retry_blocked_streams_fold([{StreamId, {_RIC, HeaderBlock, Fin}} | Rest], State) ->
    %% Get stream record with proper defaults
    Stream = maps:get(
        StreamId,
        State#state.streams,
        #h3_stream{id = StreamId, type = request, state = open}
    ),
    case handle_request_frame(StreamId, {headers, HeaderBlock}, Fin, Stream, State) of
        {ok, Stream1, State1} ->
            State2 = State1#state{streams = maps:put(StreamId, Stream1, State1#state.streams)},
            retry_blocked_streams_fold(Rest, State2);
        {error, {stream_reset, _, _} = Err} ->
            %% Stream-level error - propagate to caller
            {error, Err};
        {error, Reason} ->
            %% Connection error - stop processing
            {error, Reason}
    end.

handle_decoder_stream_data(
    Data,
    #state{
        decoder_buffer = Buffer,
        qpack_encoder = Encoder
    } = State
) ->
    FullData = <<Buffer/binary, Data/binary>>,
    case quic_qpack:process_decoder_instructions(FullData, Encoder) of
        {ok, Encoder1} ->
            {ok, State#state{qpack_encoder = Encoder1, decoder_buffer = <<>>}};
        {incomplete, Rest, Encoder1} ->
            %% Partial instruction, buffer remaining data
            {ok, State#state{qpack_encoder = Encoder1, decoder_buffer = Rest}};
        {error, Reason} ->
            {error, {connection_error, ?H3_QPACK_DECODER_STREAM_ERROR, Reason}, State}
    end.

%%====================================================================
%% Internal: Push Stream Handling (RFC 9114 Section 4.6)
%%====================================================================

%% Parse push ID from push stream header (client-side)
%% Push stream format after type byte: Push ID (varint) + frames
handle_push_stream_id(StreamId, Data, #state{uni_stream_buffers = Buffers} = State) ->
    {push_pending, Buffer} = maps:get(StreamId, Buffers),
    Combined = <<Buffer/binary, Data/binary>>,
    try quic_varint:decode(Combined) of
        {PushId, Rest} ->
            process_push_stream_id(StreamId, PushId, Rest, State)
    catch
        error:badarg ->
            %% Need more data for push ID (empty binary)
            {ok, State#state{
                uni_stream_buffers = maps:put(StreamId, {push_pending, Combined}, Buffers)
            }};
        error:{incomplete, _} ->
            %% Need more data for push ID
            {ok, State#state{
                uni_stream_buffers = maps:put(StreamId, {push_pending, Combined}, Buffers)
            }}
    end.

%% Process decoded push ID from push stream
process_push_stream_id(
    StreamId,
    PushId,
    _Rest,
    #state{
        promised_pushes = Promised,
        received_pushes = Received,
        local_max_push_id = MaxPushId,
        local_cancelled_pushes = Cancelled,
        uni_stream_buffers = Buffers
    } = State
) ->
    case validate_push_stream(PushId, MaxPushId, Promised, Received, Cancelled) of
        ok ->
            correlate_push_stream(StreamId, PushId, _Rest, State);
        {error, cancelled} ->
            %% RFC 9114 Section 7.2.3: Cancelled push - silently ignore stream
            %% Just remove the buffer and continue without processing
            {ok, State#state{uni_stream_buffers = maps:remove(StreamId, Buffers)}};
        {error, Reason} ->
            {error, Reason, State}
    end.

%% Correlate push stream with PUSH_PROMISE
correlate_push_stream(
    StreamId,
    PushId,
    Rest,
    #state{
        uni_stream_buffers = Buffers,
        promised_pushes = Promised,
        received_pushes = Received,
        owner = Owner
    } = State
) ->
    case maps:find(PushId, Promised) of
        {ok, {ReqStreamId, Headers}} ->
            %% Valid push stream - register with frame state tracking
            %% Push streams must receive HEADERS first, then DATA (RFC 9114 Section 4.6)
            PushStream = #h3_stream{
                id = StreamId,
                type = push,
                state = open,
                frame_state = expecting_headers
            },
            State1 = State#state{
                uni_stream_buffers = maps:remove(StreamId, Buffers),
                received_pushes = maps:put(PushId, PushStream, Received),
                promised_pushes = maps:remove(PushId, Promised)
            },
            %% Notify owner that push stream started
            Owner ! {quic_h3, self(), {push_stream, PushId, ReqStreamId, Headers}},
            %% Process remaining data as frames
            maybe_process_push_rest(StreamId, PushId, Rest, State1);
        error ->
            %% Push stream without corresponding PUSH_PROMISE
            {error, {connection_error, ?H3_ID_ERROR, <<"push stream without PUSH_PROMISE">>}, State}
    end.

%% Process remaining data on push stream if any
maybe_process_push_rest(_StreamId, _PushId, <<>>, State) ->
    {ok, State};
maybe_process_push_rest(StreamId, PushId, Rest, State) ->
    handle_push_stream_data(StreamId, PushId, Rest, false, State).

%% Validate push stream constraints
validate_push_stream(PushId, MaxPushId, _Promised, Received, Cancelled) ->
    cond_validate([
        {PushId > MaxPushId, {connection_error, ?H3_ID_ERROR, <<"push ID exceeds MAX_PUSH_ID">>}},
        {
            maps:is_key(PushId, Received),
            {connection_error, ?H3_ID_ERROR, <<"duplicate push stream">>}
        },
        {
            sets:is_element(PushId, Cancelled),
            %% Cancelled push - ignore stream silently (already cancelled)
            cancelled
        }
    ]).

cond_validate([]) -> ok;
cond_validate([{true, cancelled} | _]) -> {error, cancelled};
cond_validate([{true, Error} | _]) -> {error, Error};
cond_validate([{false, _} | Rest]) -> cond_validate(Rest).

%% Process frames on push stream (client-side)
%% Push streams can only contain HEADERS and DATA frames
handle_push_stream_data(
    StreamId,
    PushId,
    Data,
    Fin,
    #state{stream_buffers = Buffers} = State
) ->
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,
    case process_push_frames(StreamId, PushId, Combined, Fin, State) of
        {ok, Rest, State1} ->
            Buffers1 =
                case Rest of
                    <<>> -> maps:remove(StreamId, Buffers);
                    _ -> Buffers#{StreamId => Rest}
                end,
            {ok, State1#state{stream_buffers = Buffers1}};
        {error, Reason} ->
            {error, Reason, State}
    end.

%% Process frames on push stream
process_push_frames(StreamId, PushId, Data, Fin, State) ->
    case quic_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            case handle_push_frame(StreamId, PushId, Frame, Fin andalso Rest =:= <<>>, State) of
                {ok, State1} ->
                    process_push_frames(StreamId, PushId, Rest, Fin, State1);
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, {h2_reserved_frame, Type}} ->
            {error,
                {connection_error, ?H3_FRAME_UNEXPECTED,
                    iolist_to_binary(io_lib:format("reserved HTTP/2 frame type: 0x~.16B", [Type]))}};
        {error, {frame_error, FrameType, Reason}} ->
            {error,
                {connection_error, ?H3_FRAME_ERROR,
                    iolist_to_binary(
                        io_lib:format("malformed ~p on push: ~p", [FrameType, Reason])
                    )}};
        {more, _} ->
            {ok, Data, State}
    end.

%% Handle individual frames on push stream
%% RFC 9114 Section 4.6: Push streams only carry HEADERS and DATA
%% HEADERS must come first, then DATA. Zero or more interim 1xx responses
%% may precede the final response.
handle_push_frame(
    StreamId,
    PushId,
    {headers, HeaderBlock},
    Fin,
    #state{qpack_decoder = Decoder, owner = Owner, received_pushes = Received} = State
) ->
    case maps:get(PushId, Received, undefined) of
        #h3_stream{id = StreamId, frame_state = expecting_headers} ->
            handle_push_headers(StreamId, PushId, HeaderBlock, Fin, Decoder, Owner, State);
        #h3_stream{id = StreamId, frame_state = expecting_data} = Stream ->
            %% Only trailers (HEADERS with FIN) are allowed once body has started
            case Fin of
                true ->
                    handle_push_trailers(
                        StreamId, PushId, HeaderBlock, Decoder, Owner, Stream, State
                    );
                false ->
                    {error,
                        {connection_error, ?H3_FRAME_UNEXPECTED,
                            <<"non-trailer HEADERS on push stream">>}}
            end;
        undefined ->
            %% Push stream not correlated (should not happen in normal flow)
            {error, {connection_error, ?H3_ID_ERROR, <<"unknown push stream">>}}
    end;
handle_push_frame(
    StreamId,
    PushId,
    {data, Payload},
    Fin,
    #state{owner = Owner, received_pushes = Received} = State
) ->
    case maps:get(PushId, Received, undefined) of
        #h3_stream{id = StreamId, frame_state = expecting_headers} ->
            %% DATA before HEADERS - protocol error
            {error,
                {connection_error, ?H3_FRAME_UNEXPECTED, <<"DATA before HEADERS on push stream">>}};
        #h3_stream{id = StreamId, frame_state = expecting_data} = Stream ->
            apply_push_data(StreamId, PushId, Payload, Fin, Stream, Owner, Received, State);
        undefined ->
            {error, {connection_error, ?H3_ID_ERROR, <<"unknown push stream">>}}
    end;
%% Invalid frames on push stream
handle_push_frame(_StreamId, _PushId, {settings, _}, _Fin, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"SETTINGS on push stream">>}};
handle_push_frame(_StreamId, _PushId, {goaway, _}, _Fin, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"GOAWAY on push stream">>}};
handle_push_frame(_StreamId, _PushId, {push_promise, _, _}, _Fin, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"PUSH_PROMISE on push stream">>}};
handle_push_frame(_StreamId, _PushId, {max_push_id, _}, _Fin, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"MAX_PUSH_ID on push stream">>}};
handle_push_frame(_StreamId, _PushId, {cancel_push, _}, _Fin, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"CANCEL_PUSH on push stream">>}};
handle_push_frame(_StreamId, _PushId, {unknown, _Type, _Payload}, _Fin, State) ->
    %% Unknown frame types are ignored per RFC 9114
    {ok, State}.

%% Helper to handle HEADERS frame on push stream.
%% Applies the same validation as regular response headers (size, field names,
%% pseudo-headers, request-pseudo rejection, status range) and supports
%% interim 1xx responses (RFC 9114 §4.1).
handle_push_headers(
    StreamId, PushId, HeaderBlock, Fin, Decoder, Owner, #state{received_pushes = Received} = State
) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Headers}, Decoder1} ->
            MaxSize = State#state.local_max_field_section_size,
            case calculate_field_section_size(Headers) > MaxSize of
                true ->
                    {error,
                        {connection_error, ?H3_EXCESSIVE_LOAD,
                            <<"push field section exceeds SETTINGS_MAX_FIELD_SECTION_SIZE">>}};
                false ->
                    State1 = send_section_ack(StreamId, State#state{qpack_decoder = Decoder1}),
                    validate_and_deliver_push_response(
                        StreamId, PushId, Headers, Fin, Owner, Received, State1
                    )
            end;
        {{blocked, _RIC}, _Decoder1} ->
            {error,
                {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED,
                    <<"blocked push stream headers">>}};
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end.

validate_and_deliver_push_response(StreamId, PushId, Headers, Fin, Owner, Received, State) ->
    case validate_push_response_headers(Headers) of
        {ok, Status} ->
            Owner ! {quic_h3, self(), {push_response, PushId, Status, Headers}},
            deliver_push_response_finalize(
                StreamId, PushId, Status, Headers, Fin, Owner, Received, State
            );
        {error, Reason} ->
            {error, {connection_error, ?H3_MESSAGE_ERROR, Reason}}
    end.

deliver_push_response_finalize(StreamId, PushId, _Status, _Headers, true, Owner, _Received, State) ->
    Owner ! {quic_h3, self(), {push_complete, PushId}},
    cleanup_push_stream(PushId, StreamId, State);
deliver_push_response_finalize(
    StreamId, PushId, Status, _Headers, false, _Owner, Received, State
) when
    is_integer(Status), Status >= 100, Status < 200
->
    %% Interim response - keep expecting_headers for another interim or final.
    Stream = push_stream_with_state(StreamId, Received, PushId, expecting_headers),
    Stream1 = Stream#h3_stream{status = Status},
    {ok, State#state{received_pushes = Received#{PushId => Stream1}}};
deliver_push_response_finalize(
    StreamId, PushId, Status, Headers, false, _Owner, Received, State
) ->
    Stream = push_stream_with_state(StreamId, Received, PushId, expecting_data),
    CL = extract_content_length(Headers),
    Stream1 = Stream#h3_stream{
        status = Status,
        headers = Headers,
        content_length = CL
    },
    {ok, State#state{received_pushes = Received#{PushId => Stream1}}}.

push_stream_with_state(StreamId, Received, PushId, FrameState) ->
    Existing =
        case maps:find(PushId, Received) of
            {ok, S} -> S;
            error -> #h3_stream{id = StreamId, type = push, state = open}
        end,
    Existing#h3_stream{frame_state = FrameState}.

extract_content_length(Headers) ->
    case lists:keyfind(<<"content-length">>, 1, Headers) of
        {_, Value} ->
            try binary_to_integer(Value) of
                N when N >= 0 -> N;
                _ -> undefined
            catch
                _:_ -> undefined
            end;
        false ->
            undefined
    end.

%% RFC 9114 §4.1.2: push DATA must respect content-length if advertised.
apply_push_data(StreamId, PushId, Payload, Fin, Stream, Owner, Received, State) ->
    Received0 = Received,
    Size = byte_size(Payload),
    NewReceived = Stream#h3_stream.body_received + Size,
    CL = Stream#h3_stream.content_length,
    case cl_data_check(CL, NewReceived, Fin) of
        ok ->
            Owner ! {quic_h3, self(), {push_data, PushId, Payload, Fin}},
            Stream1 = Stream#h3_stream{body_received = NewReceived},
            case Fin of
                true ->
                    Owner ! {quic_h3, self(), {push_complete, PushId}},
                    cleanup_push_stream(PushId, StreamId, State);
                false ->
                    {ok, State#state{received_pushes = Received0#{PushId => Stream1}}}
            end;
        {error, Code} ->
            {error, {connection_error, Code, <<"push content-length violated">>}}
    end.

cl_data_check(undefined, _Received, _Fin) ->
    ok;
cl_data_check(CL, Received, _Fin) when Received > CL ->
    {error, ?H3_MESSAGE_ERROR};
cl_data_check(CL, Received, true) when Received < CL ->
    {error, ?H3_MESSAGE_ERROR};
cl_data_check(_, _, _) ->
    ok.

%% Handle trailers on a push stream. Applies the same validation as regular
%% stream trailers (§4.1.2): no pseudo-headers, no forbidden connection-
%% specific fields, Content-Length matches response headers, body size
%% agrees with advertised content-length.
handle_push_trailers(StreamId, PushId, HeaderBlock, Decoder, Owner, Stream, State) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Trailers}, Decoder1} ->
            State1 = send_section_ack(StreamId, State#state{qpack_decoder = Decoder1}),
            try
                validate_field_names_and_values(Trailers),
                case validate_trailer_headers(Trailers, Stream) of
                    ok -> ok;
                    {error, Reason} -> throw({trailer_error, Reason})
                end,
                case
                    cl_data_check(
                        Stream#h3_stream.content_length,
                        Stream#h3_stream.body_received,
                        true
                    )
                of
                    ok ->
                        Owner ! {quic_h3, self(), {push_trailers, PushId, Trailers}},
                        Owner ! {quic_h3, self(), {push_complete, PushId}},
                        cleanup_push_stream(PushId, StreamId, State1);
                    {error, Code} ->
                        {error,
                            {connection_error, Code, <<"push body length mismatch at trailers">>}}
                end
            catch
                throw:{header_error, _} ->
                    {error, {connection_error, ?H3_MESSAGE_ERROR, <<"malformed push trailers">>}};
                throw:{trailer_error, _} ->
                    {error, {connection_error, ?H3_MESSAGE_ERROR, <<"invalid push trailer">>}}
            end;
        {{blocked, _RIC}, _Decoder1} ->
            {error,
                {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, <<"blocked push trailers">>}};
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end.

%% Validate push response headers (RFC 9114 §4.6 + §4.2).
%% Applies the same malformed-message rules as regular responses.
validate_push_response_headers(Headers) ->
    try
        validate_field_names_and_values(Headers),
        check_duplicate_headers(Headers),
        case proplists:get_value(<<":status">>, Headers) of
            undefined ->
                {error, <<"missing :status in push response">>};
            StatusBin ->
                validate_push_response_status(StatusBin, Headers)
        end
    catch
        throw:{header_error, {invalid_field, _, _}} ->
            {error, <<"malformed push response header">>};
        throw:{header_error, _} ->
            {error, <<"invalid push response header">>}
    end.

validate_push_response_status(StatusBin, Headers) ->
    try binary_to_integer(StatusBin) of
        Status when Status >= 100, Status < 600 ->
            case has_request_pseudo_headers(Headers) of
                true -> {error, <<"request pseudo-header in push response">>};
                false -> {ok, Status}
            end;
        _ ->
            {error, <<"invalid :status value">>}
    catch
        _:_ -> {error, <<"invalid :status value">>}
    end.

%% Check if headers contain request pseudo-headers (forbidden in responses)
has_request_pseudo_headers(Headers) ->
    lists:any(
        fun({K, _}) ->
            K =:= <<":method">> orelse K =:= <<":path">> orelse
                K =:= <<":scheme">> orelse K =:= <<":authority">>
        end,
        Headers
    ).

%% Clean up push stream state after completion (client-side)
%% Also cleans local_cancelled_pushes to prevent unbounded set growth
cleanup_push_stream(
    PushId,
    StreamId,
    #state{
        received_pushes = Received,
        stream_buffers = Buffers,
        local_cancelled_pushes = LocalCancelled
    } = State
) ->
    {ok, State#state{
        received_pushes = maps:remove(PushId, Received),
        stream_buffers = maps:remove(StreamId, Buffers),
        local_cancelled_pushes = sets:del_element(PushId, LocalCancelled)
    }}.

%% Handle CANCEL_PUSH from client (server-side)
%% Client is cancelling a push they don't want
handle_cancel_push_server(
    PushId,
    #state{
        max_push_id = MaxPushId,
        next_push_id = NextPushId,
        push_streams = PushStreams,
        cancelled_pushes = Cancelled,
        quic_conn = QuicConn
    } = State
) ->
    %% Validate push ID (RFC 9114 Section 7.2.3)
    case PushId > MaxPushId orelse (MaxPushId =:= undefined) of
        true ->
            %% Invalid - push ID exceeds what we could use
            {error, {connection_error, ?H3_ID_ERROR, <<"invalid CANCEL_PUSH ID">>}};
        false ->
            %% Check if push stream already exists
            case maps:find(PushId, PushStreams) of
                {ok, {StreamId, _Stream}} ->
                    %% Push stream active - reset it
                    quic:reset_stream(QuicConn, StreamId, ?H3_REQUEST_CANCELLED),
                    {ok, State#state{
                        push_streams = maps:remove(PushId, PushStreams),
                        cancelled_pushes = sets:add_element(PushId, Cancelled)
                    }};
                error when PushId < NextPushId ->
                    %% Push ID already used but stream closed - ignore
                    {ok, State#state{
                        cancelled_pushes = sets:add_element(PushId, Cancelled)
                    }};
                error ->
                    %% Push ID not yet used - remember to skip it
                    {ok, State#state{
                        cancelled_pushes = sets:add_element(PushId, Cancelled)
                    }}
            end
    end.

%% Handle CANCEL_PUSH from server (client-side)
%% Server is withdrawing a push promise
handle_cancel_push_client(
    PushId,
    #state{
        local_max_push_id = MaxPushId,
        promised_pushes = Promised,
        received_pushes = Received,
        owner = Owner
    } = State
) ->
    %% Validate push ID
    case MaxPushId =:= undefined orelse PushId > MaxPushId of
        true ->
            %% Invalid push ID
            {error, {connection_error, ?H3_ID_ERROR, <<"invalid CANCEL_PUSH ID">>}};
        false ->
            %% Remove from promised and received, notify owner
            State1 = State#state{
                promised_pushes = maps:remove(PushId, Promised),
                received_pushes = maps:remove(PushId, Received)
            },
            Owner ! {quic_h3, self(), {push_cancelled, PushId}},
            {ok, State1}
    end.

handle_request_stream_data(
    StreamId,
    Data,
    Fin,
    #state{streams = Streams, stream_buffers = Buffers} = State
) ->
    Stream = maps:get(StreamId, Streams, #h3_stream{id = StreamId, type = request, state = open}),
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,

    case process_request_frames(StreamId, Combined, Fin, Stream, State) of
        {ok, Rest, _Stream1, _State1} when Fin, Rest =/= <<>> ->
            %% Stream ended inside an H3 frame: truncated (RFC 9114 §7.1).
            {error, {connection_error, ?H3_FRAME_ERROR, <<"stream ended mid-frame">>}};
        {ok, Rest, Stream1, State1} ->
            %% RFC 9114 §4.1: the message ends when the stream ends, not at
            %% a frame boundary. A peer that sends its FIN in a bare final
            %% QUIC frame (quic-go does) otherwise leaves the application
            %% waiting for a fin-marked delivery that never comes.
            {Stream2, State2} =
                case Fin of
                    true -> finish_request_stream(StreamId, Stream1, State1);
                    false -> {Stream1, State1}
                end,
            Buffers1 =
                case Rest of
                    <<>> -> maps:remove(StreamId, Buffers);
                    _ -> Buffers#{StreamId => Rest}
                end,
            Streams1 = Streams#{StreamId => Stream2},
            {ok, State2#state{streams = Streams1, stream_buffers = Buffers1}};
        {error, Reason} ->
            {error, Reason, State}
    end.

%% The stream's FIN arrived after the last complete frame. If the body
%% was already closed by a fin-marked frame delivery this is a no-op;
%% an open body gets its final empty fin-marked delivery here.
finish_request_stream(
    StreamId, #h3_stream{frame_state = expecting_data} = Stream, State
) ->
    State1 = notify_stream_data(StreamId, <<>>, true, State),
    {Stream#h3_stream{frame_state = complete, state = half_closed_remote}, State1};
finish_request_stream(_StreamId, Stream, State) ->
    {Stream, State}.

process_request_frames(StreamId, Data, Fin, Stream, #state{quic_conn = QuicConn} = State) ->
    case quic_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            case handle_request_frame(StreamId, Frame, Fin andalso Rest =:= <<>>, Stream, State) of
                {ok, Stream1, State1} ->
                    process_request_frames(StreamId, Rest, Fin, Stream1, State1);
                {error, {stream_reset, SId, Code}} ->
                    %% Stream-level error - reset the stream and remove from tracking
                    quic:reset_stream(QuicConn, SId, Code),
                    {ok, <<>>, Stream, State#state{streams = maps:remove(SId, State#state.streams)}};
                {error, Reason} ->
                    {error, Reason}
            end;
        %% RFC 9114 Section 7.2.4: duplicate settings use H3_SETTINGS_ERROR
        {error, {frame_error, settings, {duplicate_setting, _Key}}} ->
            {error, {connection_error, ?H3_SETTINGS_ERROR, <<"duplicate setting identifier">>}};
        %% RFC 9114 Section 7.2.4.1: HTTP/2 settings forbidden in HTTP/3
        {error, {frame_error, settings, {forbidden_setting, Id}}} ->
            {error,
                {connection_error, ?H3_SETTINGS_ERROR,
                    iolist_to_binary(io_lib:format("forbidden HTTP/2 setting: 0x~.16B", [Id]))}};
        %% RFC 9114 §7.2.8: HTTP/2 reserved frame types
        {error, {h2_reserved_frame, Type}} ->
            {error,
                {connection_error, ?H3_FRAME_UNEXPECTED,
                    iolist_to_binary(io_lib:format("reserved HTTP/2 frame type: 0x~.16B", [Type]))}};
        {error, {frame_error, FrameType, Reason}} ->
            %% Other frame errors use H3_FRAME_ERROR
            {error,
                {connection_error, ?H3_FRAME_ERROR,
                    iolist_to_binary(io_lib:format("malformed ~p: ~p", [FrameType, Reason]))}};
        {more, _} ->
            {ok, Data, Stream, State}
    end.

handle_request_frame(
    StreamId,
    {headers, HeaderBlock},
    Fin,
    #h3_stream{frame_state = expecting_headers} = Stream,
    #state{
        qpack_decoder = Decoder,
        owner = Owner,
        role = Role
    } = State
) ->
    %% Size check moved to after QPACK decode (RFC 9114 Section 4.2.2 checks decoded size)
    handle_headers_decode(StreamId, HeaderBlock, Fin, Stream, Decoder, Owner, Role, State);
%% DATA before HEADERS - stream error (RFC 9114 Section 4.1)
handle_request_frame(
    StreamId,
    {data, _Payload},
    _Fin,
    #h3_stream{frame_state = expecting_headers},
    _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% DATA frame - validate content-length if present (RFC 9114 Section 4.1.2)
handle_request_frame(
    StreamId,
    {data, Payload},
    Fin,
    #h3_stream{frame_state = expecting_data, content_length = CL, body_received = Received} =
        Stream,
    State
) when CL =/= undefined ->
    NewReceived = Received + byte_size(Payload),
    case NewReceived > CL of
        true ->
            %% Body exceeds content-length - stream error
            {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}};
        false when Fin, NewReceived < CL ->
            %% Body shorter than content-length - stream error
            {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}};
        false ->
            Stream1 = Stream#h3_stream{
                body_received = NewReceived
            },
            State1 = notify_stream_data(StreamId, Payload, Fin, State),
            Stream2 =
                case Fin of
                    true -> Stream1#h3_stream{frame_state = complete, state = half_closed_remote};
                    false -> Stream1
                end,
            {ok, Stream2, State1}
    end;
%% DATA frame - no content-length
handle_request_frame(
    StreamId,
    {data, Payload},
    _Fin,
    #h3_stream{frame_state = expecting_data} = Stream,
    _State
) when (Stream#h3_stream.body_received + byte_size(Payload)) > ?H3_MAX_BUFFERED_BODY ->
    %% Without Content-Length, cap the total received body bytes so a peer
    %% cannot keep an unbounded application stream open indefinitely.
    {error, {stream_reset, StreamId, ?H3_EXCESSIVE_LOAD}};
handle_request_frame(
    StreamId,
    {data, Payload},
    Fin,
    #h3_stream{frame_state = expecting_data} = Stream,
    State
) ->
    Stream1 = Stream#h3_stream{
        body_received = Stream#h3_stream.body_received + byte_size(Payload)
    },
    State1 = notify_stream_data(StreamId, Payload, Fin, State),
    Stream2 =
        case Fin of
            true -> Stream1#h3_stream{frame_state = complete, state = half_closed_remote};
            false -> Stream1
        end,
    {ok, Stream2, State1};
%% RFC 9114 §4.4: once a CONNECT tunnel is established, only DATA frames are
%% allowed on the stream. Reject any HEADERS (including trailers) or
%% PUSH_PROMISE frames.
handle_request_frame(
    StreamId,
    {headers, _HeaderBlock},
    _Fin,
    #h3_stream{frame_state = expecting_data, is_connect = true},
    _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
handle_request_frame(
    StreamId,
    {push_promise, _, _},
    _Fin,
    #h3_stream{is_connect = true},
    _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% Non-trailer HEADERS after body started - stream error (RFC 9114 Section 4.1)
handle_request_frame(
    StreamId,
    {headers, _HeaderBlock},
    false,
    #h3_stream{frame_state = expecting_data},
    _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% Trailers (HEADERS with FIN after expecting_data)
handle_request_frame(
    StreamId,
    {headers, HeaderBlock},
    true,
    #h3_stream{frame_state = expecting_data} = Stream,
    #state{qpack_decoder = Decoder, owner = Owner} = State
) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Trailers}, Decoder1} ->
            %% RFC 9114 Section 4.1.2: validate trailers
            case validate_trailer_headers(Trailers, Stream) of
                ok ->
                    %% Send Section Acknowledgment for trailers
                    State1 = send_section_ack(StreamId, State#state{qpack_decoder = Decoder1}),
                    Stream1 = Stream#h3_stream{
                        trailers = Trailers,
                        frame_state = complete,
                        state = half_closed_remote
                    },
                    Owner ! {quic_h3, self(), {trailers, StreamId, Trailers}},
                    {ok, Stream1, State1};
                {error, _Reason} ->
                    {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}}
            end;
        {{blocked, RIC}, Decoder1} ->
            %% Trailers blocked - buffer them
            BlockedStreams = maps:put(
                StreamId, {RIC, HeaderBlock, true}, State#state.blocked_streams
            ),
            {ok, Stream, State#state{blocked_streams = BlockedStreams, qpack_decoder = Decoder1}};
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end;
handle_request_frame(_StreamId, {settings, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"SETTINGS on request stream">>}};
handle_request_frame(_StreamId, {goaway, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"GOAWAY on request stream">>}};
handle_request_frame(_StreamId, {max_push_id, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"MAX_PUSH_ID on request stream">>}};
handle_request_frame(_StreamId, {cancel_push, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"CANCEL_PUSH on request stream">>}};
handle_request_frame(_StreamId, {unknown, _Type, _Payload}, _Fin, Stream, State) ->
    %% Skip unknown frame types per RFC 9114 Section 7.2.8
    {ok, Stream, State};
%% After complete state, no more frames allowed except unknown (handled above)
handle_request_frame(StreamId, _Frame, _Fin, #h3_stream{frame_state = complete}, _State) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% DATA after we've received everything (expecting_trailers means we already got trailers or fin)
handle_request_frame(
    StreamId, {data, _}, _Fin, #h3_stream{frame_state = expecting_trailers}, _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% Client receives PUSH_PROMISE on request stream - process it (RFC 9114 Section 7.2.5)
handle_request_frame(
    StreamId,
    {push_promise, PushId, HeaderBlock},
    _Fin,
    Stream,
    #state{role = client} = State
) ->
    handle_push_promise(StreamId, PushId, HeaderBlock, Stream, State);
%% Server should NEVER receive PUSH_PROMISE on request stream - error
handle_request_frame(_StreamId, {push_promise, _, _}, _Fin, _Stream, #state{role = server}) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"PUSH_PROMISE on request stream">>}};
%% Any other unexpected frame/state combination
handle_request_frame(StreamId, _Frame, _Fin, _Stream, _State) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}}.

%% Handle PUSH_PROMISE on request stream (client-side, RFC 9114 Section 7.2.5)
handle_push_promise(
    StreamId,
    PushId,
    HeaderBlock,
    Stream,
    #state{
        local_max_push_id = MaxPushId,
        promised_pushes = Promised,
        local_cancelled_pushes = Cancelled,
        qpack_decoder = Decoder,
        owner = Owner
    } = State
) ->
    %% Validate push ID bounds (duplicate handling happens after QPACK decode,
    %% since it requires the decompressed headers to compare).
    case validate_push_promise_id(PushId, MaxPushId) of
        ok ->
            decode_push_promise_headers(
                StreamId, PushId, HeaderBlock, Stream, Cancelled, Decoder, Owner, Promised, State
            );
        {error, Reason} ->
            {error, Reason}
    end.

decode_push_promise_headers(
    StreamId, PushId, HeaderBlock, Stream, Cancelled, Decoder, Owner, Promised, State
) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Headers}, Decoder1} ->
            MaxSize = State#state.local_max_field_section_size,
            case calculate_field_section_size(Headers) > MaxSize of
                true ->
                    {error,
                        {connection_error, ?H3_EXCESSIVE_LOAD,
                            <<"PUSH_PROMISE field section exceeds limit">>}};
                false ->
                    State1 = send_section_ack(StreamId, State#state{qpack_decoder = Decoder1}),
                    validate_and_apply_push_promise(
                        StreamId, PushId, Stream, Headers, Cancelled, Owner, Promised, State1
                    )
            end;
        {{blocked, _RIC}, _Decoder1} ->
            {error,
                {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED,
                    <<"blocked PUSH_PROMISE headers">>}};
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end.

validate_and_apply_push_promise(
    StreamId, PushId, Stream, Headers, Cancelled, Owner, Promised, State
) ->
    case validate_promised_request_headers(Headers, State) of
        ok ->
            apply_push_promise(
                StreamId, PushId, Stream, Headers, Cancelled, Owner, Promised, State
            );
        {error, Reason} ->
            {error, {connection_error, ?H3_MESSAGE_ERROR, Reason}}
    end.

%% RFC 9114 §7.2.5 + §4.2 + §4.3.1: promised request headers MUST be a
%% well-formed request field section.
-spec validate_promised_request_headers([{binary(), binary()}], #state{}) ->
    ok | {error, binary()}.
validate_promised_request_headers(Headers, State) ->
    try
        validate_field_names_and_values(Headers),
        check_duplicate_headers(Headers),
        case cacheable_promised_method(Headers) of
            ok -> ok;
            {error, _} -> throw({header_error, non_cacheable_method})
        end,
        Template = #h3_stream{id = 0, type = request, state = open, headers = Headers},
        Stream = do_update_stream_with_headers(Headers, Template, false),
        validate_request_headers(Stream, State),
        ok
    catch
        throw:{header_error, _} ->
            {error, <<"malformed PUSH_PROMISE headers">>}
    end.

apply_push_promise(StreamId, PushId, Stream, Headers, Cancelled, Owner, Promised, State) ->
    case validate_push_promise_duplicate(PushId, Headers, Promised) of
        ok ->
            store_push_promise(
                StreamId, PushId, Stream, Headers, Cancelled, Owner, Promised, State
            );
        duplicate_ok ->
            %% RFC 9114 §7.2.5: repeat with identical headers is allowed
            {ok, Stream, State};
        {error, Reason} ->
            {error, Reason}
    end.

store_push_promise(StreamId, PushId, Stream, Headers, Cancelled, Owner, Promised, State) ->
    State1 = bump_last_accepted_push_id(PushId, State),
    case sets:is_element(PushId, Cancelled) of
        true ->
            {ok, Stream, State1};
        false ->
            Promised1 = maps:put(PushId, {StreamId, Headers}, Promised),
            Owner ! {quic_h3, self(), {push_promise, PushId, StreamId, Headers}},
            {ok, Stream, State1#state{promised_pushes = Promised1}}
    end.

%% Maintain a monotonic watermark of the highest validated push ID so
%% client-sent GOAWAY does not under-report after promises drain.
bump_last_accepted_push_id(PushId, #state{last_accepted_push_id = undefined} = State) ->
    State#state{last_accepted_push_id = PushId};
bump_last_accepted_push_id(PushId, #state{last_accepted_push_id = Current} = State) when
    PushId > Current
->
    State#state{last_accepted_push_id = PushId};
bump_last_accepted_push_id(_PushId, State) ->
    State.

%% Validate PUSH_PROMISE push-ID bounds (RFC 9114 Section 7.2.5)
validate_push_promise_id(_PushId, MaxPushId) when MaxPushId =:= undefined ->
    {error, {connection_error, ?H3_ID_ERROR, <<"PUSH_PROMISE without MAX_PUSH_ID">>}};
validate_push_promise_id(PushId, MaxPushId) when PushId > MaxPushId ->
    {error, {connection_error, ?H3_ID_ERROR, <<"push ID exceeds MAX_PUSH_ID">>}};
validate_push_promise_id(_PushId, _MaxPushId) ->
    ok.

%% RFC 9114 Section 7.2.5: same push ID may be promised on multiple request
%% streams only if the decompressed headers are identical. Mismatched repeat
%% promises MUST be treated as H3_GENERAL_PROTOCOL_ERROR.
validate_push_promise_duplicate(PushId, Headers, Promised) ->
    case maps:find(PushId, Promised) of
        error ->
            ok;
        {ok, {_StreamId, Headers}} ->
            duplicate_ok;
        {ok, {_StreamId, _Other}} ->
            {error,
                {connection_error, ?H3_GENERAL_PROTOCOL_ERROR,
                    <<"PUSH_PROMISE headers mismatch for repeated push ID">>}}
    end.

%% Decode and process headers
handle_headers_decode(StreamId, HeaderBlock, Fin, Stream, Decoder, Owner, Role, State) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Headers}, Decoder1} ->
            %% RFC 9114 Section 4.2.2: Check decoded field section size
            %% Use LOCAL setting - we enforce our own limit on inbound headers
            DecodedSize = calculate_field_section_size(Headers),
            MaxSize = State#state.local_max_field_section_size,
            case DecodedSize > MaxSize of
                true ->
                    {error,
                        {connection_error, ?H3_EXCESSIVE_LOAD,
                            <<"field section exceeds SETTINGS_MAX_FIELD_SECTION_SIZE">>}};
                false ->
                    State1 = State#state{qpack_decoder = Decoder1},
                    process_decoded_headers(StreamId, Headers, Fin, Stream, Owner, Role, State1)
            end;
        {{blocked, RIC}, Decoder1} ->
            %% Stream blocked waiting for encoder instructions (RFC 9204 Section 2.2.2)
            %% Check blocked streams limit (RFC 9204 Section 2.1.2)
            %% Use LOCAL setting - we enforce our own decoder's blocked stream limit
            BlockedCount = map_size(State#state.blocked_streams),
            MaxBlocked = State#state.local_max_blocked_streams,
            case BlockedCount >= MaxBlocked of
                true ->
                    %% RFC 9204 §2.1.2: if MaxBlocked is 0 the peer's encoder
                    %% must not produce blocking references at all; any blocked
                    %% stream here violates the advertised limit.
                    {error, {stream_reset, StreamId, ?H3_REQUEST_REJECTED}};
                false ->
                    BlockedStreams = maps:put(
                        StreamId, {RIC, HeaderBlock, Fin}, State#state.blocked_streams
                    ),
                    {ok, Stream, State#state{
                        blocked_streams = BlockedStreams, qpack_decoder = Decoder1
                    }}
            end;
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end.

%% Process successfully decoded headers
process_decoded_headers(StreamId, Headers, Fin, Stream, Owner, Role, State) ->
    %% Send Section Acknowledgment on decoder stream (RFC 9204 Section 4.4)
    State1 = send_section_ack(StreamId, State),
    case update_stream_with_headers(Headers, Stream, Role, State1) of
        {ok, Stream1} ->
            %% Apply RFC 9218 priority to underlying QUIC stream
            apply_stream_priority(StreamId, Stream1, State1),
            Stream2 = finalize_stream_state(Stream1, Fin, Role),
            notify_headers_received(StreamId, Headers, Stream2, Owner, Role),
            {ok, Stream2, State1};
        {error, {invalid_field, _Field, _Value}} ->
            %% Malformed header field - stream reset (RFC 9114 Section 4.1.2)
            {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}};
        {error, _Reason} ->
            %% Other header validation error - stream reset
            {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}}
    end.

%% RFC 9114 §4.1: the client may receive zero or more interim 1xx responses
%% before a single final response. Interim responses leave the stream in
%% expecting_headers so subsequent HEADERS frames are accepted as either
%% another interim or the final response.
finalize_stream_state(Stream, true, _Role) ->
    Stream#h3_stream{frame_state = complete, state = half_closed_remote};
finalize_stream_state(#h3_stream{status = Status} = Stream, false, client) when
    is_integer(Status), Status >= 100, Status < 200
->
    Stream#h3_stream{frame_state = expecting_headers};
finalize_stream_state(Stream, false, _Role) ->
    Stream#h3_stream{frame_state = expecting_data}.

%% Notify owner and invoke handler for received headers
notify_headers_received(StreamId, Headers, Stream, Owner, server) ->
    Method = Stream#h3_stream.method,
    Path = Stream#h3_stream.path,
    Owner ! {quic_h3, self(), {request, StreamId, Method, Path, Headers}},
    invoke_handler(self(), StreamId, Method, Path, Headers);
notify_headers_received(StreamId, Headers, Stream, Owner, client) ->
    Status = Stream#h3_stream.status,
    Owner ! {quic_h3, self(), {response, StreamId, Status, Headers}},
    %% RFC 9114: if the peer half-closed the stream with the HEADERS frame
    %% (HEAD, 204, 304, or any response without a body) deliver an empty
    %% final DATA event so callers see end-of-stream.
    case Stream#h3_stream.frame_state of
        complete ->
            Owner ! {quic_h3, self(), {data, StreamId, <<>>, true}};
        _ ->
            ok
    end.

%% Update stream with headers, validating pseudo-headers and parsing values safely
%% Returns {ok, Stream} | {error, Reason}
update_stream_with_headers(Headers, Stream, Role, State) ->
    try
        %% RFC 9114 Section 4.2: validate field names/values for malformed messages
        validate_field_names_and_values(Headers),
        %% RFC 9110 Section 5.3: only pseudo-headers must be unique
        check_duplicate_headers(Headers),
        Stream1 = do_update_stream_with_headers(
            Headers, Stream#h3_stream{headers = Headers}, false
        ),
        %% Validate pseudo-headers based on role
        case Role of
            server -> validate_request_headers(Stream1, State);
            client -> validate_response_headers(Stream1, Headers)
        end,
        {ok, Stream1}
    catch
        throw:{header_error, Reason} -> {error, Reason}
    end.

%% RFC 9114 Section 4.2 / RFC 9110 Section 5.1: validate field names and values.
%% Detect uppercase names, invalid characters, and reject connection-specific
%% fields that are disallowed in HTTP/3.
validate_field_names_and_values(Headers) ->
    lists:foreach(fun validate_field/1, Headers).

validate_field({Name, Value}) ->
    validate_field_name(Name),
    validate_field_value(Name, Value),
    validate_forbidden_field(Name, Value).

%% Field names: must be lowercase tchar (RFC 9114 §4.2, RFC 7230 §3.2.6).
%% Pseudo-headers (leading ":") use the same char class after the colon.
validate_field_name(<<>>) ->
    throw({header_error, {invalid_field, <<>>, <<>>}});
validate_field_name(<<$:, Rest/binary>>) ->
    validate_field_name_chars(Rest, <<":", Rest/binary>>);
validate_field_name(Name) ->
    validate_field_name_chars(Name, Name).

%% The char class is inlined as clause guards so each byte is a single
%% (tail-recursive) call rather than a call plus a separate predicate;
%% the common lowercase-letter case matches the first guard immediately.
%% tchar per RFC 7230 §3.2.6, restricted to lowercase letters.
validate_field_name_chars(<<>>, Full) ->
    %% empty after ":" is invalid
    case Full of
        <<":">> -> throw({header_error, {invalid_field, Full, <<>>}});
        _ -> ok
    end;
validate_field_name_chars(<<C, Rest/binary>>, Full) when C >= $a, C =< $z ->
    validate_field_name_chars(Rest, Full);
validate_field_name_chars(<<C, Rest/binary>>, Full) when C >= $0, C =< $9 ->
    validate_field_name_chars(Rest, Full);
validate_field_name_chars(<<C, Rest/binary>>, Full) when
    C =:= $!;
    C =:= $#;
    C =:= $$;
    C =:= $%;
    C =:= $&;
    C =:= $';
    C =:= $*;
    C =:= $+;
    C =:= $-;
    C =:= $.;
    C =:= $^;
    C =:= $_;
    C =:= $`;
    C =:= $|;
    C =:= $~
->
    validate_field_name_chars(Rest, Full);
validate_field_name_chars(<<_, _/binary>>, Full) ->
    throw({header_error, {invalid_field, Full, <<>>}}).

%% Field values: VCHAR / SP / HTAB / obs-text, no leading/trailing whitespace,
%% no CR/LF/NUL (RFC 9110 §5.5).
validate_field_value(Name, Value) ->
    case Value of
        <<>> ->
            ok;
        <<C, _/binary>> when C =:= $\s; C =:= $\t ->
            throw({header_error, {invalid_field, Name, Value}});
        _ ->
            Last = binary:last(Value),
            case Last of
                $\s -> throw({header_error, {invalid_field, Name, Value}});
                $\t -> throw({header_error, {invalid_field, Name, Value}});
                _ -> ok
            end,
            validate_field_value_chars(Value, Name)
    end.

%% Char class inlined as clause guards (see validate_field_name_chars/2).
validate_field_value_chars(<<>>, _Name) ->
    ok;
validate_field_value_chars(<<C, Rest/binary>>, Name) when C >= 16#21, C =< 16#7E ->
    validate_field_value_chars(Rest, Name);
validate_field_value_chars(<<C, Rest/binary>>, Name) when C >= 16#80, C =< 16#FF ->
    validate_field_value_chars(Rest, Name);
validate_field_value_chars(<<C, Rest/binary>>, Name) when C =:= $\s; C =:= $\t ->
    validate_field_value_chars(Rest, Name);
validate_field_value_chars(<<C, _/binary>>, Name) ->
    throw({header_error, {invalid_field, Name, <<C>>}}).

%% RFC 9114 §4.2: connection-specific fields MUST NOT appear in HTTP/3.
%% te is allowed only with value "trailers".
validate_forbidden_field(<<"connection">>, _) ->
    throw({header_error, {invalid_field, <<"connection">>, <<>>}});
validate_forbidden_field(<<"keep-alive">>, _) ->
    throw({header_error, {invalid_field, <<"keep-alive">>, <<>>}});
validate_forbidden_field(<<"proxy-connection">>, _) ->
    throw({header_error, {invalid_field, <<"proxy-connection">>, <<>>}});
validate_forbidden_field(<<"upgrade">>, _) ->
    throw({header_error, {invalid_field, <<"upgrade">>, <<>>}});
validate_forbidden_field(<<"transfer-encoding">>, _) ->
    throw({header_error, {invalid_field, <<"transfer-encoding">>, <<>>}});
validate_forbidden_field(<<"te">>, Value) when Value =/= <<"trailers">> ->
    throw({header_error, {invalid_field, <<"te">>, Value}});
validate_forbidden_field(_, _) ->
    ok.

%% RFC 9114 §4.3: pseudo-headers MUST NOT be duplicated. Regular fields MAY
%% repeat (per RFC 9110 §5.2-§5.3, list-based fields are legal to combine).
check_duplicate_headers(Headers) ->
    check_duplicate_headers(Headers, #{}).

check_duplicate_headers([], _Seen) ->
    ok;
check_duplicate_headers([{<<$:, _/binary>> = Name, _Value} | Rest], Seen) ->
    case maps:is_key(Name, Seen) of
        true -> throw({header_error, {duplicate_header, Name}});
        false -> check_duplicate_headers(Rest, Seen#{Name => true})
    end;
check_duplicate_headers([{_Name, _Value} | Rest], Seen) ->
    check_duplicate_headers(Rest, Seen).

%% SeenRegular tracks whether we've seen non-pseudo headers (for ordering check)
do_update_stream_with_headers([], Stream, _SeenRegular) ->
    Stream;
%% Pseudo-header after regular header - RFC 9114 Section 4.3
do_update_stream_with_headers([{<<$:, _/binary>>, _} | _], _Stream, true) ->
    throw({header_error, pseudo_header_after_regular});
do_update_stream_with_headers([{<<":method">>, Value} | Rest], Stream, _SeenRegular) ->
    IsConnect = (Value =:= <<"CONNECT">>),
    do_update_stream_with_headers(
        Rest, Stream#h3_stream{method = Value, is_connect = IsConnect}, false
    );
do_update_stream_with_headers([{<<":path">>, Value} | Rest], Stream, _SeenRegular) ->
    do_update_stream_with_headers(Rest, Stream#h3_stream{path = Value}, false);
do_update_stream_with_headers([{<<":scheme">>, Value} | Rest], Stream, _SeenRegular) ->
    do_update_stream_with_headers(Rest, Stream#h3_stream{scheme = Value}, false);
do_update_stream_with_headers([{<<":authority">>, Value} | Rest], Stream, _SeenRegular) ->
    do_update_stream_with_headers(Rest, Stream#h3_stream{authority = Value}, false);
do_update_stream_with_headers([{<<":protocol">>, Value} | Rest], Stream, _SeenRegular) ->
    do_update_stream_with_headers(Rest, Stream#h3_stream{protocol = Value}, false);
do_update_stream_with_headers([{<<":status">>, Value} | Rest], Stream, _SeenRegular) ->
    Status = safe_binary_to_integer(Value, <<":status">>),
    do_update_stream_with_headers(Rest, Stream#h3_stream{status = Status}, false);
do_update_stream_with_headers([{<<"content-length">>, Value} | Rest], Stream, _SeenRegular) ->
    CL = safe_binary_to_integer(Value, <<"content-length">>),
    case Stream#h3_stream.content_length of
        undefined ->
            do_update_stream_with_headers(Rest, Stream#h3_stream{content_length = CL}, true);
        CL ->
            %% RFC 9110 §8.6: multiple Content-Length fields are allowed only
            %% when all values are identical; otherwise the message is invalid.
            do_update_stream_with_headers(Rest, Stream, true);
        _Other ->
            throw({header_error, {invalid_field, <<"content-length">>, Value}})
    end;
do_update_stream_with_headers([{<<"priority">>, Value} | Rest], Stream, _SeenRegular) ->
    %% RFC 9218 Extensible Priorities: parse "u=N, i" format
    {Urgency, Incremental} = parse_priority_header(Value),
    do_update_stream_with_headers(
        Rest, Stream#h3_stream{urgency = Urgency, incremental = Incremental}, true
    );
%% RFC 9114 §4.3: any pseudo-header other than the ones defined above is
%% undefined and makes the message malformed. (A known pseudo-header after
%% a regular field is already rejected above.)
do_update_stream_with_headers([{<<$:, _/binary>> = Name, _} | _], _Stream, _SeenRegular) ->
    throw({header_error, {invalid_pseudo_header, Name}});
do_update_stream_with_headers([_ | Rest], Stream, _SeenRegular) ->
    do_update_stream_with_headers(Rest, Stream, true).

%% Validate request pseudo-headers (server receiving requests - RFC 9114 Section 4.3.1)
%% RFC 9114 §4.3.1: request MUST NOT contain response pseudo-headers (e.g. :status).
validate_request_headers(#h3_stream{status = Status}, _State) when Status =/= undefined ->
    throw({header_error, {prohibited_pseudo_header, <<":status">>}});
validate_request_headers(#h3_stream{method = undefined}, _State) ->
    throw({header_error, {missing_pseudo_header, <<":method">>}});
%% RFC 9220 extended CONNECT: :method=CONNECT + :protocol requires
%% local SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (we are the receiver) and
%% includes :scheme/:path/:authority (the opposite of plain CONNECT).
validate_request_headers(
    #h3_stream{method = <<"CONNECT">>, protocol = Protocol},
    #state{local_connect_enabled = false}
) when Protocol =/= undefined ->
    throw({header_error, extended_connect_not_enabled});
validate_request_headers(
    #h3_stream{
        method = <<"CONNECT">>,
        protocol = Protocol,
        scheme = Scheme,
        path = Path,
        authority = Authority
    } = Stream,
    _State
) when
    Protocol =/= undefined
->
    case {Scheme, Path, Authority} of
        {undefined, _, _} ->
            throw({header_error, {missing_pseudo_header, <<":scheme">>}});
        {_, undefined, _} ->
            throw({header_error, {missing_pseudo_header, <<":path">>}});
        {_, <<>>, _} ->
            throw({header_error, {invalid_pseudo_header, <<":path">>, empty}});
        {_, _, undefined} ->
            throw({header_error, {missing_pseudo_header, <<":authority">>}});
        _ ->
            validate_authority_and_host(Stream),
            ok
    end;
%% Plain CONNECT (RFC 9114 Section 4.4): no scheme/path/protocol; authority required;
%% peer must have advertised CONNECT support if we are the originator.
validate_request_headers(#h3_stream{method = <<"CONNECT">>, scheme = Scheme}, _State) when
    Scheme =/= undefined
->
    throw({header_error, {invalid_connect, scheme_present}});
validate_request_headers(#h3_stream{method = <<"CONNECT">>, path = Path}, _State) when
    Path =/= undefined
->
    throw({header_error, {invalid_connect, path_present}});
validate_request_headers(
    #h3_stream{method = <<"CONNECT">>},
    #state{peer_connect_enabled = false}
) ->
    throw({header_error, connect_not_enabled});
validate_request_headers(#h3_stream{method = <<"CONNECT">>, authority = undefined}, _State) ->
    throw({header_error, {missing_pseudo_header, <<":authority">>}});
validate_request_headers(#h3_stream{method = <<"CONNECT">>}, _State) ->
    %% CONNECT request is valid
    ok;
%% Non-CONNECT must not carry :protocol (RFC 9220).
validate_request_headers(#h3_stream{protocol = Protocol}, _State) when Protocol =/= undefined ->
    throw({header_error, {invalid_field, <<":protocol">>, Protocol}});
%% Non-CONNECT requests
validate_request_headers(#h3_stream{scheme = undefined}, _State) ->
    throw({header_error, {missing_pseudo_header, <<":scheme">>}});
validate_request_headers(#h3_stream{path = undefined}, _State) ->
    throw({header_error, {missing_pseudo_header, <<":path">>}});
validate_request_headers(#h3_stream{path = <<>>}, _State) ->
    throw({header_error, {invalid_pseudo_header, <<":path">>, empty}});
%% RFC 9114 §4.3.1 / RFC 9110 §7.2: non-CONNECT requests need an authority,
%% provided by either :authority or Host. When both are present, they must
%% match.
validate_request_headers(#h3_stream{method = Method} = Stream, _State) when
    Method =/= <<"CONNECT">>
->
    validate_scheme_value(Stream#h3_stream.scheme),
    validate_path_form(Method, Stream#h3_stream.path),
    validate_authority_and_host(Stream),
    ok;
validate_request_headers(_, _State) ->
    ok.

%% RFC 9110 §4.2 / RFC 3986 §3.1: scheme must be ALPHA *(ALPHA / DIGIT / "+" /
%% "-" / "."), HTTP/3 mandates lowercase. We require at least one lowercase
%% letter and no other characters. Caller has already ensured Scheme is a
%% non-undefined binary.
validate_scheme_value(<<>>) ->
    throw({header_error, {invalid_field, <<":scheme">>, <<>>}});
validate_scheme_value(<<C, _/binary>> = Scheme) when C >= $a, C =< $z ->
    case scheme_chars_ok(Scheme) of
        true -> ok;
        false -> throw({header_error, {invalid_field, <<":scheme">>, Scheme}})
    end;
validate_scheme_value(Scheme) ->
    throw({header_error, {invalid_field, <<":scheme">>, Scheme}}).

scheme_chars_ok(<<>>) ->
    true;
scheme_chars_ok(<<C, Rest/binary>>) when
    (C >= $a andalso C =< $z) orelse
        (C >= $0 andalso C =< $9) orelse
        C =:= $+ orelse C =:= $- orelse C =:= $.
->
    scheme_chars_ok(Rest);
scheme_chars_ok(_) ->
    false.

%% RFC 9114 §4.3.1: for OPTIONS, :path may be "*". Otherwise it MUST be
%% origin-form (start with "/"). Absolute URI (scheme://...) is forbidden.
%% Caller has already ensured Path is a non-undefined, non-empty binary.
validate_path_form(<<"OPTIONS">>, <<"*">>) ->
    ok;
validate_path_form(_Method, <<$/, _/binary>>) ->
    ok;
validate_path_form(_Method, Path) ->
    throw({header_error, {invalid_field, <<":path">>, Path}}).

validate_authority_and_host(#h3_stream{authority = Authority, headers = Headers}) ->
    Host = lookup_host_header(Headers),
    check_authority_value(Authority),
    check_host_value(Host),
    case {Authority, Host} of
        {undefined, undefined} ->
            throw({header_error, {missing_pseudo_header, <<":authority">>}});
        {undefined, _} ->
            ok;
        {_, undefined} ->
            ok;
        {Same, Same} ->
            ok;
        {_, _} ->
            throw({header_error, {invalid_field, <<"host">>, Host}})
    end.

%% RFC 9114 §4.3.1 / RFC 9110 §7.2: :authority, when present, MUST NOT be empty
%% and MUST NOT contain userinfo ("user@host"-style) for http/https URIs.
check_authority_value(undefined) ->
    ok;
check_authority_value(<<>>) ->
    throw({header_error, {invalid_field, <<":authority">>, <<>>}});
check_authority_value(Value) ->
    case binary:match(Value, <<"@">>) of
        nomatch -> ok;
        _ -> throw({header_error, {invalid_field, <<":authority">>, Value}})
    end.

check_host_value(undefined) ->
    ok;
check_host_value(<<>>) ->
    throw({header_error, {invalid_field, <<"host">>, <<>>}});
check_host_value(_Value) ->
    ok.

lookup_host_header([]) ->
    undefined;
lookup_host_header([{<<"host">>, Value} | _]) ->
    Value;
lookup_host_header([_ | Rest]) ->
    lookup_host_header(Rest).

%% Validate response pseudo-headers (client receiving responses - RFC 9114 §4.3.2).
%% Rejects request pseudo-headers in responses, requires :status in 100..599.
validate_response_headers(#h3_stream{status = undefined}, _Headers) ->
    throw({header_error, {missing_pseudo_header, <<":status">>}});
validate_response_headers(#h3_stream{status = Status}, _Headers) when
    Status < 100; Status > 599
->
    throw({header_error, {invalid_field, <<":status">>, integer_to_binary(Status)}});
validate_response_headers(_Stream, Headers) ->
    case response_has_request_pseudo(Headers) of
        {true, Name} -> throw({header_error, {invalid_field, Name, <<>>}});
        false -> ok
    end.

response_has_request_pseudo([]) ->
    false;
response_has_request_pseudo([{<<":method">>, _} | _]) ->
    {true, <<":method">>};
response_has_request_pseudo([{<<":scheme">>, _} | _]) ->
    {true, <<":scheme">>};
response_has_request_pseudo([{<<":path">>, _} | _]) ->
    {true, <<":path">>};
response_has_request_pseudo([{<<":authority">>, _} | _]) ->
    {true, <<":authority">>};
response_has_request_pseudo([{<<":protocol">>, _} | _]) ->
    {true, <<":protocol">>};
response_has_request_pseudo([_ | Rest]) ->
    response_has_request_pseudo(Rest).

%% Safe binary to integer conversion with proper error handling
safe_binary_to_integer(Bin, FieldName) ->
    try binary_to_integer(Bin) of
        N when N >= 0 -> N;
        _ -> throw({header_error, {invalid_field, FieldName, Bin}})
    catch
        error:badarg -> throw({header_error, {invalid_field, FieldName, Bin}})
    end.

%% Validate trailer headers (RFC 9114 Section 4.1.2)
%% Trailers MUST NOT contain pseudo-headers or duplicate Content-Length
validate_trailer_headers(Trailers, Stream) ->
    %% RFC 9114 §4.1.2: trailers MUST NOT contain pseudo-headers nor any
    %% connection-specific fields. Reuse the malformed-message validators
    %% so the rules are symmetric with regular header sections.
    try
        validate_field_names_and_values(Trailers),
        case has_pseudo_header(Trailers) of
            true -> throw({header_error, pseudo_header_in_trailer});
            false -> ok
        end,
        validate_trailer_content_length(Trailers, Stream)
    catch
        throw:{header_error, Reason} -> {error, Reason}
    end.

%% Check if headers contain any pseudo-headers
has_pseudo_header([]) ->
    false;
has_pseudo_header([{<<$:, _/binary>>, _} | _]) ->
    true;
has_pseudo_header([_ | Rest]) ->
    has_pseudo_header(Rest).

%% If Content-Length was in headers, it must not be in trailers
validate_trailer_content_length(Trailers, #h3_stream{content_length = CL}) when CL =/= undefined ->
    case lists:keyfind(<<"content-length">>, 1, Trailers) of
        false -> ok;
        _ -> {error, duplicate_content_length_in_trailer}
    end;
validate_trailer_content_length(_, _) ->
    ok.

%% Calculate field section size per RFC 9110 Section 5.2
%% Size = sum of (name length + value length + 32) for each field
calculate_field_section_size(Headers) ->
    lists:foldl(
        fun({Name, Value}, Acc) ->
            Acc + byte_size(Name) + byte_size(Value) + 32
        end,
        0,
        Headers
    ).

%% RFC 9114 Section 4.2.2: Validate outbound headers against peer's limit
-spec validate_outbound_headers([{binary(), binary()}], #state{}) -> ok | {error, term()}.
validate_outbound_headers(Headers, #state{peer_max_field_section_size = MaxSize}) ->
    Size = calculate_field_section_size(Headers),
    case Size > MaxSize of
        true ->
            {error, {header_error, field_section_too_large}};
        false ->
            ok
    end.

%% Parse RFC 9218 Priority header field value
%% Format: "u=N" or "u=N, i" where N is urgency 0-7, i means incremental
%% Examples: "u=3", "u=0, i", "u=7"
%% Returns {Urgency, Incremental} with defaults {3, false}
parse_priority_header(Value) ->
    parse_priority_params(binary:split(Value, <<",">>, [global, trim_all]), 3, false).

parse_priority_params([], Urgency, Incremental) ->
    {Urgency, Incremental};
parse_priority_params([Param | Rest], Urgency, Incremental) ->
    Trimmed = string:trim(Param),
    case Trimmed of
        <<"u=", UBin/binary>> ->
            try binary_to_integer(UBin) of
                U when is_integer(U), U >= 0, U =< 7 ->
                    parse_priority_params(Rest, U, Incremental);
                _ ->
                    %% Invalid urgency - use default
                    parse_priority_params(Rest, Urgency, Incremental)
            catch
                _:_ ->
                    %% Not an integer - use default
                    parse_priority_params(Rest, Urgency, Incremental)
            end;
        <<"i">> ->
            parse_priority_params(Rest, Urgency, true);
        <<"i=?1">> ->
            parse_priority_params(Rest, Urgency, true);
        <<"i=?0">> ->
            parse_priority_params(Rest, Urgency, false);
        _ ->
            %% Unknown parameter - ignore per RFC 9218
            parse_priority_params(Rest, Urgency, Incremental)
    end.

-ifdef(TEST).
%% Legacy test entry point; production code always has the error code.
handle_stream_closed(StreamId, State) ->
    handle_stream_closed(StreamId, 0, State).
-endif.

handle_stream_closed(
    StreamId,
    ErrorCode,
    #state{
        streams = Streams,
        stream_buffers = Buffers,
        uni_stream_buffers = UniBuffers,
        discarded_uni_streams = Discarded,
        claimed_uni_streams = ClaimedUni,
        claimed_bidi_streams = ClaimedBidi,
        bidi_type_buffers = BidiBuffers,
        owner = Owner
    } = State
) ->
    case is_critical_stream(StreamId, State) of
        {true, Type} ->
            %% Peer closed a critical stream - connection error (RFC 9114 Section 6.2.1)
            {error,
                {connection_error, ?H3_CLOSED_CRITICAL_STREAM,
                    iolist_to_binary(io_lib:format("~p stream closed", [Type]))}};
        false ->
            case claimed_stream_direction(StreamId, State) of
                {ok, Direction} ->
                    Event =
                        case ErrorCode of
                            0 -> {stream_type_closed, Direction, StreamId};
                            _ -> {stream_type_reset, Direction, StreamId, ErrorCode}
                        end,
                    Owner ! {quic_h3, self(), Event};
                error ->
                    ok
            end,
            %% RFC 9114 Section 4.1.1: server-side request stream that ends
            %% before a complete request is received MUST be reset with
            %% H3_REQUEST_INCOMPLETE.
            maybe_reset_incomplete_request(StreamId, State),
            State1 = maybe_send_stream_cancel(StreamId, State),
            {ok, State1#state{
                streams = maps:remove(StreamId, Streams),
                stream_buffers = maps:remove(StreamId, Buffers),
                uni_stream_buffers = maps:remove(StreamId, UniBuffers),
                discarded_uni_streams = sets:del_element(StreamId, Discarded),
                claimed_uni_streams = maps:remove(StreamId, ClaimedUni),
                claimed_bidi_streams = maps:remove(StreamId, ClaimedBidi),
                bidi_type_buffers = maps:remove(StreamId, BidiBuffers)
            }}
    end.

maybe_reset_incomplete_request(StreamId, #state{role = server, quic_conn = QuicConn} = State) when
    StreamId rem 4 =:= 0
->
    case maps:find(StreamId, State#state.streams) of
        {ok, #h3_stream{frame_state = complete}} ->
            ok;
        {ok, _Incomplete} ->
            quic:reset_stream(QuicConn, StreamId, ?H3_REQUEST_INCOMPLETE),
            ok;
        error ->
            ok
    end;
maybe_reset_incomplete_request(_StreamId, _State) ->
    ok.

test_discarded_uni_streams(#state{discarded_uni_streams = D}) ->
    D.

test_stream(StreamId, #state{streams = Streams}) ->
    maps:get(StreamId, Streams).

test_push_stream(PushId, #state{push_streams = Pushes}) ->
    maps:get(PushId, Pushes).

%% Check if a stream is a critical H3 stream
is_critical_stream(StreamId, #state{peer_control_stream = StreamId}) -> {true, control};
is_critical_stream(StreamId, #state{peer_encoder_stream = StreamId}) -> {true, qpack_encoder};
is_critical_stream(StreamId, #state{peer_decoder_stream = StreamId}) -> {true, qpack_decoder};
is_critical_stream(_, _) -> false.

%%====================================================================
%% Internal: Sending
%%====================================================================

send_request(
    Headers,
    Opts,
    #state{
        quic_conn = QuicConn,
        qpack_encoder = Encoder,
        next_stream_id = NextId,
        streams = Streams
    } = State
) ->
    %% RFC 9114 §4.2.2: enforce peer's max field section size.
    case validate_outbound_headers(Headers, State) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            %% RFC 9114 §4.2 / §4.3.1: apply the same malformed-message and
            %% pseudo-header rules used on inbound, so we never emit a
            %% request that we would reject on receive.
            case validate_outbound_request_headers(Headers, State) of
                {error, Reason} ->
                    {error, Reason};
                ok ->
                    send_request_validated(
                        Headers, Opts, QuicConn, Encoder, NextId, Streams, State
                    )
            end
    end.

validate_outbound_request_headers(Headers, State) ->
    try
        validate_field_names_and_values(Headers),
        check_duplicate_headers(Headers),
        Template = #h3_stream{id = 0, type = request, state = open, headers = Headers},
        Stream = do_update_stream_with_headers(Headers, Template, false),
        validate_request_headers(Stream, State),
        ok
    catch
        throw:{header_error, Reason} -> {error, Reason}
    end.

send_request_validated(Headers, Opts, QuicConn, Encoder, NextId, Streams, State) ->
    %% end_stream defaults to true for requests without body (GET, HEAD, etc.)
    EndStream = maps:get(end_stream, Opts, true),
    case quic:open_stream(QuicConn) of
        {ok, StreamId} ->
            %% Use encode/3 with StreamId for section ack tracking
            {Encoded, Encoder1} = quic_qpack:encode(Headers, StreamId, Encoder),
            %% RFC 9204: Send encoder instructions BEFORE the HEADERS frame
            %% so peer has dynamic table entries before receiving references
            State1 = State#state{qpack_encoder = Encoder1},
            State2 = send_encoder_instructions(State1),
            HeadersFrame = quic_h3_frame:encode_headers(Encoded),
            case quic:send_data(QuicConn, StreamId, HeadersFrame, EndStream) of
                ok ->
                    StreamState =
                        case EndStream of
                            true -> half_closed_local;
                            false -> open
                        end,
                    IsConnect =
                        (lists:keyfind(<<":method">>, 1, Headers) =:=
                            {<<":method">>, <<"CONNECT">>}),
                    Stream = #h3_stream{
                        id = StreamId,
                        type = request,
                        state = StreamState,
                        frame_state = expecting_headers,
                        is_connect = IsConnect
                    },
                    State3 = State2#state{
                        next_stream_id = NextId + 4,
                        streams = Streams#{StreamId => Stream}
                    },
                    {ok, StreamId, State3};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Coalesce a full response: send_response then a final send_data with end-stream
%% in one connection call. Reuses do_send_response/4 (validation, QPACK, HEADERS
%% buffering) and do_send_data/4 (which prepends the buffered HEADERS so they ride
%% in the same QUIC packet as the body). HEAD, 204 and 304 send no body.
do_respond(StreamId, Status, Headers, Body, State) ->
    case do_send_response(StreamId, Status, Headers, State) of
        {ok, State1} ->
            Data =
                case response_body_allowed(StreamId, Status, State1) of
                    true -> Body;
                    false -> <<>>
                end,
            do_send_data(StreamId, Data, true, State1);
        {error, _} = Err ->
            Err
    end.

%% RFC 9110: HEAD requests and 204/304 responses carry no body.
response_body_allowed(_StreamId, Status, _State) when Status =:= 204; Status =:= 304 ->
    false;
response_body_allowed(StreamId, _Status, #state{streams = Streams}) ->
    case maps:find(StreamId, Streams) of
        {ok, #h3_stream{method = <<"HEAD">>}} -> false;
        _ -> true
    end.

do_send_response(
    _StreamId,
    Status,
    _Headers,
    _State
) when not is_integer(Status); Status < 100; Status > 599 ->
    %% RFC 9114 §4.3.2: :status must be a valid HTTP status code.
    {error, {invalid_status, Status}};
do_send_response(
    StreamId,
    Status,
    Headers,
    #state{
        qpack_encoder = Encoder,
        streams = Streams
    } = State
) ->
    StatusHeader = {<<":status">>, integer_to_binary(Status)},
    AllHeaders = [StatusHeader | Headers],
    %% RFC 9114 Section 4.2.2: Validate outbound headers against peer's limit
    case validate_outbound_headers(AllHeaders, State) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            case maps:find(StreamId, Streams) of
                {ok, Stream} ->
                    %% Use encode/3 with StreamId for section ack tracking
                    {Encoded, Encoder1} = quic_qpack:encode(AllHeaders, StreamId, Encoder),
                    %% RFC 9204: Send encoder instructions BEFORE the HEADERS frame
                    State1 = State#state{qpack_encoder = Encoder1},
                    State2 = send_encoder_instructions(State1),
                    HeadersFrame = quic_h3_frame:encode_headers(Encoded),
                    Stream1 = Stream#h3_stream{status = Status, headers = AllHeaders},
                    finish_send_response(StreamId, Status, HeadersFrame, Stream1, State2);
                error ->
                    {error, unknown_stream}
            end
    end.

%% Final response (>= 200) on a normal request: buffer the HEADERS so they
%% coalesce into the same QUIC packet as the first body chunk (flushed by
%% do_send_data/4 or do_send_trailers/3). The QPACK encoder instructions were
%% already sent, preserving RFC 9204 ordering.
%%
%% A CONNECT response and informational (1xx) responses are sent immediately,
%% never buffered: a CONNECT tunnel's 200 must reach the client before any
%% tunnel DATA (and the server may send none until the client does), so
%% buffering it would deadlock the tunnel.
finish_send_response(StreamId, Status, HeadersFrame, Stream1, State) when
    Status >= 200, not Stream1#h3_stream.is_connect
->
    Pending = maps:put(StreamId, HeadersFrame, State#state.pending_response_headers),
    {ok, State#state{
        streams = (State#state.streams)#{StreamId => Stream1},
        pending_response_headers = Pending
    }};
finish_send_response(StreamId, _Status, HeadersFrame, Stream1, State) ->
    send_response_headers_now(StreamId, HeadersFrame, Stream1, State).

send_response_headers_now(StreamId, HeadersFrame, Stream1, State) ->
    case quic:send_data(State#state.quic_conn, StreamId, HeadersFrame, false) of
        ok ->
            {ok, State#state{streams = (State#state.streams)#{StreamId => Stream1}}};
        {error, Reason} ->
            {error, Reason}
    end.

do_send_data(
    StreamId,
    Data,
    Fin,
    #state{quic_conn = QuicConn, streams = Streams, pending_response_headers = Pending} = State
) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            DataFrame = quic_h3_frame:encode_data(Data),
            %% Prepend any buffered response HEADERS so HEADERS + first body
            %% chunk ride in one QUIC packet.
            {Payload, Pending1} =
                case maps:take(StreamId, Pending) of
                    {HeadersFrame, P1} -> {<<HeadersFrame/binary, DataFrame/binary>>, P1};
                    error -> {DataFrame, Pending}
                end,
            case quic:send_data(QuicConn, StreamId, Payload, Fin) of
                ok ->
                    Stream1 =
                        case Fin of
                            true -> Stream#h3_stream{state = half_closed_local};
                            false -> Stream
                        end,
                    {ok, State#state{
                        streams = Streams#{StreamId => Stream1},
                        pending_response_headers = Pending1
                    }};
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, unknown_stream}
    end.

do_send_trailers(
    StreamId,
    Trailers,
    #state{
        quic_conn = QuicConn,
        qpack_encoder = Encoder,
        streams = Streams
    } = State
) ->
    %% RFC 9114 Section 4.2.2: Validate outbound headers against peer's limit
    case validate_outbound_headers(Trailers, State) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            case maps:find(StreamId, Streams) of
                {ok, #h3_stream{is_connect = true}} ->
                    %% RFC 9114 §4.4: no trailers on CONNECT tunnel streams
                    {error, connect_tunnel};
                {ok, Stream} ->
                    %% Use encode/3 with StreamId for section ack tracking
                    {Encoded, Encoder1} = quic_qpack:encode(Trailers, StreamId, Encoder),
                    %% RFC 9204: Send encoder instructions BEFORE the HEADERS frame
                    State1 = State#state{qpack_encoder = Encoder1},
                    State2 = send_encoder_instructions(State1),
                    TrailersFrame = quic_h3_frame:encode_headers(Encoded),
                    %% Flush any still-buffered response HEADERS ahead of the
                    %% trailers (a response with HEADERS + trailers but no body).
                    {Payload, Pending1} =
                        case maps:take(StreamId, State2#state.pending_response_headers) of
                            {HeadersFrame, P1} ->
                                {<<HeadersFrame/binary, TrailersFrame/binary>>, P1};
                            error ->
                                {TrailersFrame, State2#state.pending_response_headers}
                        end,
                    case quic:send_data(QuicConn, StreamId, Payload, true) of
                        ok ->
                            Stream1 = Stream#h3_stream{
                                trailers = Trailers,
                                state = half_closed_local
                            },
                            State3 = State2#state{
                                streams = Streams#{StreamId => Stream1},
                                pending_response_headers = Pending1
                            },
                            {ok, State3};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                error ->
                    {error, unknown_stream}
            end
    end.

do_cancel_stream(
    StreamId,
    ErrorCode,
    #state{quic_conn = QuicConn, streams = Streams, pending_response_headers = Pending} = State
) ->
    quic:reset_stream(QuicConn, StreamId, ErrorCode),
    %% RFC 9204 Section 4.4.2: Send Stream Cancellation if stream was blocked
    State1 = maybe_send_stream_cancel(StreamId, State),
    %% Drop any buffered (unsent) HEADERS for the cancelled stream.
    State1#state{
        streams = maps:remove(StreamId, Streams),
        pending_response_headers = maps:remove(StreamId, Pending)
    }.

%%====================================================================
%% Internal: Per-stream Handler Registration
%%====================================================================

%% Register a handler process to receive stream data
do_set_stream_handler(StreamId, HandlerPid, Opts, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, _Stream} ->
            register_stream_handler(StreamId, HandlerPid, Opts, State);
        error ->
            {error, unknown_stream}
    end.

register_stream_handler(
    StreamId,
    HandlerPid,
    Opts,
    #state{
        stream_handlers = Handlers,
        stream_data_buffers = Buffers
    } = State
) ->
    MonRef = erlang:monitor(process, HandlerPid),
    NewHandlers = Handlers#{StreamId => {HandlerPid, MonRef}},
    case maps:take(StreamId, Buffers) of
        {{Chunks, _Size, _HadFin}, NewBuffers} ->
            State1 = State#state{stream_handlers = NewHandlers, stream_data_buffers = NewBuffers},
            drain_buffered_data(StreamId, HandlerPid, Chunks, Opts, State1);
        error ->
            {ok, State#state{stream_handlers = NewHandlers}}
    end.

drain_buffered_data(StreamId, HandlerPid, Chunks, Opts, State) ->
    OrderedChunks = lists:reverse(Chunks),
    case maps:get(drain_buffer, Opts, true) of
        true ->
            {ok, OrderedChunks, State};
        false ->
            Conn = self(),
            [
                HandlerPid ! {quic_h3, Conn, {data, StreamId, Data, Fin}}
             || {Data, Fin} <- OrderedChunks
            ],
            {ok, State}
    end.

%% Unregister a stream handler
do_unset_stream_handler(StreamId, #state{stream_handlers = Handlers} = State) ->
    case maps:take(StreamId, Handlers) of
        {{_Pid, MonRef}, NewHandlers} ->
            erlang:demonitor(MonRef, [flush]),
            State#state{stream_handlers = NewHandlers};
        error ->
            State
    end.

%% Find stream ID by monitor reference
find_handler_by_ref(Ref, Handlers) ->
    find_handler_by_ref_iter(Ref, maps:iterator(Handlers)).

find_handler_by_ref_iter(Ref, Iter) ->
    case maps:next(Iter) of
        {StreamId, {_Pid, Ref}, _} ->
            {ok, StreamId};
        {_StreamId, {_Pid, _OtherRef}, NextIter} ->
            find_handler_by_ref_iter(Ref, NextIter);
        none ->
            error
    end.

%% Notify stream data to appropriate recipient
%% If a handler is registered, send directly to handler.
%% If no handler registered and role is client, send to owner (default client behavior).
%% If no handler registered and role is server, buffer the data for when handler registers.
notify_stream_data(
    StreamId, Data, Fin, #state{stream_handlers = Handlers, owner = Owner, role = Role} = State
) ->
    Conn = self(),
    case maps:find(StreamId, Handlers) of
        {ok, {HandlerPid, _MonRef}} ->
            HandlerPid ! {quic_h3, Conn, {data, StreamId, Data, Fin}},
            State;
        error when Role =:= client ->
            %% Client mode: send data to owner by default (typical client usage pattern)
            Owner ! {quic_h3, Conn, {data, StreamId, Data, Fin}},
            State;
        error ->
            %% Server mode: buffer data for later retrieval when handler registers
            buffer_stream_data(StreamId, Data, Fin, State)
    end.

%% Buffer data for a stream (before handler registers)
buffer_stream_data(
    StreamId,
    Data,
    Fin,
    #state{
        stream_data_buffers = Buffers,
        stream_buffer_limit = Limit
    } = State
) ->
    {Chunks, Size, HadFin} = maps:get(StreamId, Buffers, {[], 0, false}),
    NewSize = Size + byte_size(Data),
    case NewSize > Limit of
        true ->
            %% Buffer overflow - keep buffering but truncate
            %% Add the chunk anyway but mark as overflow for debugging
            NewChunks = [{Data, Fin} | Chunks],
            NewBuffers = Buffers#{StreamId => {NewChunks, NewSize, HadFin orelse Fin}},
            State#state{stream_data_buffers = NewBuffers};
        false ->
            NewChunks = [{Data, Fin} | Chunks],
            NewHadFin = HadFin orelse Fin,
            NewBuffers = Buffers#{StreamId => {NewChunks, NewSize, NewHadFin}},
            State#state{stream_data_buffers = NewBuffers}
    end.

%%====================================================================
%% Internal: Server Push (RFC 9114 Section 4.6)
%%====================================================================

%% Initiate a server push
%% 1. Allocate push ID (skipping cancelled IDs)
%% 2. Send PUSH_PROMISE on request stream
%% 3. Open push stream (unidirectional)
%% 4. Return push ID for subsequent data sending
do_push(RequestStreamId, Headers, #state{streams = Streams} = State) ->
    %% RFC 9114 §4.6: server MUST NOT push for a non-cacheable method.
    case cacheable_promised_method(Headers) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            case allocate_push_id(State) of
                {ok, PushId, State1} ->
                    case maps:is_key(RequestStreamId, Streams) of
                        false ->
                            {error, unknown_request_stream};
                        true ->
                            do_push_internal(RequestStreamId, Headers, PushId, State1)
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% RFC 9114 §4.6: only safe & cacheable methods (GET, HEAD) may be pushed.
cacheable_promised_method(Headers) ->
    case lists:keyfind(<<":method">>, 1, Headers) of
        {_, <<"GET">>} -> ok;
        {_, <<"HEAD">>} -> ok;
        {_, Method} -> {error, {non_cacheable_method, Method}};
        false -> {error, missing_method}
    end.

%% Allocate the next available push ID, skipping cancelled ones
%% Returns {ok, PushId, State} | {error, Reason}
allocate_push_id(#state{max_push_id = undefined}) ->
    {error, push_not_enabled};
allocate_push_id(#state{next_push_id = Next, max_push_id = Max}) when Next > Max ->
    {error, max_push_id_exceeded};
allocate_push_id(
    #state{next_push_id = Next, max_push_id = Max, cancelled_pushes = Cancelled} = State
) ->
    case sets:is_element(Next, Cancelled) of
        true ->
            %% Skip cancelled ID, try next
            %% Remove from cancelled set since we're skipping it
            State1 = State#state{
                next_push_id = Next + 1,
                cancelled_pushes = sets:del_element(Next, Cancelled)
            },
            %% Recursively find next available (but check bounds)
            case Next + 1 > Max of
                true ->
                    {error, max_push_id_exceeded};
                false ->
                    allocate_push_id(State1)
            end;
        false ->
            {ok, Next, State#state{next_push_id = Next + 1}}
    end.

do_push_internal(
    RequestStreamId,
    Headers,
    PushId,
    #state{
        quic_conn = QuicConn,
        qpack_encoder = Encoder,
        push_streams = PushStreams
    } = State
) ->
    %% RFC 9114 Section 4.2.2: Validate outbound headers against peer's limit
    case validate_outbound_headers(Headers, State) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            %% Encode headers for PUSH_PROMISE
            {Encoded, Encoder1} = quic_qpack:encode(Headers, RequestStreamId, Encoder),
            State1 = State#state{qpack_encoder = Encoder1},
            State2 = send_encoder_instructions(State1),

            %% Send PUSH_PROMISE on request stream
            PushPromiseFrame = quic_h3_frame:encode_push_promise(PushId, Encoded),
            do_push_send(
                QuicConn, RequestStreamId, PushPromiseFrame, PushId, PushStreams, State2
            )
    end.

do_push_send(QuicConn, RequestStreamId, PushPromiseFrame, PushId, PushStreams, State) ->
    case quic:send_data(QuicConn, RequestStreamId, PushPromiseFrame, false) of
        ok ->
            %% Open push stream (unidirectional, server-initiated)
            case quic:open_unidirectional_stream(QuicConn) of
                {ok, PushStreamId} ->
                    %% Send push stream header: Type(0x01) + Push ID
                    PushStreamType = quic_h3_frame:encode_stream_type(push),
                    PushIdVarint = quic_varint:encode(PushId),
                    PushStreamHeader = <<PushStreamType/binary, PushIdVarint/binary>>,
                    case quic:send_data(QuicConn, PushStreamId, PushStreamHeader, false) of
                        ok ->
                            %% Track push stream
                            Stream = #h3_stream{
                                id = PushStreamId,
                                type = push,
                                state = open,
                                frame_state = expecting_headers
                            },
                            %% next_push_id already incremented by allocate_push_id
                            State3 = State#state{
                                push_streams = maps:put(PushId, {PushStreamId, Stream}, PushStreams)
                            },
                            {ok, PushId, State3};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Send response headers on a push stream
do_send_push_response(
    PushId,
    Status,
    Headers,
    #state{
        push_streams = PushStreams,
        quic_conn = QuicConn,
        qpack_encoder = Encoder
    } = State
) ->
    StatusHeader = {<<":status">>, integer_to_binary(Status)},
    AllHeaders = [StatusHeader | Headers],
    %% RFC 9114 Section 4.2.2: Validate outbound headers against peer's limit
    case validate_outbound_headers(AllHeaders, State) of
        {error, Reason} ->
            {error, Reason};
        ok ->
            case maps:find(PushId, PushStreams) of
                {ok, {StreamId, Stream}} ->
                    {Encoded, Encoder1} = quic_qpack:encode(AllHeaders, StreamId, Encoder),
                    State1 = State#state{qpack_encoder = Encoder1},
                    State2 = send_encoder_instructions(State1),
                    HeadersFrame = quic_h3_frame:encode_headers(Encoded),
                    case quic:send_data(QuicConn, StreamId, HeadersFrame, false) of
                        ok ->
                            Stream1 = Stream#h3_stream{
                                status = Status,
                                headers = AllHeaders,
                                frame_state = expecting_data
                            },
                            State3 = State2#state{
                                push_streams = maps:put(PushId, {StreamId, Stream1}, PushStreams)
                            },
                            {ok, State3};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                error ->
                    {error, unknown_push_id}
            end
    end.

%% Send data on a push stream
do_send_push_data(
    PushId,
    Data,
    Fin,
    #state{
        push_streams = PushStreams,
        cancelled_pushes = Cancelled,
        quic_conn = QuicConn
    } = State
) ->
    case maps:find(PushId, PushStreams) of
        {ok, {StreamId, Stream}} ->
            DataFrame = quic_h3_frame:encode_data(Data),
            case quic:send_data(QuicConn, StreamId, DataFrame, Fin) of
                ok ->
                    case Fin of
                        true ->
                            %% Push complete - remove from tracking
                            %% Also clean cancelled_pushes to prevent unbounded set growth
                            {ok, State#state{
                                push_streams = maps:remove(PushId, PushStreams),
                                cancelled_pushes = sets:del_element(PushId, Cancelled)
                            }};
                        false ->
                            Stream1 = Stream#h3_stream{
                                %% Sent-side accounting; push stream is dropped on FIN.
                                body_received = Stream#h3_stream.body_received + byte_size(Data)
                            },
                            {ok, State#state{
                                push_streams = maps:put(PushId, {StreamId, Stream1}, PushStreams)
                            }}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, unknown_push_id}
    end.

%%====================================================================
%% Internal: Client Push (RFC 9114 Section 4.6)
%%====================================================================

%% Set MAX_PUSH_ID (client-side)
do_set_max_push_id(
    MaxPushId,
    #state{
        local_max_push_id = OldMaxPushId,
        quic_conn = QuicConn,
        local_control_stream = ControlStream
    } = State
) ->
    %% Validate that MAX_PUSH_ID does not decrease
    case OldMaxPushId =/= undefined andalso MaxPushId < OldMaxPushId of
        true ->
            {error, max_push_id_cannot_decrease};
        false ->
            %% Send MAX_PUSH_ID frame on control stream
            MaxPushIdFrame = quic_h3_frame:encode_max_push_id(MaxPushId),
            case quic:send_data(QuicConn, ControlStream, MaxPushIdFrame, false) of
                ok ->
                    {ok, State#state{local_max_push_id = MaxPushId}};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% Cancel a push (client-side)
do_cancel_push(
    PushId,
    #state{
        local_max_push_id = MaxPushId,
        local_cancelled_pushes = Cancelled,
        promised_pushes = Promised,
        received_pushes = Received,
        quic_conn = QuicConn,
        local_control_stream = ControlStream
    } = State
) ->
    %% Validate push ID
    case MaxPushId =:= undefined orelse PushId > MaxPushId of
        true ->
            %% Invalid push ID - just ignore
            State;
        false ->
            %% Send CANCEL_PUSH on control stream
            CancelPushFrame = quic_h3_frame:encode_cancel_push(PushId),
            quic:send_data(QuicConn, ControlStream, CancelPushFrame, false),
            %% Update state
            State#state{
                local_cancelled_pushes = sets:add_element(PushId, Cancelled),
                promised_pushes = maps:remove(PushId, Promised),
                received_pushes = maps:remove(PushId, Received)
            }
    end.

%% Send Stream Cancellation on decoder stream if stream was blocked (RFC 9204 Section 4.4.2)
maybe_send_stream_cancel(
    StreamId,
    #state{
        blocked_streams = Blocked,
        quic_conn = QuicConn,
        local_decoder_stream = DecoderStream
    } = State
) ->
    case maps:is_key(StreamId, Blocked) of
        true when DecoderStream =/= undefined ->
            Cancel = quic_qpack:encode_stream_cancel(StreamId),
            quic:send_data(QuicConn, DecoderStream, Cancel, false),
            State#state{blocked_streams = maps:remove(StreamId, Blocked)};
        _ ->
            State
    end.

%% Clean up blocked streams when GOAWAY received (RFC 9114 Section 5.2)
%% Send Stream Cancellation for each blocked stream (RFC 9204 Section 4.4.2)
cleanup_blocked_streams_on_goaway(
    #state{
        blocked_streams = Blocked,
        quic_conn = QuicConn,
        local_decoder_stream = DecoderStream
    } = State
) when map_size(Blocked) > 0, DecoderStream =/= undefined ->
    maps:foreach(
        fun(StreamId, _) ->
            Cancel = quic_qpack:encode_stream_cancel(StreamId),
            quic:send_data(QuicConn, DecoderStream, Cancel, false)
        end,
        Blocked
    ),
    State#state{blocked_streams = #{}};
cleanup_blocked_streams_on_goaway(State) ->
    State#state{blocked_streams = #{}}.

send_goaway(
    #state{
        quic_conn = QuicConn,
        local_control_stream = ControlStream
    } = State
) ->
    Id = goaway_id_to_send(State),
    GoawayFrame = quic_h3_frame:encode_goaway(Id),
    case quic:send_data(QuicConn, ControlStream, GoawayFrame, false) of
        ok ->
            {ok, State#state{goaway_id = Id}};
        {error, Reason} ->
            {error, Reason}
    end.

%% RFC 9114 §5.2 / §7.2.6: GOAWAY identifier marks the first stream/push that
%% will NOT be processed. Server sends LastId + 4 (next client-initiated bidi).
%% Client sends the next push ID it will refuse.
goaway_id_to_send(#state{role = server, last_stream_id = LastId}) ->
    LastId + 4;
goaway_id_to_send(#state{role = client, last_accepted_push_id = undefined}) ->
    0;
goaway_id_to_send(#state{role = client, last_accepted_push_id = Last}) ->
    Last + 1.

%% RFC 9114 Section 7.2.6: validate GOAWAY identifier by our role (we are the
%% receiver). A client receives a stream ID (client-initiated bidi, rem 4 =:= 0);
%% a server receives a push ID.
validate_goaway_id(client, Id) when Id rem 4 =:= 0 -> ok;
validate_goaway_id(client, _Id) -> {error, <<"GOAWAY stream ID not client-initiated bidi">>};
validate_goaway_id(server, _Id) -> ok.

send_encoder_instructions(
    #state{
        quic_conn = QuicConn,
        local_encoder_stream = EncoderStream,
        qpack_encoder = Encoder
    } = State
) ->
    Instructions = quic_qpack:get_encoder_instructions(Encoder),
    case Instructions of
        <<>> ->
            State;
        _ ->
            quic:send_data(QuicConn, EncoderStream, Instructions, false),
            Encoder1 = quic_qpack:clear_encoder_instructions(Encoder),
            State#state{qpack_encoder = Encoder1}
    end.

%%====================================================================
%% Internal: Helpers
%%====================================================================

%% Send Section Acknowledgment on decoder stream (RFC 9204 Section 4.4.1)
%% Only send when the field section could have referenced dynamic table entries.
%% If our max table capacity is 0, peer cannot use dynamic entries, so RIC is always 0.
send_section_ack(
    StreamId,
    #state{
        quic_conn = QuicConn,
        local_decoder_stream = DecoderStream,
        qpack_decoder = Decoder
    } = State
) when DecoderStream =/= undefined ->
    MaxCapacity = quic_qpack:get_dynamic_capacity(Decoder),
    case MaxCapacity > 0 of
        true ->
            %% Dynamic table in use, send Section Ack
            Ack = quic_qpack:encode_section_ack(StreamId),
            quic:send_data(QuicConn, DecoderStream, Ack, false),
            State;
        false ->
            %% No dynamic table, peer can't use dynamic entries, no ack needed
            State
    end;
send_section_ack(_StreamId, State) ->
    %% Decoder stream not yet established
    State.

%% Apply peer SETTINGS to QPACK encoder and connection state (RFC 9114 Section 7.2.4.1)
apply_peer_settings(Settings, #state{qpack_encoder = Encoder} = State) ->
    %% 1. QPACK encoder configuration
    %% Set encoder dynamic table capacity based on peer's advertised max.
    %% NOTE: The QPACK encoder (quic_qpack.erl) only references entries that
    %% have been acknowledged by the peer (via Known Received Count). New entries
    %% are added to the table and encoder instructions are sent, but we encode
    %% as literals until the peer acknowledges receipt. This avoids the cross-stream
    %% ordering issue where HEADERS might arrive before encoder instructions.
    MaxCapacity = maps:get(qpack_max_table_capacity, Settings, 0),
    Encoder1 = quic_qpack:set_dynamic_capacity(MaxCapacity, Encoder),

    %% 2. Max field section size - store for header block validation. Cap
    %% the peer-advertised value at our local frame ceiling so an attacker
    %% cannot inflate per-block memory budgets via SETTINGS.
    MaxFieldSectionSize = min(
        maps:get(max_field_section_size, Settings, ?H3_DEFAULT_MAX_FIELD_SECTION_SIZE),
        ?H3_MAX_FRAME_SIZE
    ),

    %% 3. QPACK blocked streams limit
    MaxBlockedStreams = maps:get(qpack_blocked_streams, Settings, 0),

    %% 4. Connect protocol enabled (RFC 9220)
    ConnectEnabled = maps:get(enable_connect_protocol, Settings, 0) =:= 1,

    %% 5. H3 DATAGRAM (RFC 9297). Value must be 0 or 1; anything else is
    %% a SETTINGS_ERROR. A peer advertising h3_datagram = 1 without a
    %% non-zero QUIC max_datagram_frame_size is also an error.
    H3DatagramEnabled =
        case maps:find(h3_datagram, Settings) of
            {ok, 0} ->
                false;
            {ok, 1} ->
                validate_peer_h3_datagram(State);
            {ok, _Other} ->
                throw({connection_error, ?H3_SETTINGS_ERROR, <<"invalid h3_datagram">>});
            error ->
                false
        end,

    %% Send any encoder instructions generated by capacity change
    State1 = State#state{
        qpack_encoder = Encoder1,
        peer_max_field_section_size = MaxFieldSectionSize,
        peer_max_blocked_streams = MaxBlockedStreams,
        peer_connect_enabled = ConnectEnabled,
        peer_h3_datagram_enabled = H3DatagramEnabled
    },
    send_encoder_instructions(State1).

%% RFC 9297 §2.1: peer SETTINGS_H3_DATAGRAM = 1 requires non-zero
%% max_datagram_frame_size on the QUIC connection. Return `true' when
%% the precondition holds, otherwise raise H3_SETTINGS_ERROR. Takes
%% the QUIC-level max datagram size directly so the check can be
%% unit-tested without a live connection.
validate_peer_h3_datagram_with(0) ->
    throw(
        {connection_error, ?H3_SETTINGS_ERROR, <<"h3_datagram without max_datagram_frame_size">>}
    );
validate_peer_h3_datagram_with(_) ->
    true.

validate_peer_h3_datagram(#state{quic_conn = QuicConn}) ->
    validate_peer_h3_datagram_with(quic:datagram_max_size(QuicConn)).

%% RFC 9297 §2.1 inbound datagram. Peel the quarter-stream-id varint
%% and deliver the payload tagged with the full stream id to the owner.
%% Datagrams for unknown streams are dropped silently per §5.
deliver_h3_datagram(Data, #state{owner = Owner} = State) ->
    case decode_h3_datagram(Data) of
        {ok, StreamId, Payload} ->
            case maps:is_key(StreamId, State#state.streams) of
                true -> Owner ! {quic_h3, self(), {datagram, StreamId, Payload}};
                false -> ok
            end;
        error ->
            ok
    end.

decode_h3_datagram(Bin) ->
    try
        {QSID, Rest} = quic_varint:decode(Bin),
        {ok, QSID bsl 2, Rest}
    catch
        _:_ -> error
    end.

%% RFC 9297 §2.1 outbound. Caller provides the request stream id; we
%% prepend QSID = StreamId bsr 2 and hand the framed bytes to the QUIC
%% DATAGRAM send path. Errors from the QUIC layer (datagrams_not_supported,
%% datagram_too_large, datagram_too_large_for_path, congestion_limited)
%% bubble up unchanged.
h3_send_datagram(StreamId, Data, State) ->
    case h3_datagrams_live(State) of
        false ->
            {error, h3_datagrams_disabled};
        true ->
            case maps:is_key(StreamId, State#state.streams) of
                false ->
                    {error, unknown_stream};
                true ->
                    QSID = quic_varint:encode(StreamId bsr 2),
                    Framed = <<QSID/binary, (iolist_to_binary(Data))/binary>>,
                    quic:send_datagram(State#state.quic_conn, Framed)
            end
    end.

h3_datagrams_live(#state{h3_datagram_enabled = L, peer_h3_datagram_enabled = R}) ->
    L andalso R.

%% Apply RFC 9218 priority to underlying QUIC stream
apply_stream_priority(_StreamId, _Stream, #state{quic_conn = undefined}) ->
    ok;
apply_stream_priority(StreamId, Stream, #state{quic_conn = QuicConn}) ->
    #h3_stream{urgency = Urgency, incremental = Incremental} = Stream,
    %% Set QUIC stream priority - ignore errors (stream might be closed)
    _ = quic:set_stream_priority(QuicConn, StreamId, Urgency, Incremental),
    ok.

%% Handle PRIORITY_UPDATE frame payload (RFC 9218 Section 7)
%% Payload format: Prioritized Element ID (varint) + Priority Field Value (rest)
handle_priority_update_frame(Payload, #state{streams = Streams} = State) ->
    case decode_priority_update_payload(Payload) of
        {ok, StreamId, PriorityFieldValue} ->
            case maps:find(StreamId, Streams) of
                {ok, Stream} ->
                    {Urgency, Incremental} = parse_priority_field_value(PriorityFieldValue),
                    Stream1 = Stream#h3_stream{urgency = Urgency, incremental = Incremental},
                    apply_stream_priority(StreamId, Stream1, State),
                    {ok, State#state{streams = maps:put(StreamId, Stream1, Streams)}};
                error ->
                    %% Stream doesn't exist - ignore per RFC 9218 §7
                    {ok, State}
            end;
        {error, Reason} ->
            {error, {connection_error, ?H3_FRAME_ERROR, Reason}}
    end.

%% RFC 9218 §7: PRIORITY_UPDATE payload = Prioritized Element ID (varint) +
%% Priority Field Value (bytes). The varint MUST decode successfully; the
%% value bytes are forgiving (parsed as Structured Fields per §5).
decode_priority_update_payload(Payload) ->
    try quic_varint:decode(Payload) of
        {ElementId, FieldValue} -> {ok, ElementId, FieldValue}
    catch
        _:_ -> {error, <<"malformed PRIORITY_UPDATE payload">>}
    end.

%% RFC 9218 §7.2: PRIORITY_UPDATE targeting a push stream. Server-side only;
%% client sends it to reprioritize a push stream.
handle_priority_update_push_frame(Payload, #state{role = server, push_streams = Pushes} = State) ->
    case decode_priority_update_payload(Payload) of
        {ok, PushId, PriorityFieldValue} ->
            case maps:find(PushId, Pushes) of
                {ok, {StreamId, Stream}} ->
                    {Urgency, Incremental} = parse_priority_field_value(PriorityFieldValue),
                    Stream1 = Stream#h3_stream{urgency = Urgency, incremental = Incremental},
                    apply_stream_priority(StreamId, Stream1, State),
                    {ok, State#state{push_streams = Pushes#{PushId => {StreamId, Stream1}}}};
                error ->
                    %% Push ID unknown - ignore per RFC 9218
                    {ok, State}
            end;
        {error, Reason} ->
            {error, {connection_error, ?H3_FRAME_ERROR, Reason}}
    end;
handle_priority_update_push_frame(_Payload, #state{role = client} = State) ->
    %% RFC 9218: client should not receive PRIORITY_UPDATE for push; ignore.
    {ok, State}.

%% Parse RFC 9218 Priority Field Value (Structured Fields format)
%% Same format as Priority header: "u=N, i" or just parameters
parse_priority_field_value(<<>>) ->
    %% Default values
    {3, false};
parse_priority_field_value(Value) ->
    parse_priority_header(Value).

maybe_transition_connected(#state{settings_received = true} = State) ->
    {next_state, connected, State};
maybe_transition_connected(State) ->
    {keep_state, State}.

maybe_close_if_drained(#state{streams = Streams} = State) when map_size(Streams) =:= 0 ->
    {next_state, closing, State};
maybe_close_if_drained(State) ->
    {keep_state, State}.

handle_connection_error(
    {connection_error, ErrorCode, Reason}, #state{quic_conn = QuicConn, owner = Owner} = State
) ->
    %% Some call sites forward a non-binary decode reason; quic:close/3
    %% requires a binary phrase, so coerce before sending CONNECTION_CLOSE.
    Phrase = reason_phrase(Reason),
    Owner ! {quic_h3, self(), {error, ErrorCode, Phrase}},
    quic:safe_close(QuicConn, ErrorCode, Phrase),
    {next_state, closing, State}.

reason_phrase(Reason) when is_binary(Reason) ->
    Reason;
reason_phrase(Reason) ->
    try
        iolist_to_binary(Reason)
    catch
        _:_ -> iolist_to_binary(io_lib:format("~0p", [Reason]))
    end.

notify_stream_reset(StreamId, ErrorCode, #state{owner = Owner}) ->
    Owner ! {quic_h3, self(), {stream_reset, StreamId, ErrorCode}}.

%% Forward a session ticket from the QUIC layer to the H3 owner.
%% RFC 8446 Section 4.6.1: tickets may be issued at any time post-handshake;
%% consumers need this to populate per-origin session caches.
forward_session_ticket(T, #state{owner = Owner}) ->
    Owner ! {quic_h3, self(), {session_ticket, T}},
    ok.

%% Forward an early_data_rejected notification from the QUIC layer to
%% the H3 owner and drop the affected streams. RFC 9001 Section 4.6.2.
forward_early_data_rejected(StreamIds, #state{owner = Owner, streams = Streams} = State) ->
    NewStreams = lists:foldl(fun maps:remove/2, Streams, rejected_ids_list(StreamIds)),
    Owner ! {quic_h3, self(), {early_data_rejected, StreamIds}},
    State#state{streams = NewStreams}.

rejected_ids_list(L) when is_list(L) -> L;
rejected_ids_list(S) -> sets:to_list(S).

invoke_handler(Conn, StreamId, Method, Path, Headers) ->
    case get(h3_handler) of
        undefined ->
            ok;
        Fun when is_function(Fun, 5) ->
            %% Spawn to avoid blocking the connection process
            spawn(fun() ->
                try
                    Fun(Conn, StreamId, Method, Path, Headers)
                catch
                    Class:Reason:Stack ->
                        error_logger:error_msg(
                            "HTTP/3 handler error: ~p:~p~n~p~n",
                            [Class, Reason, Stack]
                        )
                end
            end);
        Module when is_atom(Module) ->
            spawn(fun() ->
                try
                    Module:handle_request(Conn, StreamId, Method, Path, Headers)
                catch
                    Class:Reason:Stack ->
                        error_logger:error_msg(
                            "HTTP/3 handler error: ~p:~p~n~p~n",
                            [Class, Reason, Stack]
                        )
                end
            end)
    end.
