%%% -*- erlang -*-
%%%
%%% QUIC ACK Frame Processing
%%% RFC 9000 Section 13 - Packetization and Reliability
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC ACK frame generation and processing.
%%%
%%% This module handles:
%%% - Tracking received packet numbers
%%% - Generating ACK frames with ranges
%%% - Processing incoming ACK frames
%%% - ACK delay calculation
%%%
%%% == ACK Ranges ==
%%%
%%% ACK ranges are stored as a list of {Start, End} tuples where Start =&lt; End.
%%% The list is sorted in descending order by Start.
%%% Example: [{100, 105}, {90, 95}, {80, 82}] acknowledges packets
%%% 100-105, 90-95, and 80-82.
%%%

-module(quic_ack).

-include("quic.hrl").

-export([
    %% ACK state management
    new/0,

    %% Packet reception tracking
    record_received/2,
    record_received/3,

    %% ACK frame generation
    generate_ack/1,
    generate_ack/2,
    needs_ack/1,
    mark_ack_sent/1,

    %% ACK frame processing
    process_ack/2,
    process_ack/3,

    %% ACK frame utilities (shared with quic_loss)
    ack_frame_to_pn_list/3,
    ack_frame_to_ranges/3,

    %% Queries
    largest_received/1,
    largest_acked/1,
    ack_ranges/1,
    ack_eliciting_in_flight/1
]).

%% ACK tracking state
-record(ack_state, {
    %% Receive tracking
    largest_recv :: non_neg_integer() | undefined,
    % monotonic milliseconds
    recv_time :: non_neg_integer() | undefined,
    ack_ranges = [] :: [{non_neg_integer(), non_neg_integer()}],

    %% Send tracking
    largest_acked :: non_neg_integer() | undefined,
    ack_eliciting_in_flight = 0 :: non_neg_integer(),

    %% ACK generation
    ack_pending = false :: boolean(),
    ack_eliciting_received = 0 :: non_neg_integer(),

    %% Configuration
    ack_delay_exponent = ?DEFAULT_ACK_DELAY_EXPONENT :: non_neg_integer(),
    max_ack_delay = ?DEFAULT_MAX_ACK_DELAY :: non_neg_integer()
}).

-opaque ack_state() :: #ack_state{}.
-export_type([ack_state/0]).

%% Maximum ACK range size to prevent memory exhaustion
-define(MAX_ACK_RANGE, 65536).

%%====================================================================
%% ACK State Management
%%====================================================================

%% @doc Create a new ACK tracking state.
-spec new() -> ack_state().
new() ->
    #ack_state{}.

%%====================================================================
%% Packet Reception Tracking
%%====================================================================

%% @doc Record that a packet was received.
-spec record_received(ack_state(), non_neg_integer()) -> ack_state().
record_received(State, PacketNumber) ->
    record_received(State, PacketNumber, true).

%% @doc Record that a packet was received, optionally marking it as ACK-eliciting.
-spec record_received(ack_state(), non_neg_integer(), boolean()) -> ack_state().
record_received(
    #ack_state{
        largest_recv = Largest,
        ack_ranges = Ranges,
        ack_eliciting_received = AckEliciting
    } = State,
    PacketNumber,
    IsAckEliciting
) ->
    Now = erlang:monotonic_time(millisecond),

    %% Update largest received
    {NewLargest, NewTime} =
        case Largest of
            undefined -> {PacketNumber, Now};
            L when PacketNumber > L -> {PacketNumber, Now};
            _ -> {Largest, State#ack_state.recv_time}
        end,

    %% Update ACK ranges
    NewRanges = add_to_ranges(PacketNumber, Ranges),

    %% Update ACK-eliciting count
    NewAckEliciting =
        case IsAckEliciting of
            true -> AckEliciting + 1;
            false -> AckEliciting
        end,

    State#ack_state{
        largest_recv = NewLargest,
        recv_time = NewTime,
        ack_ranges = NewRanges,
        ack_pending = IsAckEliciting orelse State#ack_state.ack_pending,
        ack_eliciting_received = NewAckEliciting
    }.

%%====================================================================
%% ACK Frame Generation
%%====================================================================

%% @doc Generate an ACK frame for the current state.
%% Returns {ok, AckFrame} or {error, no_packets}.
-spec generate_ack(ack_state()) -> {ok, term()} | {error, no_packets}.
generate_ack(State) ->
    generate_ack(State, erlang:monotonic_time(millisecond)).

%% @doc Generate an ACK frame with a specific timestamp.
-spec generate_ack(ack_state(), non_neg_integer()) -> {ok, term()} | {error, no_packets}.
generate_ack(#ack_state{largest_recv = undefined}, _Now) ->
    {error, no_packets};
generate_ack(
    #ack_state{
        largest_recv = Largest,
        recv_time = RecvTime,
        ack_ranges = Ranges,
        ack_delay_exponent = Exp
    },
    Now
) ->
    %% Calculate ACK delay in microseconds, then encode
    AckDelayUs = (Now - RecvTime) * 1000,
    AckDelayEncoded = AckDelayUs bsr Exp,

    %% Convert ranges to ACK frame format
    %% First range count is the number of packets in the first range - 1
    [{FirstStart, FirstEnd} | RestRanges] = Ranges,
    FirstAckRange = FirstEnd - FirstStart,

    %% Convert remaining ranges to gap/range pairs
    AckRanges = ranges_to_ack_ranges(FirstStart, RestRanges),

    AckFrame = {ack, Largest, AckDelayEncoded, FirstAckRange, AckRanges},
    {ok, AckFrame}.

%% @doc Check if an ACK needs to be sent.
-spec needs_ack(ack_state()) -> boolean().
needs_ack(#ack_state{ack_pending = Pending, ack_eliciting_received = Count}) ->
    Pending andalso Count > 0.

%% @doc Mark that an ACK was sent.
-spec mark_ack_sent(ack_state()) -> ack_state().
mark_ack_sent(State) ->
    State#ack_state{
        ack_pending = false,
        ack_eliciting_received = 0
    }.

%%====================================================================
%% ACK Frame Processing
%%====================================================================

%% @doc Process a received ACK frame.
%% Returns {NewState, AckedPackets} where AckedPackets is a list of
%% newly acknowledged packet numbers.
-spec process_ack(ack_state(), term()) ->
    {ack_state(), [non_neg_integer()]}.
process_ack(State, AckFrame) ->
    process_ack(State, AckFrame, #{}).

%% @doc Process a received ACK frame with sent packet info.
%% SentPackets is a map of PacketNumber => SentPacketInfo
-spec process_ack(ack_state(), term(), map()) ->
    {ack_state(), [non_neg_integer()]} | {error, ack_range_too_large}.
process_ack(State, {ack, LargestAcked, _AckDelay, FirstRange, AckRanges}, SentPackets) ->
    %% Build list of acknowledged packet numbers
    case ack_frame_to_pn_list(LargestAcked, FirstRange, AckRanges) of
        {error, _} = Error ->
            Error;
        AckedPNs ->
            %% Filter to only packets we actually sent
            NewlyAcked =
                case maps:size(SentPackets) of
                    0 -> AckedPNs;
                    _ -> [PN || PN <- AckedPNs, maps:is_key(PN, SentPackets)]
                end,

            %% Update largest acked
            NewLargestAcked =
                case State#ack_state.largest_acked of
                    undefined -> LargestAcked;
                    Old when LargestAcked > Old -> LargestAcked;
                    Old -> Old
                end,

            %% Update ACK-eliciting in flight count
            AckElicitingAcked = length([
                PN
             || PN <- NewlyAcked,
                maps:is_key(PN, SentPackets),
                is_ack_eliciting(maps:get(PN, SentPackets))
            ]),
            NewInFlight = max(0, State#ack_state.ack_eliciting_in_flight - AckElicitingAcked),

            NewState = State#ack_state{
                largest_acked = NewLargestAcked,
                ack_eliciting_in_flight = NewInFlight
            },

            {NewState, NewlyAcked}
    end;
process_ack(
    State, {ack_ecn, LargestAcked, AckDelay, FirstRange, AckRanges, ECT0, ECT1, ECNCE}, SentPackets
) ->
    %% Process ACK and return ECN counts for congestion control
    {NewState, NewlyAcked} = process_ack(
        State, {ack, LargestAcked, AckDelay, FirstRange, AckRanges}, SentPackets
    ),
    {NewState, NewlyAcked, {ecn, ECT0, ECT1, ECNCE}}.

%%====================================================================
%% Queries
%%====================================================================

%% @doc Get the largest received packet number.
-spec largest_received(ack_state()) -> non_neg_integer() | undefined.
largest_received(#ack_state{largest_recv = L}) -> L.

%% @doc Get the largest acknowledged packet number.
-spec largest_acked(ack_state()) -> non_neg_integer() | undefined.
largest_acked(#ack_state{largest_acked = L}) -> L.

%% @doc Get the current ACK ranges.
-spec ack_ranges(ack_state()) -> [{non_neg_integer(), non_neg_integer()}].
ack_ranges(#ack_state{ack_ranges = R}) -> R.

%% @doc Get the number of ACK-eliciting packets in flight.
-spec ack_eliciting_in_flight(ack_state()) -> non_neg_integer().
ack_eliciting_in_flight(#ack_state{ack_eliciting_in_flight = N}) -> N.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Add a packet number to the ACK ranges
add_to_ranges(PN, []) ->
    [{PN, PN}];
add_to_ranges(PN, [{_Start, End} | _Rest] = Ranges) when PN > End + 1 ->
    %% New range before current
    [{PN, PN} | Ranges];
add_to_ranges(PN, [{Start, End} | Rest]) when PN =:= End + 1 ->
    %% Extend current range upward
    [{Start, PN} | Rest];
add_to_ranges(PN, [{Start, End} | Rest]) when PN >= Start, PN =< End ->
    %% Already in range
    [{Start, End} | Rest];
add_to_ranges(PN, [{Start, End} | Rest]) when PN =:= Start - 1 ->
    %% Extend current range downward, possibly merge with next
    merge_ranges([{PN, End} | Rest]);
add_to_ranges(PN, [Range | Rest]) ->
    %% Check remaining ranges
    [Range | add_to_ranges(PN, Rest)].

%% Merge adjacent ranges
merge_ranges([{S1, E1}, {S2, E2} | Rest]) when E2 + 1 >= S1 ->
    merge_ranges([{S2, max(E1, E2)} | Rest]);
merge_ranges(Ranges) ->
    Ranges.

%% Convert internal ranges to ACK frame gap/range format
ranges_to_ack_ranges(_PrevStart, []) ->
    [];
ranges_to_ack_ranges(PrevStart, [{Start, End} | Rest]) ->
    %% Gap is the number of missing packets between ranges - 1
    Gap = PrevStart - End - 2,
    %% Range is the number of packets in this range - 1
    Range = End - Start,
    [{Gap, Range} | ranges_to_ack_ranges(Start, Rest)].

%% Convert ACK frame format back to list of packet numbers
%% Returns list of packet numbers or {error, ack_range_too_large}
ack_frame_to_pn_list(LargestAcked, FirstRange, AckRanges) ->
    %% First range: LargestAcked - FirstRange to LargestAcked
    FirstEnd = LargestAcked,
    FirstStart = LargestAcked - FirstRange,
    case FirstEnd - FirstStart > ?MAX_ACK_RANGE of
        true ->
            {error, ack_range_too_large};
        false ->
            FirstPNs = lists:seq(FirstStart, FirstEnd),
            %% Process remaining ranges
            case ack_ranges_to_pn_list(FirstStart, AckRanges) of
                {error, _} = Error -> Error;
                RestPNs -> FirstPNs ++ RestPNs
            end
    end.

ack_ranges_to_pn_list(_PrevStart, []) ->
    [];
ack_ranges_to_pn_list(PrevStart, [{Gap, Range} | Rest]) ->
    %% End of this range
    End = PrevStart - Gap - 2,
    Start = End - Range,
    case End - Start > ?MAX_ACK_RANGE of
        true ->
            {error, ack_range_too_large};
        false ->
            PNs = lists:seq(Start, End),
            case ack_ranges_to_pn_list(Start, Rest) of
                {error, _} = Error -> Error;
                RestPNs -> PNs ++ RestPNs
            end
    end.

%% @doc Convert ACK frame to list of ranges instead of expanded list.
%% Returns a list of `{Start, End}' tuples where Start is less than or equal to End.
%% Much more efficient than ack_frame_to_pn_list for large ranges.
%% Example: `{100, 5, [{2, 3}]}' becomes `[{95, 100}, {89, 92}]'
-spec ack_frame_to_ranges(non_neg_integer(), non_neg_integer(), list()) ->
    [{non_neg_integer(), non_neg_integer()}] | {error, ack_range_too_large}.
ack_frame_to_ranges(LargestAcked, FirstRange, AckRanges) ->
    %% First range: LargestAcked - FirstRange to LargestAcked
    FirstEnd = LargestAcked,
    FirstStart = LargestAcked - FirstRange,
    case FirstEnd - FirstStart > ?MAX_ACK_RANGE of
        true ->
            {error, ack_range_too_large};
        false ->
            FirstRangeT = {FirstStart, FirstEnd},
            case ack_ranges_to_range_list(FirstStart, AckRanges) of
                {error, _} = Error -> Error;
                RestRanges -> [FirstRangeT | RestRanges]
            end
    end.

ack_ranges_to_range_list(_PrevStart, []) ->
    [];
ack_ranges_to_range_list(PrevStart, [{Gap, Range} | Rest]) ->
    %% End of this range
    End = PrevStart - Gap - 2,
    Start = End - Range,
    case End - Start > ?MAX_ACK_RANGE of
        true ->
            {error, ack_range_too_large};
        false ->
            RangeT = {Start, End},
            case ack_ranges_to_range_list(Start, Rest) of
                {error, _} = Error -> Error;
                RestRanges -> [RangeT | RestRanges]
            end
    end.

%% Check if a sent packet info indicates ACK-eliciting
is_ack_eliciting(#sent_packet{ack_eliciting = AE}) ->
    AE;
is_ack_eliciting(Info) when is_map(Info) ->
    maps:get(ack_eliciting, Info, false);
is_ack_eliciting(_) ->
    false.
