%%% -*- erlang -*-
%%%
%%% QUIC Loss Detection
%%% RFC 9002 - Loss Detection and Congestion Control
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC loss detection implementation.
%%%
%%% This module implements:
%%% - Packet loss detection using time and packet thresholds
%%% - RTT estimation (smoothed RTT, RTT variance)
%%% - Probe Timeout (PTO) calculation
%%% - Loss detection timer management
%%%
%%% == Loss Detection Methods ==
%%%
%%% 1. Packet Threshold: A packet is lost if a packet sent more than
%%%    kPacketThreshold (3) later has been acknowledged.
%%%
%%% 2. Time Threshold: A packet is lost if it was sent more than
%%%    max(kTimeThreshold * smoothed_rtt, kGranularity) ago and a
%%%    later packet has been acknowledged.
%%%

-module(quic_loss).

-include("quic.hrl").

-export([
    reset_for_new_path/1,
    %% Loss detection state
    new/0,
    new/1,

    %% Packet tracking
    on_packet_sent/4,
    on_packet_sent/5,
    on_packet_sent/6,
    on_ack_received/3,

    %% Retransmission
    retransmittable_frames/1,
    stream_has_unacked_below/3,

    %% Loss detection
    detect_lost_packets/2,
    get_loss_time_and_space/1,

    %% RTT
    update_rtt/3,
    smoothed_rtt/1,
    rtt_var/1,
    latest_rtt/1,
    min_rtt/1,

    %% PTO
    get_pto/1,
    on_pto_expired/1,

    %% Queries
    sent_packets/1,
    bytes_in_flight/1,
    last_progress/1,
    pto_count/1,
    oldest_unacked/1,
    has_rtt_sample/1
]).

%% Constants from RFC 9002
-define(PACKET_THRESHOLD, 3).
% 9/8
-define(TIME_THRESHOLD, 1.125).
% 1 millisecond
-define(MAX_PTO_MS, 5000).
-define(GRANULARITY, 1).
% RFC 9002 default is 333ms, but 100ms is more aggressive for faster ramp-up
-define(DEFAULT_INITIAL_RTT, 100).

%% Loss detection state.
%%
%% `sent_q' is an oldest-first queue of #sent_packet{}. Because sent
%% packet numbers are strictly monotonically increasing, the queue's
%% insertion order is also PN order and time_sent order, so:
%%   - on_packet_sent: queue:in/2 at the tail (amortised O(1))
%%   - oldest unacked: queue:peek/1 at the head (O(1))
%%   - loss-time / ACK classification: walk head to tail, stopping
%%     once PNs exceed the relevant threshold.
%% This replaces the previous dual map + gb_sets representation,
%% which paid O(log n) per send/ack/loss-scan and showed up in the
%% profile as the dominant CPU cost (gb_sets:*).
-record(loss_state, {
    sent_q = queue:new() :: queue:queue(#sent_packet{}),

    %% RTT estimation
    latest_rtt = 0 :: non_neg_integer(),
    smoothed_rtt = ?DEFAULT_INITIAL_RTT :: non_neg_integer(),
    rtt_var = ?DEFAULT_INITIAL_RTT div 2 :: non_neg_integer(),
    min_rtt = infinity :: non_neg_integer() | infinity,
    first_rtt_sample = false :: boolean(),

    %% Loss detection
    loss_time = undefined :: non_neg_integer() | undefined,
    time_of_last_ack = undefined :: non_neg_integer() | undefined,

    %% When the current outstanding burst started: set whenever an
    %% ack-eliciting packet is sent while nothing was in flight. Used
    %% together with time_of_last_ack as the anchor for the disconnect
    %% timeout, so a fresh send after a quiet period cannot trip it.
    outstanding_since = undefined :: non_neg_integer() | undefined,

    %% PTO
    pto_count = 0 :: non_neg_integer(),

    %% Bytes in flight
    bytes_in_flight = 0 :: non_neg_integer(),

    %% Configuration
    max_ack_delay = ?DEFAULT_MAX_ACK_DELAY :: non_neg_integer()
}).

-opaque loss_state() :: #loss_state{}.
-export_type([loss_state/0]).

%% RFC 9002 §9.4 path-change reset: RTT and PTO state belong to the
%% old path, but the sent-packet tracking must survive - dropping it
%% orphans every in-flight packet (no ACK match, no loss declaration,
%% no PTO since bytes_in_flight reads 0) and any lost data in that set
%% is never retransmitted.
-spec reset_for_new_path(loss_state() | undefined) -> loss_state().
reset_for_new_path(undefined) ->
    new();
reset_for_new_path(#loss_state{} = S) ->
    S#loss_state{
        latest_rtt = 0,
        smoothed_rtt = ?DEFAULT_INITIAL_RTT,
        rtt_var = ?DEFAULT_INITIAL_RTT div 2,
        min_rtt = infinity,
        first_rtt_sample = false,
        pto_count = 0,
        loss_time = undefined
    }.

%%====================================================================
%% Loss Detection State
%%====================================================================

%% @doc Create a new loss detection state.
-spec new() -> loss_state().
new() ->
    new(#{}).

%% @doc Create a new loss detection state with options.
%% Options:
%%   - max_ack_delay: Maximum ACK delay (default: 25ms)
%%   - initial_rtt: Initial RTT estimate in ms (default: 100ms)
-spec new(map()) -> loss_state().
new(Opts) ->
    InitialRTT = maps:get(initial_rtt, Opts, ?DEFAULT_INITIAL_RTT),
    #loss_state{
        smoothed_rtt = InitialRTT,
        rtt_var = InitialRTT div 2,
        max_ack_delay = maps:get(max_ack_delay, Opts, ?DEFAULT_MAX_ACK_DELAY)
    }.

%%====================================================================
%% Packet Tracking
%%====================================================================

%% @doc Record that a packet was sent (without frames).
-spec on_packet_sent(loss_state(), non_neg_integer(), non_neg_integer(), boolean()) ->
    loss_state().
on_packet_sent(State, PacketNumber, Size, AckEliciting) ->
    on_packet_sent(State, PacketNumber, Size, AckEliciting, []).

%% @doc Record that a packet was sent with frames. Samples the send
%% time itself. Callers that already hold a Now should use
%% on_packet_sent/6 to avoid a duplicate monotonic_time/1 BIF call.
-spec on_packet_sent(loss_state(), non_neg_integer(), non_neg_integer(), boolean(), [term()]) ->
    loss_state().
on_packet_sent(State, PacketNumber, Size, AckEliciting, Frames) ->
    Now = erlang:monotonic_time(millisecond),
    on_packet_sent(State, PacketNumber, Size, AckEliciting, Frames, Now).

%% @doc Like on_packet_sent/5 but uses the caller-supplied monotonic
%% millisecond timestamp. The connection send loop reuses one Now
%% per packet for both loss tracking and last_activity, saving a
%% BIF call.
-spec on_packet_sent(
    loss_state(),
    non_neg_integer(),
    non_neg_integer(),
    boolean(),
    [term()],
    integer()
) -> loss_state().
on_packet_sent(
    #loss_state{
        sent_q = Q,
        bytes_in_flight = InFlight
    } = State,
    PacketNumber,
    Size,
    AckEliciting,
    Frames,
    Now
) ->
    SentPacket = #sent_packet{
        pn = PacketNumber,
        time_sent = Now,
        ack_eliciting = AckEliciting,
        in_flight = true,
        size = Size,
        frames = Frames
    },
    NewInFlight =
        case AckEliciting of
            true -> InFlight + Size;
            false -> InFlight
        end,
    OutstandingSince =
        case AckEliciting andalso InFlight =:= 0 of
            true -> Now;
            false -> State#loss_state.outstanding_since
        end,
    %% NOTE: pto_count is NOT reset here per RFC 9002.
    %% PTO count is only reset when receiving an ACK (in on_ack_received).
    %% Resetting on send would break exponential backoff for probe retransmissions.
    State#loss_state{
        sent_q = queue:in(SentPacket, Q),
        bytes_in_flight = NewInFlight,
        outstanding_since = OutstandingSince
    }.

%% @doc Process an ACK frame.
%% Returns {NewState, AckedPackets, LostPackets, AckMeta} or {error, ack_range_too_large}
%% AckMeta is a map containing:
%%   - acked_bytes: total bytes from ack-eliciting packets that were acknowledged
%%   - largest_ae_time: sent_time of the largest ack-eliciting packet acknowledged
%%
%% Implementation: three passes over the sent queue.
%%   1. classify_ack_q: split queue into (acked, kept-unacked) by the
%%      ACK ranges in a single head-to-tail walk. Stops early once we
%%      pass LargestAcked.
%%   2. maybe_update_rtt: RTT sample derived from the largest acked
%%      ack-eliciting packet, if present.
%%   3. detect_lost_q: over the kept survivors, apply packet-threshold
%%      and time-threshold loss criteria using the freshly updated SRTT.
-spec on_ack_received(loss_state(), term(), non_neg_integer()) ->
    {loss_state(), [#sent_packet{}], [#sent_packet{}], map()} | {error, ack_range_too_large}.
on_ack_received(State, {ack, LargestAcked, AckDelay, FirstRange, AckRanges}, Now) ->
    case quic_ack:ack_frame_to_ranges(LargestAcked, FirstRange, AckRanges) of
        {error, _} = Error ->
            Error;
        AckedRanges ->
            %% Phase 1: walk the sent queue ONLY through packets with
            %% PN =< LargestAcked. Those are the ones this ACK can
            %% decide about; anything newer stays in the tail untouched.
            %% This keeps per-ACK work proportional to the ACK window,
            %% not to the full outstanding queue.
            {AckedList, KeptAccList, AckedBytes, MaxAckEliciting, TailQ} =
                classify_ack_head(
                    State#loss_state.sent_q, LargestAcked, AckedRanges, [], [], 0, undefined
                ),

            NewState1 = maybe_update_rtt(State, LargestAcked, AckedList, AckDelay, Now),

            %% Phase 2: loss detection over the survivors from phase 1
            %% (KeptAccList is newest-first, reverse to oldest-first so
            %% largest-lost bookkeeping works).
            KeptList = lists:reverse(KeptAccList),
            {LostList, SurvHeadQ, LostBytes, LargestLostSentTime} =
                detect_lost_q(
                    KeptList,
                    max(NewState1#loss_state.smoothed_rtt, NewState1#loss_state.latest_rtt),
                    LargestAcked,
                    Now,
                    [],
                    queue:new(),
                    0,
                    undefined
                ),

            %% Phase 3: stitch survivors back together with the untouched
            %% tail (packets with PN > LargestAcked).
            NewQ = queue:join(SurvHeadQ, TailQ),

            NewInFlight = max(0, State#loss_state.bytes_in_flight - AckedBytes - LostBytes),
            NewState2 = NewState1#loss_state{
                sent_q = NewQ,
                bytes_in_flight = NewInFlight,
                time_of_last_ack = Now,
                pto_count = 0
            },

            LargestAETime =
                case MaxAckEliciting of
                    undefined -> Now;
                    {_AckPN, AckTimeSent} -> AckTimeSent
                end,
            AckMeta = #{
                acked_bytes => AckedBytes,
                largest_ae_time => LargestAETime,
                has_ack_eliciting => MaxAckEliciting =/= undefined,
                lost_bytes => LostBytes,
                largest_lost_sent_time => LargestLostSentTime
            },

            {NewState2, AckedList, LostList, AckMeta}
    end;
on_ack_received(State, {ack_ecn, LargestAcked, AckDelay, FirstRange, AckRanges, _, _, _}, Now) ->
    on_ack_received(State, {ack, LargestAcked, AckDelay, FirstRange, AckRanges}, Now).

%% Pop packets from the head of the queue while PN =< LargestAcked,
%% classifying each as acked (in ranges) or kept-unacked.
%% Returns {AckedList, KeptAccList (newest-first), AckedBytes,
%%          MaxAckEliciting, TailQ} where TailQ is the remainder of
%% the sent queue that was never touched (PN > LargestAcked or empty).
classify_ack_head(Q, LargestAcked, Ranges, AckedAcc, KeptAcc, AckedBytes, MaxAE) ->
    case queue:out(Q) of
        {empty, _} ->
            {AckedAcc, KeptAcc, AckedBytes, MaxAE, Q};
        {{value, #sent_packet{pn = PN}}, _Q1} when PN > LargestAcked ->
            %% Stop: this packet (and everything after) can't be decided
            %% by this ACK. Push back and return Q unchanged.
            {AckedAcc, KeptAcc, AckedBytes, MaxAE, Q};
        {{value, #sent_packet{pn = PN, size = Size, ack_eliciting = AE, time_sent = TS} = P}, Q1} ->
            case pn_in_ranges(PN, Ranges) of
                true ->
                    {NewBytes, NewMaxAE} = update_acked_stats(
                        AE, Size, PN, TS, AckedBytes, MaxAE
                    ),
                    classify_ack_head(
                        Q1, LargestAcked, Ranges, [P | AckedAcc], KeptAcc, NewBytes, NewMaxAE
                    );
                false ->
                    classify_ack_head(
                        Q1, LargestAcked, Ranges, AckedAcc, [P | KeptAcc], AckedBytes, MaxAE
                    )
            end
    end.

%% Look up the largest-acked ack-eliciting packet's time_sent in the
%% acked list, if present. Used only to drive the RTT sample update.
maybe_update_rtt(State, LargestAcked, AckedList, AckDelay, Now) ->
    case lists:keyfind(LargestAcked, #sent_packet.pn, AckedList) of
        #sent_packet{ack_eliciting = true, time_sent = TS} ->
            LatestRTT = Now - TS,
            AckDelayMs = ack_delay_to_ms(AckDelay, State),
            update_rtt(State, LatestRTT, AckDelayMs);
        _ ->
            State
    end.

%%====================================================================
%% Loss Detection
%%====================================================================

%% @doc Detect lost packets based on time and packet thresholds.
%% Scans the sent queue head-to-tail (oldest first) and splits into
%% {Lost, Surviving}. Returns the new loss_state and the lost packets.
-spec detect_lost_packets(loss_state(), non_neg_integer()) ->
    {loss_state(), [#sent_packet{}]}.
detect_lost_packets(
    #loss_state{sent_q = Q, smoothed_rtt = SRTT, latest_rtt = LatestRTT} = State,
    LargestAcked
) ->
    Now = erlang:monotonic_time(millisecond),
    SentList = queue:to_list(Q),
    %% RFC 9002 §6.1.2: the time threshold uses max(smoothed_rtt,
    %% latest_rtt). With the EWMA alone, an RTT spike that outruns it
    %% (receiver queueing, bufferbloat) mass-declares in-flight packets
    %% lost while their ACKs are merely late; each spurious loss both
    %% retransmits data and collapses the congestion window.
    RTT = max(SRTT, LatestRTT),
    {LostPackets, SurvQ, LostBytes, _LargestLostSentTime} =
        detect_lost_q(SentList, RTT, LargestAcked, Now, [], queue:new(), 0, undefined),
    NewState = State#loss_state{
        sent_q = SurvQ,
        bytes_in_flight = max(0, State#loss_state.bytes_in_flight - LostBytes)
    },
    {NewState, LostPackets}.

%% Core loss-detection walk over an oldest-first list of sent packets.
%% Returns {LostList, SurvivingQ, LostBytes, LargestLostSentTime} where
%% LargestLostSentTime is the time_sent of the highest-PN lost packet
%% (used by the CC congestion-event reporter).
detect_lost_q([], _SRTT, _LargestAcked, _Now, LostAcc, SurvQ, LostBytes, LargestLost) ->
    {LostAcc, SurvQ, LostBytes, largest_lost_ts(LargestLost)};
detect_lost_q(
    [#sent_packet{pn = PN} = P | Rest], _SRTT, LargestAcked, _Now, LostAcc, SurvQ, LostBytes, LL
) when
    PN >= LargestAcked
->
    %% PN >= LargestAcked: can't be declared lost yet. Keep this and
    %% every subsequent packet (they are newer still).
    SurvQ1 = lists:foldl(fun queue:in/2, queue:in(P, SurvQ), Rest),
    {LostAcc, SurvQ1, LostBytes, largest_lost_ts(LL)};
detect_lost_q(
    [
        #sent_packet{
            pn = PN, size = Size, in_flight = true, ack_eliciting = AE, time_sent = TS
        } = P
        | Rest
    ],
    SRTT,
    LargestAcked,
    Now,
    LostAcc,
    SurvQ,
    LostBytes,
    LL
) ->
    LossDelay = max(trunc(?TIME_THRESHOLD * SRTT), ?GRANULARITY),
    LossThreshold = LargestAcked - ?PACKET_THRESHOLD + 1,
    case (PN < LossThreshold) orelse ((Now - TS) > LossDelay) of
        true ->
            NewBytes =
                case AE of
                    true -> LostBytes + Size;
                    false -> LostBytes
                end,
            %% Only ack-eliciting losses drive the congestion event
            %% (largest_lost_sent_time feeds on_congestion_event). A lost
            %% non-ack-eliciting packet, a PMTU probe in particular, is
            %% not a congestion signal (RFC 9000 §14.4).
            NewLL =
                case AE of
                    false ->
                        LL;
                    true ->
                        case LL of
                            undefined -> {PN, TS};
                            {OldPN, _} when PN > OldPN -> {PN, TS};
                            _ -> LL
                        end
                end,
            detect_lost_q(Rest, SRTT, LargestAcked, Now, [P | LostAcc], SurvQ, NewBytes, NewLL);
        false ->
            detect_lost_q(
                Rest, SRTT, LargestAcked, Now, LostAcc, queue:in(P, SurvQ), LostBytes, LL
            )
    end;
detect_lost_q(
    [#sent_packet{} = P | Rest], SRTT, LargestAcked, Now, LostAcc, SurvQ, LostBytes, LL
) ->
    %% Not in_flight (defensive, shouldn't happen for queue-managed packets).
    detect_lost_q(Rest, SRTT, LargestAcked, Now, LostAcc, queue:in(P, SurvQ), LostBytes, LL).

largest_lost_ts(undefined) -> undefined;
largest_lost_ts({_PN, TS}) -> TS.

%% @doc Get the loss time for setting timers.
%% The queue is oldest-first, so the earliest in_flight packet is at
%% the head; this turns the previous O(n) map fold into an O(1) head
%% peek in the common case (head is in_flight).
-spec get_loss_time_and_space(loss_state()) ->
    {non_neg_integer() | undefined, atom()}.
get_loss_time_and_space(#loss_state{sent_q = Q, smoothed_rtt = SRTT, latest_rtt = LatestRTT}) ->
    LossDelay = max(trunc(?TIME_THRESHOLD * max(SRTT, LatestRTT)), ?GRANULARITY),
    case earliest_in_flight_time(queue:to_list(Q)) of
        undefined -> {undefined, initial};
        TimeSent -> {TimeSent + LossDelay, initial}
    end.

earliest_in_flight_time([]) -> undefined;
earliest_in_flight_time([#sent_packet{time_sent = TS, in_flight = true} | _]) -> TS;
earliest_in_flight_time([_ | Rest]) -> earliest_in_flight_time(Rest).

%%====================================================================
%% RTT Estimation (RFC 9002 Section 5)
%%====================================================================

%% @doc Update RTT estimates with a new sample.
-spec update_rtt(loss_state(), non_neg_integer(), non_neg_integer()) -> loss_state().
update_rtt(#loss_state{first_rtt_sample = false} = State, LatestRTT, _AckDelay) ->
    %% First RTT sample
    State#loss_state{
        latest_rtt = LatestRTT,
        smoothed_rtt = LatestRTT,
        rtt_var = LatestRTT div 2,
        min_rtt = LatestRTT,
        first_rtt_sample = true
    };
update_rtt(
    #loss_state{
        smoothed_rtt = SRTT,
        rtt_var = RTTVAR,
        min_rtt = MinRTT,
        max_ack_delay = MaxAckDelay
    } = State,
    LatestRTT,
    AckDelay
) ->
    %% Update min RTT
    NewMinRTT = min(MinRTT, LatestRTT),

    %% Adjust for ACK delay
    AdjustedRTT =
        case LatestRTT > NewMinRTT + AckDelay of
            true -> LatestRTT - min(AckDelay, MaxAckDelay);
            false -> LatestRTT
        end,

    %% Update smoothed RTT and variance (RFC 9002 Section 5.3)
    %% rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
    %% smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
    NewRTTVAR = (3 * RTTVAR + abs(SRTT - AdjustedRTT)) div 4,
    NewSRTT = (7 * SRTT + AdjustedRTT) div 8,

    State#loss_state{
        latest_rtt = LatestRTT,
        smoothed_rtt = NewSRTT,
        rtt_var = NewRTTVAR,
        min_rtt = NewMinRTT
    }.

%% @doc Get the smoothed RTT.
-spec smoothed_rtt(loss_state()) -> non_neg_integer().
smoothed_rtt(#loss_state{smoothed_rtt = SRTT}) -> SRTT.

%% @doc Get the RTT variance.
-spec rtt_var(loss_state()) -> non_neg_integer().
rtt_var(#loss_state{rtt_var = RTTVAR}) -> RTTVAR.

%% @doc Get the latest RTT sample.
-spec latest_rtt(loss_state()) -> non_neg_integer().
latest_rtt(#loss_state{latest_rtt = L}) -> L.

%% @doc Get the minimum RTT.
-spec min_rtt(loss_state()) -> non_neg_integer() | infinity.
min_rtt(#loss_state{min_rtt = M}) -> M.

%%====================================================================
%% Probe Timeout (RFC 9002 Section 6.2)
%%====================================================================

%% @doc Calculate the Probe Timeout.
%% PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
-spec get_pto(loss_state()) -> non_neg_integer().
get_pto(#loss_state{
    smoothed_rtt = SRTT,
    rtt_var = RTTVAR,
    max_ack_delay = MaxAckDelay,
    pto_count = PTOCount
}) ->
    PTO = SRTT + max(4 * RTTVAR, ?GRANULARITY) + MaxAckDelay,
    %% Exponential backoff
    %% Exponential backoff, capped: uncapped doubling reaches tens of
    %% seconds after a loss streak, and a probe that arrives after the
    %% peer's patience is a probe that never happened. Probes are tiny,
    %% so a bounded worst-case interval costs nothing while keeping
    %% recovery inside real-world request timeouts.
    min(PTO bsl PTOCount, ?MAX_PTO_MS).

%% @doc Handle PTO expiration.
-spec on_pto_expired(loss_state()) -> loss_state().
on_pto_expired(#loss_state{pto_count = Count} = State) ->
    State#loss_state{pto_count = Count + 1}.

%%====================================================================
%% Queries
%%====================================================================

%% @doc Get all sent packets.
%% Returned as a map for API compatibility. Built on demand from the
%% queue; intended for tests and diagnostics, not the hot path.
-spec sent_packets(loss_state()) -> #{non_neg_integer() => #sent_packet{}}.
sent_packets(#loss_state{sent_q = Q}) ->
    maps:from_list([{P#sent_packet.pn, P} || P <- queue:to_list(Q)]).

%% @doc Get bytes currently in flight.
-spec bytes_in_flight(loss_state()) -> non_neg_integer().
bytes_in_flight(#loss_state{bytes_in_flight = B}) -> B.

%% @doc Get current PTO count.
-spec pto_count(loss_state()) -> non_neg_integer().
pto_count(#loss_state{pto_count = C}) -> C.

%% @doc Latest sign of forward progress for the disconnect timeout: the
%% last received ACK, or the start of the current outstanding burst,
%% whichever is later. undefined until either has happened.
-spec last_progress(loss_state()) -> non_neg_integer() | undefined.
last_progress(#loss_state{time_of_last_ack = undefined, outstanding_since = O}) -> O;
last_progress(#loss_state{time_of_last_ack = A, outstanding_since = undefined}) -> A;
last_progress(#loss_state{time_of_last_ack = A, outstanding_since = O}) -> max(A, O).

%% @doc Get the oldest unacked packet (for PTO probe selection).
%% Returns {ok, #sent_packet{}} or none. Head of the sent queue is
%% by construction the oldest in-flight packet.
-spec oldest_unacked(loss_state()) -> {ok, #sent_packet{}} | none.
oldest_unacked(#loss_state{sent_q = Q}) ->
    case queue:peek(Q) of
        empty -> none;
        {value, Packet} -> {ok, Packet}
    end.

%% @doc Check if we have received a real RTT sample.
%% Returns false until the first ACK provides a real RTT measurement.
-spec has_rtt_sample(loss_state()) -> boolean().
has_rtt_sample(#loss_state{first_rtt_sample = HasSample}) -> HasSample.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Update acked bytes + track the largest ack-eliciting acked PN so
%% the caller can derive an RTT sample from that packet's time_sent.
%% Non-ack-eliciting packets don't contribute to bytes_in_flight, so
%% we also don't count them toward acked bytes here.
update_acked_stats(true, Size, PN, TimeSent, BytesAcc, undefined) ->
    {BytesAcc + Size, {PN, TimeSent}};
update_acked_stats(true, Size, PN, TimeSent, BytesAcc, {OldPN, _}) when PN > OldPN ->
    {BytesAcc + Size, {PN, TimeSent}};
update_acked_stats(true, Size, _PN, _TimeSent, BytesAcc, MaxAE) ->
    {BytesAcc + Size, MaxAE};
update_acked_stats(false, _Size, _PN, _TimeSent, BytesAcc, MaxAE) ->
    {BytesAcc, MaxAE}.

%% Check if a packet number is in any of the acknowledged ranges.
%% Ranges is a list of {Start, End} tuples where Start =< End,
%% sorted in descending order (highest PN first).
pn_in_ranges(_PN, []) ->
    false;
pn_in_ranges(PN, [{Start, End} | _Rest]) when PN >= Start, PN =< End ->
    true;
pn_in_ranges(PN, [{_Start, End} | _Rest]) when PN > End ->
    %% Early exit: ranges are sorted descending, so if PN > End of current range,
    %% it can't be in any subsequent range (they all have lower End values)
    false;
pn_in_ranges(PN, [_Range | Rest]) ->
    pn_in_ranges(PN, Rest).

%% Convert encoded ACK delay to milliseconds
ack_delay_to_ms(AckDelay, #loss_state{}) ->
    %% AckDelay is in microseconds after shifting by ack_delay_exponent
    %% Using default exponent of 3
    (AckDelay bsl ?DEFAULT_ACK_DELAY_EXPONENT) div 1000.

%%====================================================================
%% Retransmission Helpers
%%====================================================================

%% @doc Filter frames to get only retransmittable ones.
%% Per RFC 9002, PADDING, ACK, and CONNECTION_CLOSE frames are not retransmitted.
-spec retransmittable_frames([term()]) -> [term()].
retransmittable_frames(Frames) ->
    lists:filter(fun is_retransmittable/1, Frames).

%% True if any in-flight sent packet carries STREAM data for StreamId that
%% starts before ReliableSize. Data at/after ReliableSize is never retransmitted
%% for a RESET_STREAM_AT stream, so it does not gate the reliable obligation.
-spec stream_has_unacked_below(loss_state(), non_neg_integer(), non_neg_integer()) ->
    boolean().
stream_has_unacked_below(#loss_state{sent_q = Q}, StreamId, ReliableSize) ->
    lists:any(
        fun(#sent_packet{frames = Fs}) ->
            lists:any(
                fun
                    ({stream, S, Off, _Data, _Fin}) ->
                        S =:= StreamId andalso Off < ReliableSize;
                    (_) ->
                        false
                end,
                Fs
            )
        end,
        queue:to_list(Q)
    ).

%% Check if a frame is retransmittable
is_retransmittable(padding) -> false;
is_retransmittable({padding, _}) -> false;
is_retransmittable({ack, _, _, _}) -> false;
is_retransmittable({ack, _, _, _, _}) -> false;
is_retransmittable({ack_ecn, _, _, _, _, _, _, _}) -> false;
is_retransmittable({connection_close, _, _, _, _}) -> false;
%% DATAGRAM frames (RFC 9221) are unreliable and never retransmitted
is_retransmittable({datagram, _}) -> false;
is_retransmittable({datagram_with_length, _}) -> false;
is_retransmittable(_) -> true.
