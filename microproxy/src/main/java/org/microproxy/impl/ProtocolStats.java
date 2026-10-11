package org.microproxy.impl;

import java.util.concurrent.atomic.AtomicReferenceArray;
import org.microproxy.stats.Counter;
import org.microproxy.stats.Gauge;
import org.microproxy.stats.Histogram;
import org.microproxy.stats.StatsRegistry;

/**
 * The proxy's per-protocol and per-hook metrics, which {@link ProxyStats} holds: HTTP/2 and HTTP/3
 * codec stats by direction, QUIC connections by scope, transparent QUIC flows, SOCKS, MASQUE,
 * tunnels, WebSockets and the hooks. Like the rest of the proxy's metrics they are resolved once,
 * when the proxy starts, and kept in fields; with metrics off every one is a no-op.
 *
 * <p>Nothing here needs the optional codec or QUIC modules; the QUIC connections' stats are
 * {@link QuicStats}', which only HTTP/3 code loads.
 */
final class ProtocolStats {

    private ProtocolStats() {}

    // ---------------------------------------------------------------------------------------
    // http2.<direction>.*
    // ---------------------------------------------------------------------------------------

    /** {@code http2.<direction>.*}: an HTTP/2 codec's events, as Envoy's {@code http2.*} codec stats count them. */
    static final class Http2Stats {
        final Counter rxReset;
        final Counter txReset;
        final Counter goawaySent;
        final Counter goawayReceived;
        final Gauge streamsActive;
        final Counter headerOverflow;
        final Counter headersCbNoStream;
        final Counter emptyFramesFlood;
        final Counter priorityFramesFlood;
        final Counter windowUpdateFramesFlood;
        final Counter rapidResetFlood;
        final Counter outboundControlFlood;
        final Counter rxMessagingError;
        final Counter trailers;
        final Counter txFlushTimeout;
        final Counter settingsTimeout;
        final Counter streamFlowControlBlocked;
        final Counter connectionFlowControlBlocked;

        Http2Stats(StatsRegistry registry, String direction) {
            String p = "http2." + direction + ".";
            rxReset = registry.counter(p + "rx_reset", "RST_STREAM frames received");
            txReset = registry.counter(p + "tx_reset", "RST_STREAM frames sent");
            goawaySent = registry.counter(p + "goaway_sent", "GOAWAY frames sent");
            goawayReceived = registry.counter(p + "goaway_received", "GOAWAY frames received");
            streamsActive = registry.gauge(p + "streams_active", "Streams open");
            headerOverflow = registry.counter(p + "header_overflow", "Header lists over SETTINGS_MAX_HEADER_LIST_SIZE");
            headersCbNoStream = registry.counter(p + "headers_cb_no_stream", "HEADERS for a stream already closed");
            emptyFramesFlood = registry.counter(p + "inbound_empty_frames_flood",
                    "Connections closed for too many empty DATA frames or trailers");
            priorityFramesFlood = registry.counter(p + "inbound_priority_frames_flood",
                    "Connections closed for too many PRIORITY and RST_STREAM frames");
            windowUpdateFramesFlood = registry.counter(p + "inbound_window_update_frames_flood",
                    "Connections closed for too many WINDOW_UPDATE frames");
            rapidResetFlood = registry.counter(p + "inbound_rapid_reset_flood",
                    "Connections closed for too many streams reset or refused before their response (Rapid Reset)");
            outboundControlFlood = registry.counter(p + "outbound_control_flood",
                    "Connections closed for too many PING or SETTINGS frames, each of which needs an answer");
            rxMessagingError = registry.counter(p + "rx_messaging_error", "Malformed frames, header blocks or messages received");
            trailers = registry.counter(p + "trailers", "Trailers received");
            txFlushTimeout = registry.counter(p + "tx_flush_timeout", "Connections closed because writes made no progress");
            settingsTimeout = registry.counter(p + "settings_timeout", "Connections closed because SETTINGS went unacknowledged");
            streamFlowControlBlocked = registry.counter(p + "stream_flow_control_blocked",
                    "Times DATA waited for a stream's send window");
            connectionFlowControlBlocked = registry.counter(p + "connection_flow_control_blocked",
                    "Times DATA waited for the connection's send window");
        }
    }

    // ---------------------------------------------------------------------------------------
    // http3.<direction>.*
    // ---------------------------------------------------------------------------------------

    /** {@code http3.<direction>.*}: an HTTP/3 codec's events. */
    static final class Http3Stats {
        final Counter rxReset;
        final Counter txReset;
        final Counter goawaySent;
        final Counter goawayReceived;
        final Gauge streamsActive;
        final Counter qpackBlockedStreams;
        final Counter qpackDecoderErrors;
        final Counter unknownFrames;
        final Counter unknownStreamTypes;
        final Counter earlyDataRequests;
        final Counter tooEarly;
        final Counter tcpFallback;

        Http3Stats(StatsRegistry registry, String direction) {
            String p = "http3." + direction + ".";
            rxReset = registry.counter(p + "rx_reset", "Request streams the peer reset");
            txReset = registry.counter(p + "tx_reset", "Request streams the proxy reset");
            goawaySent = registry.counter(p + "goaway_sent", "GOAWAY frames sent");
            goawayReceived = registry.counter(p + "goaway_received", "GOAWAY frames received");
            streamsActive = registry.gauge(p + "streams_active", "Request streams open");
            qpackBlockedStreams = registry.counter(p + "qpack_blocked_streams",
                    "Field sections that waited for the QPACK encoder stream");
            qpackDecoderErrors = registry.counter(p + "qpack_decoder_errors", "Field sections QPACK could not decode");
            unknownFrames = registry.counter(p + "unknown_frames", "Frames of unknown types, and empty ones, received");
            unknownStreamTypes = registry.counter(p + "unknown_stream_types", "Unidirectional streams of unknown types received");
            if (direction.equals("downstream")) {
                earlyDataRequests = registry.counter(p + "early_data_requests", "Requests that arrived in 0-RTT data");
                tooEarly = registry.counter(p + "too_early_425", "Requests in 0-RTT data answered 425 Too Early");
                tcpFallback = StatsRegistry.NOOP.counter("none");
            } else {
                earlyDataRequests = StatsRegistry.NOOP.counter("none");
                tooEarly = StatsRegistry.NOOP.counter("none");
                tcpFallback = registry.counter(p + "tcp_fallback",
                        "Requests to a server known to speak HTTP/3 that went over TCP (its handshake failed, recently or now, or it took no new streams)");
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // quic_transparent.*, masque.quic.*
    // ---------------------------------------------------------------------------------------

    /**
     * The flows of QUIC that reaches the proxy without being sent to it ({@link QuicFlows}): {@code
     * quic_transparent.*} for the transparent listener's, {@code masque.quic.*} for the QUIC inside
     * CONNECT-UDP flows.
     */
    static final class QuicFlowStats {
        final Gauge flowsActive;
        final Gauge pendingInitials;
        final Counter interceptedTotal;
        final Counter relayedTotal;
        final Counter droppedCap;
        final Counter droppedMalformed;
        final Counter droppedTimeout;
        final Counter droppedRefused;
        final Counter relayRxBytes;
        final Counter relayTxBytes;

        QuicFlowStats(StatsRegistry registry, String prefix) {
            String p = prefix + ".";
            flowsActive = registry.gauge(p + "flows_active", "Client flows known: pending, intercepted or relayed");
            pendingInitials = registry.gauge(p + "pending_initials", "Flows whose ClientHello is being read or decided on");
            interceptedTotal = registry.counter(p + "intercepted_total", "Flows intercepted (as HTTP/3, or stream by stream)");
            relayedTotal = registry.counter(p + "relayed_total", "Flows relayed untouched");
            String help = "Datagrams of client flows dropped, by reason";
            droppedCap = registry.counter(p + "dropped_initials.cap", help);
            droppedMalformed = registry.counter(p + "dropped_initials.malformed", help);
            droppedTimeout = registry.counter(p + "dropped_initials.timeout", help);
            droppedRefused = registry.counter(p + "dropped_initials.refused", help);
            relayRxBytes = registry.counter(p + "relay_rx_bytes_total", "Bytes relayed from clients to servers, counted when relays end");
            relayTxBytes = registry.counter(p + "relay_tx_bytes_total", "Bytes relayed from servers to clients, counted when relays end");
        }
    }

    // ---------------------------------------------------------------------------------------
    // socks.*
    // ---------------------------------------------------------------------------------------

    /** {@code socks.*}: SOCKS clients, their authentication and the replies they got. */
    static final class SocksStats {
        /** Reply names by SOCKS5 code, 0 to 8: the tags of {@code replies}. */
        private static final String[] REPLIES = {"succeeded", "general_failure", "not_allowed", "network_unreachable",
            "host_unreachable", "connection_refused", "ttl_expired", "command_not_supported", "address_type_not_supported"};

        final Counter connectionsV4;
        final Counter connectionsV5;
        final Counter authFailures;
        final Counter commandNotSupported;
        private final Counter[] replies = new Counter[REPLIES.length];

        SocksStats(StatsRegistry registry) {
            connectionsV4 = registry.counter("socks.v4.connections_total", "SOCKS clients, by version");
            connectionsV5 = registry.counter("socks.v5.connections_total", "SOCKS clients, by version");
            authFailures = registry.counter("socks.auth_failures", "SOCKS clients refused by authentication");
            commandNotSupported = registry.counter("socks.command_not_supported", "SOCKS requests for a command other than CONNECT");
            for (int i = 0; i < REPLIES.length; i++) {
                replies[i] = registry.counter("socks.replies." + REPLIES[i], "Replies to SOCKS requests, by SOCKS5 reply code");
            }
        }

        /** Counts a reply with SOCKS5 code {@code code} (a SOCKS4 client's is counted by the code it stands for). */
        void reply(int code) {
            replies[code >= 0 && code < replies.length ? code : 1].inc();
        }
    }

    // ---------------------------------------------------------------------------------------
    // masque.*
    // ---------------------------------------------------------------------------------------

    /** {@code masque.*}: CONNECT-UDP flows; their datagrams and bytes are counted when they end. */
    static final class MasqueStats {
        final Gauge flowsActive;
        final Counter flowsTotal;
        final Counter datagramsRx;
        final Counter datagramsTx;
        final Counter capsulesRx;
        final Counter capsulesTx;
        final Counter datagramsDropped;
        final Counter rejectedLimit;
        final Counter rejectedPolicy;
        final Counter rxBytes;
        final Counter txBytes;
        final QuicFlowStats quic;

        MasqueStats(StatsRegistry registry) {
            flowsActive = registry.gauge("masque.udp_flows_active", "CONNECT-UDP flows open");
            flowsTotal = registry.counter("masque.udp_flows_total", "CONNECT-UDP flows accepted");
            datagramsRx = registry.counter("masque.datagrams_rx", "UDP payloads from clients, counted when flows end");
            datagramsTx = registry.counter("masque.datagrams_tx", "UDP payloads sent to clients, counted when flows end");
            capsulesRx = registry.counter("masque.capsules_rx", "DATAGRAM capsules from clients, counted when flows end");
            capsulesTx = registry.counter("masque.capsules_tx",
                    "DATAGRAM capsules sent to clients (for want of QUIC DATAGRAM frames), counted when flows end");
            datagramsDropped = registry.counter("masque.datagrams_dropped",
                    "Datagrams dropped because a flow's queue was full, counted when flows end");
            rejectedLimit = registry.counter("masque.flow_rejected.limit", "CONNECT-UDP requests refused, by reason");
            rejectedPolicy = registry.counter("masque.flow_rejected.policy", "CONNECT-UDP requests refused, by reason");
            rxBytes = registry.counter("masque.rx_bytes_total", "UDP payload bytes from clients, counted when flows end");
            txBytes = registry.counter("masque.tx_bytes_total", "UDP payload bytes to clients, counted when flows end");
            quic = new QuicFlowStats(registry, "masque.quic");
        }
    }

    // ---------------------------------------------------------------------------------------
    // tunnel.*, websocket.*
    // ---------------------------------------------------------------------------------------

    /** {@code tunnel.*}: byte tunnels (CONNECT, and TLS relayed undecrypted), by kind. */
    static final class TunnelStats {
        final Gauge active;
        final Counter h1Connect;
        final Counter h2Connect;
        final Counter h3Connect;
        final Counter socks;
        final Counter forwarded;
        final Counter raw;
        final Counter rxBytes;
        final Counter txBytes;
        final Histogram durationMs;

        TunnelStats(StatsRegistry registry) {
            active = registry.gauge("tunnel.active", "Tunnels open");
            String help = "Tunnels opened, by kind";
            h1Connect = registry.counter("tunnel.h1_connect.total", help);
            h2Connect = registry.counter("tunnel.h2_connect.total", help);
            h3Connect = registry.counter("tunnel.h3_connect.total", help);
            socks = registry.counter("tunnel.socks.total", help);
            forwarded = registry.counter("tunnel.forwarded.total", help);
            raw = registry.counter("tunnel.raw.total", help);
            rxBytes = registry.counter("tunnel.rx_bytes_total", "Bytes relayed from clients, counted when tunnels close");
            txBytes = registry.counter("tunnel.tx_bytes_total", "Bytes relayed to clients, counted when tunnels close");
            durationMs = registry.histogram("tunnel.duration_ms", "Milliseconds tunnels were open");
        }
    }

    /** {@code websocket.*}: WebSocket sessions, and the frames and messages of those the hooks watch. */
    static final class WebSocketStats {
        /** The close codes counted by name, 1000 to 1015; others are {@code other}. */
        private static final int FIRST_CODE = 1000;
        private static final int LAST_CODE = 1015;

        private final StatsRegistry registry;
        final Gauge sessionsActive;
        final Counter sessionsTotal;
        final Counter framesRx;
        final Counter framesTx;
        final Counter messagesRx;
        final Counter messagesTx;
        final Counter deflateBytesSaved;
        private final AtomicReferenceArray<Counter> closeCodes = new AtomicReferenceArray<>(LAST_CODE - FIRST_CODE + 2);

        WebSocketStats(StatsRegistry registry) {
            this.registry = registry;
            sessionsActive = registry.gauge("websocket.sessions_active", "WebSocket sessions open");
            sessionsTotal = registry.counter("websocket.sessions_total", "WebSocket sessions opened");
            framesRx = registry.counter("websocket.frames_rx", "Frames read from either peer, of sessions whose frames are parsed");
            framesTx = registry.counter("websocket.frames_tx", "Frames written to either peer, of sessions whose frames are parsed");
            messagesRx = registry.counter("websocket.messages_rx", "Messages joined for the message hook");
            messagesTx = registry.counter("websocket.messages_tx", "Messages the message hook returned and the proxy sent");
            deflateBytesSaved = registry.counter("websocket.deflate_bytes_saved",
                    "Bytes permessage-deflate saved on the frames the proxy compressed");
        }

        /** {@code close_codes.<code>}: Close frames by status code; codes outside 1000 to 1015 are {@code other}. */
        Counter closeCode(int code) {
            int i = code >= FIRST_CODE && code <= LAST_CODE ? code - FIRST_CODE : LAST_CODE - FIRST_CODE + 1;
            Counter c = closeCodes.get(i);
            if (c == null) {
                String name = i <= LAST_CODE - FIRST_CODE ? Integer.toString(code) : "other";
                c = registry.counter("websocket.close_codes." + name, "Close frames, by status code");
                if (!closeCodes.compareAndSet(i, null, c)) c = closeCodes.get(i);
            }
            return c;
        }
    }

    // ---------------------------------------------------------------------------------------
    // hooks.<family>.*
    // ---------------------------------------------------------------------------------------

    /**
     * {@code hooks.<family>.*}: one family of hooks' calls, errors, drops and rewrites, and how
     * long they took. The time is read only with metrics on: {@link #start} returns 0 otherwise,
     * and {@link #end} does nothing then.
     */
    static final class HookStats {
        /** Counts nothing: hooks run outside a proxy (in tests), or before their proxy's stats are known. */
        static final HookStats NOOP = new HookStats(StatsRegistry.NOOP, "none");

        final boolean enabled;
        final Counter invocations;
        final Counter errors;
        final Counter drops;
        final Counter rewrites;
        final Histogram latencyUs;

        HookStats(StatsRegistry registry, String family) {
            String p = "hooks." + family + ".";
            enabled = registry.enabled();
            invocations = registry.counter(p + "invocations", "Hook calls");
            errors = registry.counter(p + "errors", "Hook calls that threw");
            drops = registry.counter(p + "drops", "Hook calls that dropped what they were given");
            rewrites = registry.counter(p + "rewrites", "Hook calls that replaced what they were given, or answered for the server");
            latencyUs = registry.histogram(p + "latency_us", "Microseconds hook calls took", Histogram.microsecondBounds());
        }

        /** {@return when a call starts, for {@link #end}; 0 without metrics, when no clock is read} */
        long start() {
            return enabled ? System.nanoTime() : 0;
        }

        /** Counts a call that started at {@code start}. */
        void end(long start) {
            if (!enabled) return;
            invocations.inc();
            latencyUs.record((System.nanoTime() - start) / 1_000.0);
        }

        /** Counts a call that started at {@code start} and threw. */
        void failed(long start) {
            if (!enabled) return;
            end(start);
            errors.inc();
        }

        /** Counts what a call that was given {@code given} returned: null drops it, another object rewrites it. */
        void outcome(Object given, Object result) {
            if (result == null) {
                drops.inc();
            } else if (result != given) {
                rewrites.inc();
            }
        }

        /**
         * Counts what a frame interceptor made of {@code frame}: dropped (nothing in its place),
         * passed on (itself alone), or rewritten (anything else, frames it added included).
         */
        void frameOutcome(Object frame, Object result, boolean added) {
            if (result == null && !added) {
                drops.inc();
            } else if (result != frame || added) {
                rewrites.inc();
            }
        }
    }

    /** Every family of hooks. */
    static final class Hooks {
        final HookStats httpFilters;
        final HookStats frameInterceptor;
        final HookStats tcp;
        final HookStats udp;
        final HookStats quicStream;
        final HookStats quicDatagram;
        final HookStats webSocketFrame;
        final HookStats webSocketMessage;

        Hooks(StatsRegistry registry) {
            httpFilters = new HookStats(registry, "http_filters");
            frameInterceptor = new HookStats(registry, "frame_interceptor");
            tcp = new HookStats(registry, "tcp");
            udp = new HookStats(registry, "udp");
            quicStream = new HookStats(registry, "quic_stream");
            quicDatagram = new HookStats(registry, "quic_datagram");
            webSocketFrame = new HookStats(registry, "websocket_frame");
            webSocketMessage = new HookStats(registry, "websocket_message");
        }
    }
}
