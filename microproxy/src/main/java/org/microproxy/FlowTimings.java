package org.microproxy;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * When the phases of one request/response exchange happened, from {@link FlowContext#timings()}.
 *
 * <p>Every {@code ...Nanos} component except {@code clientTlsHandshakeNanos} is an offset in
 * nanoseconds ({@link System#nanoTime()}) from the moment the first byte of the request arrived,
 * or {@code -1} when that phase did not happen (yet). A request on a reused keep-alive or pooled
 * server connection has no DNS, connect or TLS phase; a request answered by the proxy or a filter
 * has no server phases at all. When several connection attempts were made (falling back from one
 * chained proxy to the next), a phase starts with the first attempt and ends with the last.
 *
 * <p>Phases with the server:
 *
 * <ul>
 *   <li>DNS: resolving the server's name (or a chained proxy's), unless a filter supplied an
 *       address;
 *   <li>connect: the TCP connection to the server or first chained proxy;
 *   <li>TLS: handshakes towards the server: with a TLS chained proxy, and with the origin when
 *       intercepting ({@code CONNECT} with a {@link MitmManager}, where it is part of the {@code
 *       CONNECT} exchange, not of the requests inside the session);
 *   <li>request sent: the request head and body have been written;
 *   <li>first response byte: the first byte of the server's response (including a {@code 1xx});
 *   <li>response complete: the last byte of the response to the client has been written, whoever
 *       made the response.
 * </ul>
 *
 * <p>{@code clientTlsHandshakeNanos} is the duration of the TLS handshake with the client (the
 * proxy's TLS listener, or the intercepted session) on which the request arrived, or {@code -1}.
 *
 * @param startEpochMillis wall-clock time when the request started arriving; 0 for {@link #NONE}
 */
public record FlowTimings(
        long startEpochMillis,
        long dnsStartNanos,
        long dnsEndNanos,
        long connectStartNanos,
        long connectEndNanos,
        long tlsStartNanos,
        long tlsEndNanos,
        long requestSentNanos,
        long firstResponseByteNanos,
        long responseCompleteNanos,
        long clientTlsHandshakeNanos) {

    /** No exchange recorded, e.g. for a context made outside the proxy. */
    public static final FlowTimings NONE = new FlowTimings(0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);

    /** When the request started arriving (wall clock). */
    public Optional<Instant> start() {
        return startEpochMillis == 0 ? Optional.empty() : Optional.of(Instant.ofEpochMilli(startEpochMillis));
    }

    /** How long resolving the server's name took. */
    public Optional<Duration> dnsLookup() {
        return between(dnsStartNanos, dnsEndNanos);
    }

    /** How long the TCP connect took. */
    public Optional<Duration> connect() {
        return between(connectStartNanos, connectEndNanos);
    }

    /** How long the TLS handshakes towards the server took. */
    public Optional<Duration> tlsHandshake() {
        return between(tlsStartNanos, tlsEndNanos);
    }

    /** How long the TLS handshake with the client took. */
    public Optional<Duration> clientTlsHandshake() {
        return clientTlsHandshakeNanos < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(clientTlsHandshakeNanos));
    }

    /**
     * From the start of the request to the first byte of the server's response: everything the
     * client waited for that the proxy did not decide alone (lookup, connect, sending, the server).
     */
    public Optional<Duration> timeToFirstByte() {
        return sinceStart(firstResponseByteNanos);
    }

    /** From the start of the request to the end of the response sent to the client. */
    public Optional<Duration> total() {
        return sinceStart(responseCompleteNanos);
    }

    private static Optional<Duration> sinceStart(long offset) {
        return offset < 0 ? Optional.empty() : Optional.of(Duration.ofNanos(offset));
    }

    private static Optional<Duration> between(long start, long end) {
        return start < 0 || end < start ? Optional.empty() : Optional.of(Duration.ofNanos(end - start));
    }
}
