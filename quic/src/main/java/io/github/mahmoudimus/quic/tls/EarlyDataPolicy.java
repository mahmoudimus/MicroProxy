package io.github.mahmoudimus.quic.tls;

import java.time.Duration;
import java.util.Objects;

/**
 * Decides, on a server, whether to accept the 0-RTT data a resuming client offers. The handshake
 * asks only once the offer passes the protocol's own checks: the first PSK identity was accepted,
 * the ticket allows early data, and the cipher suite, ALPN protocol, server name and QUIC transport
 * parameters match the session's. Rejecting early data is always safe: the handshake goes on, the
 * client learns of the rejection and sends its data again after the handshake.
 *
 * <p><b>Replay.</b> 0-RTT data has no protection against replay (RFC 8446 sections 2.3 and 8): an
 * attacker who captures a client's first flight can send it again, and a server that accepts it
 * acts on the early data twice. The default, {@link #antiReplay()}, narrows this as RFC 8446
 * section 8 describes: it accepts a ticket's early data at most once, and only while the client's
 * idea of the ticket's age agrees with the server's within a short window, so a first flight
 * replayed later fails the age check and one replayed sooner hits the single-use record. That
 * record lives in one process: servers behind one address that share a ticket key but not the
 * record can each accept a replay once. Even then, early data should only carry requests that are
 * safe to repeat, which is the application's call; RFC 8470 describes it for HTTP. Compose an
 * application veto with {@link #and(EarlyDataPolicy)}.
 *
 * <p>Policies are called on the thread that drives the handshake, so they should be quick and must
 * be thread-safe.
 */
@FunctionalInterface
public interface EarlyDataPolicy {

    /** Accepts no early data. */
    EarlyDataPolicy REJECT = attempt -> false;

    /**
     * Accepts any early data the protocol allows, with no protection against replay. For tests.
     */
    EarlyDataPolicy ACCEPT_ALL = attempt -> true;

    /**
     * Whether to accept a client's early data.
     *
     * @param attempt what the client offers
     * @return true to accept it
     */
    boolean accept(EarlyDataAttempt attempt);

    /**
     * A policy that accepts only what both this one and another accept. The other is asked first,
     * and this one only if the other accepts: in {@code antiReplay().and(veto)} the anti-replay
     * record notes a ticket only when the application's veto lets it through.
     *
     * @param other the second policy
     * @return the combined policy
     */
    default EarlyDataPolicy and(EarlyDataPolicy other) {
        Objects.requireNonNull(other, "other");
        return attempt -> other.accept(attempt) && accept(attempt);
    }

    /**
     * The default anti-replay policy: a ticket age window of {@value AntiReplay#DEFAULT_WINDOW_SECONDS}
     * seconds and a single-use record of up to {@value AntiReplay#DEFAULT_MAX_ENTRIES} tickets.
     *
     * @return a new policy with its own record
     */
    static EarlyDataPolicy antiReplay() {
        return new AntiReplay(Duration.ofSeconds(AntiReplay.DEFAULT_WINDOW_SECONDS), AntiReplay.DEFAULT_MAX_ENTRIES,
                System::nanoTime);
    }

    /**
     * An anti-replay policy.
     *
     * @param window how far the client's and the server's ticket ages may differ; the single-use
     *     record keeps each ticket for twice this long
     * @param maxEntries the most tickets the record holds; when it is full, early data is refused
     * @return a new policy with its own record
     */
    static EarlyDataPolicy antiReplay(Duration window, int maxEntries) {
        return new AntiReplay(window, maxEntries, System::nanoTime);
    }
}
