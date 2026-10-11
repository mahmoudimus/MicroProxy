/*
 * Ported from quinn-proto src/connection/paths.rs (PathResponses, PathResponse) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The PATH_RESPONSE frames owed to the peer (RFC 9000 section 8.2.2), each for the path its
 * PATH_CHALLENGE arrived on: one per path, the latest challenge replacing an earlier one, and at
 * most {@value #MAX_PATH_RESPONSES} paths at once. A response for the current path rides in the
 * next packet; one for another path (the peer probing it, or an attacker spoofing it) goes out in
 * a datagram of its own, no larger than three times the datagram that carried the challenge.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
final class PathResponses {

    /** An arbitrary bound against abuse, as quinn's. */
    static final int MAX_PATH_RESPONSES = 16;

    /**
     * A PATH_RESPONSE to send.
     *
     * @param packet the number of the packet that carried the PATH_CHALLENGE
     * @param token the challenge data, echoed
     * @param remote where the challenge came from
     * @param local the local address it arrived at, or null for the endpoint's default
     * @param received the size of the datagram that carried it, which bounds the response on an
     *     unvalidated path
     */
    record PathResponse(long packet, long token, InetSocketAddress remote, InetSocketAddress local, int received) {

        boolean on(InetSocketAddress remote, InetSocketAddress local) {
            return this.remote.equals(remote) && Objects.equals(this.local, local);
        }
    }

    private final List<PathResponse> pending = new ArrayList<>();

    /** Queues a response, replacing an older one for the same path. */
    void push(long packet, long token, InetSocketAddress remote, InetSocketAddress local, int received) {
        PathResponse response = new PathResponse(packet, token, remote, local, received);
        for (int i = 0; i < pending.size(); i++) {
            PathResponse existing = pending.get(i);
            if (existing.on(remote, local)) {
                if (existing.packet() <= packet) {
                    pending.set(i, response);
                }
                return;
            }
        }
        if (pending.size() < MAX_PATH_RESPONSES) {
            pending.add(response);
        }
    }

    /** Takes a response for a path other than {@code remote} and {@code local}, or null. */
    PathResponse popOffPath(InetSocketAddress remote, InetSocketAddress local) {
        for (int i = pending.size() - 1; i >= 0; i--) {
            if (!pending.get(i).on(remote, local)) {
                return pending.remove(i);
            }
        }
        return null;
    }

    /** Takes the response for the path of {@code remote} and {@code local}, or null. */
    PathResponse popOnPath(InetSocketAddress remote, InetSocketAddress local) {
        for (int i = pending.size() - 1; i >= 0; i--) {
            if (pending.get(i).on(remote, local)) {
                return pending.remove(i);
            }
        }
        return null;
    }

    /** Whether a response for the path of {@code remote} and {@code local} is queued. */
    boolean hasOnPath(InetSocketAddress remote, InetSocketAddress local) {
        for (PathResponse r : pending) {
            if (r.on(remote, local)) {
                return true;
            }
        }
        return false;
    }

    /** Whether a response for any path other than {@code remote} and {@code local} is queued. */
    boolean hasOffPath(InetSocketAddress remote, InetSocketAddress local) {
        for (PathResponse r : pending) {
            if (!r.on(remote, local)) {
                return true;
            }
        }
        return false;
    }

    boolean isEmpty() {
        return pending.isEmpty();
    }
}
