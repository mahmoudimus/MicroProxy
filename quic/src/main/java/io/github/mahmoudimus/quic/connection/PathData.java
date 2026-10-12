/*
 * Ported from quinn-proto src/connection/paths.rs (PathData: new, from_previous,
 * anti_amplification_blocked, remove_in_flight; InFlight) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.congestion.Controller;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * One network path of a connection (RFC 9000 section 9): the peer's address, the local address the
 * connection uses on it, and what is measured per path: the RTT, the congestion controller, the
 * pacer, MTU discovery, the delivery rate, the bytes in flight, and the anti-amplification counts
 * until the path is validated (RFC 9000 section 8). {@link Recovery} keeps the current path; a
 * connection that migrates swaps in a new one and keeps the previous one for the packets still in
 * flight on it.
 *
 * <p>Packets carry the generation of the path they were sent on, so that acknowledging or losing
 * them updates the right path's counts.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class PathData {

    private final InetSocketAddress remote;
    private final InetSocketAddress local;
    final RttEstimator rtt;
    final Controller congestion;
    final Pacer pacer;
    final MtuDiscovery mtud;
    final DeliveryRate deliveryRate = new DeliveryRate();
    /** The PATH_CHALLENGE data this endpoint sent on the path and awaits; valid while {@link #hasChallenge}. */
    long challenge;
    boolean hasChallenge;
    /** Whether a PATH_CHALLENGE must still be sent on the path. */
    boolean challengePending;
    /** Whether the peer is known to receive on this address (RFC 9000 section 8). */
    boolean validated;
    /** Bytes of datagrams sent on the path. */
    long totalSent;
    /** Bytes of datagrams received on the path. */
    long totalReceived;
    /** The space and number of the first packet sent after the first RTT sample, or null. */
    SpaceId firstAfterRttSampleSpace;
    long firstAfterRttSamplePacket;
    /** Bytes of congestion-controlled packets in flight on the path. */
    long inFlightBytes;
    /** Ack-eliciting packets in flight on the path. */
    long inFlightAckEliciting;
    private final long generation;

    private PathData(InetSocketAddress remote, InetSocketAddress local, RttEstimator rtt, Controller congestion,
            Pacer pacer, MtuDiscovery mtud, long generation) {
        this.remote = remote;
        this.local = local;
        this.rtt = rtt;
        this.congestion = congestion;
        this.pacer = pacer;
        this.mtud = mtud;
        this.generation = generation;
    }

    /**
     * A path with fresh RTT, congestion and MTU state: the first path, or one whose network may
     * differ from the previous one (RFC 9000 section 9.4).
     *
     * @param config the loss recovery settings
     * @param remote the peer's address, or null where it does not matter
     * @param local the local address, or null for the endpoint's default
     * @param peerMaxUdpPayloadSize the peer's {@code max_udp_payload_size}, or -1 if not yet known
     * @param generation tells the path's packets from those of other paths
     * @param now the current time
     * @return the path, not validated
     */
    static PathData create(RecoveryConfig config, InetSocketAddress remote, InetSocketAddress local,
            int peerMaxUdpPayloadSize, long generation, long now) {
        Controller congestion = config.congestionControllerFactory().build(now, config.initialMtu());
        Pacer pacer = new Pacer(config.initialRtt(), congestion.initialWindow(), config.initialMtu(),
                config.maxOutgoingBytesPerSecond(), now);
        MtuDiscovery mtud = config.mtuDiscovery() == null
                ? MtuDiscovery.disabled(config.initialMtu(), config.minMtu())
                : MtuDiscovery.enabled(config.initialMtu(), config.minMtu(), peerMaxUdpPayloadSize, config.mtuDiscovery());
        if (config.mtuDiscovery() == null && peerMaxUdpPayloadSize >= 0) {
            mtud.onPeerMaxUdpPayloadSizeReceived(peerMaxUdpPayloadSize);
        }
        return new PathData(remote, local, new RttEstimator(config.initialRtt()), congestion, pacer, mtud, generation);
    }

    /**
     * A path that keeps the previous path's RTT, congestion and MTU state: a NAT rebinding, where
     * only a port changed and the network is presumably the same.
     *
     * @param remote the peer's new address
     * @param local the local address, or null for the endpoint's default
     * @param prev the previous path
     * @param generation tells the path's packets from those of other paths
     * @param now the current time
     * @return the path, not validated
     */
    static PathData fromPrevious(InetSocketAddress remote, InetSocketAddress local, PathData prev, long generation,
            long now) {
        Controller congestion = prev.congestion.copy();
        long smoothedRtt = prev.rtt.get();
        Pacer pacer = new Pacer(smoothedRtt, congestion.window(), prev.mtud.currentMtu(), prev.pacer.maxBytesPerSecond(),
                now);
        PathData path = new PathData(remote, local, new RttEstimator(prev.rtt), congestion, pacer, prev.mtud.copy(),
                generation);
        path.firstAfterRttSampleSpace = prev.firstAfterRttSampleSpace;
        path.firstAfterRttSamplePacket = prev.firstAfterRttSamplePacket;
        return path;
    }

    /**
     * Whether only the port of either end changed between two addresses of each end: a NAT
     * rebinding, which keeps the congestion state (RFC 9000 section 9.4).
     *
     * @param remote the peer's new address
     * @param local the new local address, or null for the endpoint's default
     * @return true if the IP addresses at both ends are the same as this path's (a local address
     *     that is not known, or a wildcard, counts as the same)
     */
    boolean sameHosts(InetSocketAddress remote, InetSocketAddress local) {
        return sameIp(this.remote, remote) && sameLocalIp(this.local, local);
    }

    private static boolean sameIp(InetSocketAddress a, InetSocketAddress b) {
        if (a == null || b == null) {
            return a == b;
        }
        InetAddress x = a.getAddress();
        InetAddress y = b.getAddress();
        return x == null ? y == null : x.equals(y);
    }

    /**
     * Whether two local addresses may be on the same host address: null (the endpoint's default
     * socket) and wildcard addresses could be any, so they count as the same; a client that
     * rebinds its socket to a new port so keeps its congestion state.
     */
    private static boolean sameLocalIp(InetSocketAddress a, InetSocketAddress b) {
        if (a == null || b == null || a.getAddress() == null || b.getAddress() == null
                || a.getAddress().isAnyLocalAddress() || b.getAddress().isAnyLocalAddress()) {
            return true;
        }
        return a.getAddress().equals(b.getAddress());
    }

    /**
     * Whether a server that has not validated this path must not send {@code bytesToSend} more:
     * until it is validated it may send at most three times what it received on it (RFC 9000
     * section 8).
     *
     * @param bytesToSend the bytes about to be sent
     * @return true if they would exceed the limit
     */
    boolean antiAmplificationBlocked(long bytesToSend) {
        return !validated && totalReceived * 3 < totalSent + bytesToSend;
    }

    /**
     * How many more bytes the anti-amplification limit lets this endpoint send on the path.
     *
     * @return three times the bytes received less those sent, at least 0; {@link Long#MAX_VALUE}
     *     once the path is validated
     */
    long antiAmplificationBudget() {
        return validated ? Long.MAX_VALUE : Math.max(0, totalReceived * 3 - totalSent);
    }

    void addInFlight(SentPacket p) {
        inFlightBytes += p.size();
        inFlightAckEliciting += p.ackEliciting() ? 1 : 0;
    }

    /**
     * Takes a packet out of the in-flight counts if it was sent on this path.
     *
     * @param p the packet
     * @return false if it was sent on another path
     */
    boolean removeInFlight(SentPacket p) {
        if (p.pathGeneration() != generation) {
            return false;
        }
        inFlightBytes -= p.size();
        inFlightAckEliciting -= p.ackEliciting() ? 1 : 0;
        return true;
    }

    /**
     * The peer's address on this path.
     *
     * @return the address, or null if not set
     */
    public InetSocketAddress remote() {
        return remote;
    }

    /**
     * The local address on this path.
     *
     * @return the address, or null for the endpoint's default
     */
    public InetSocketAddress local() {
        return local;
    }

    /**
     * Whether the path is validated.
     *
     * @return true once the peer proved it receives on it
     */
    public boolean isValidated() {
        return validated;
    }

    /**
     * Whether this endpoint awaits a PATH_RESPONSE on the path.
     *
     * @return true while validating it
     */
    public boolean isValidating() {
        return hasChallenge;
    }

    /**
     * The path's generation, which tells its packets from those of other paths.
     *
     * @return the generation
     */
    public long generation() {
        return generation;
    }

    @Override
    public String toString() {
        return "PathData[" + local + " -> " + remote + " gen " + generation + (validated ? " validated" : "") + "]";
    }
}
