/*
 * Ported from quinn-proto src/connection/mod.rs (on_ack_received, detect_spurious_loss,
 * drain_lost_packets, process_ecn, on_packet_acked, on_loss_detection_timeout,
 * detect_lost_packets, loss_time_and_space, pto_time_and_space,
 * peer_completed_address_validation, set_loss_detection_timer, pto, discard_space,
 * reset_idle_timeout) and src/connection/paths.rs (PathData, InFlight) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.congestion.Controller;
import io.github.mahmoudimus.quic.congestion.RttEstimator;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.random.RandomGenerator;

/**
 * Loss detection and congestion control of one connection (RFC 9002): the three packet number
 * spaces, the in-flight counts, the RTT estimator, the congestion controller, the pacer, MTU
 * discovery and the probe timeout. It sets {@link Timer#LOSS_DETECTION} in the connection's {@link
 * TimerTable}; the connection calls {@link #onLossDetectionTimeout} when it fires.
 *
 * <p>The connection layer reports what it sends ({@link #onPacketSent}, {@link #onDatagramSent})
 * and receives ({@link #onPacketReceived}, {@link #onAckReceived}); acknowledged and lost packets
 * are handed to a {@link Listener}, and the control frames of lost packets are queued again in their
 * space's {@link PacketSpace#pending()}.
 *
 * <p>Persistent congestion (RFC 9002 section 7.6) is detected among packets deemed lost on receipt
 * of an ACK: two ack-eliciting packets lost more than {@code persistentCongestionThreshold} PTOs
 * apart, with nothing acknowledged between them, both sent after the first RTT sample.
 *
 * <p>Times and durations are nanoseconds.
 *
 * <p><b>Threads.</b> Not thread-safe and takes no locks; owned by one connection, which serializes
 * access.
 */
public final class Recovery {

    /** The largest PTO backoff exponent. */
    static final int MAX_BACKOFF_EXPONENT = 16;

    /** Receives acknowledged and lost packets. */
    public interface Listener {

        /** A listener that does nothing. */
        Listener NONE = new Listener() {};

        /**
         * A packet was acknowledged. Its in-flight accounting is already done.
         *
         * @param space the packet's space
         * @param packetNumber the packet number
         * @param packet the packet
         */
        default void onPacketAcked(SpaceId space, long packetNumber, SentPacket packet) {}

        /**
         * A packet was deemed lost. Its control frames are already queued again in its space; its
         * STREAM frames are the listener's to retransmit.
         *
         * @param space the packet's space
         * @param packetNumber the packet number
         * @param packet the packet
         */
        default void onPacketLost(SpaceId space, long packetNumber, SentPacket packet) {}

        /**
         * The listener of a connection's streams, as quinn wires it: acknowledged STREAM frames and
         * RESET_STREAMs release stream state, lost STREAM frames are queued again.
         *
         * @param streams the streams
         * @return the listener
         */
        static Listener forStreams(StreamsState streams) {
            return new Listener() {
                @Override
                public void onPacketAcked(SpaceId space, long packetNumber, SentPacket packet) {
                    if (packet.retransmits() != null) {
                        for (Retransmits.PendingReset r : packet.retransmits().resetStream) {
                            streams.resetAcked(r.id());
                        }
                    }
                    for (StreamMeta frame : packet.streamFrames()) {
                        streams.receivedAckOf(frame);
                    }
                }

                @Override
                public void onPacketLost(SpaceId space, long packetNumber, SentPacket packet) {
                    for (StreamMeta frame : packet.streamFrames()) {
                        streams.retransmit(frame);
                    }
                }
            };
        }
    }

    private record Deadline(long time, SpaceId space) {}

    private final Side side;
    private final RecoveryConfig config;
    private final TimerTable timers;
    private final RandomGenerator random;
    private final PacketSpace[] spaces = new PacketSpace[3];
    private final RttEstimator rtt;
    private final Controller congestion;
    private final Pacer pacer;
    private final MtuDiscovery mtud;
    private final AckFrequencyState ackFrequency;
    PacketNumberFilter packetNumberFilter;

    /** Bytes of congestion-controlled packets in flight. */
    private long inFlightBytes;
    /** Ack-eliciting packets in flight. */
    private long inFlightAckEliciting;
    private int ptoCount;
    private boolean appLimited;
    private boolean handshakeConfirmed;
    private boolean closed;
    private boolean sendingEcn = true;
    private boolean addressValidated;
    private long totalSent;
    private long totalReceived;
    private long peerAckDelayExponent = TransportParameters.DEFAULT_ACK_DELAY_EXPONENT;
    /** The space and number of the first packet sent after the first RTT sample, or null. */
    private SpaceId firstAfterRttSampleSpace;
    private long firstAfterRttSamplePacket;

    private long sentPacketCount;
    private long lostPacketCount;
    private long lostByteCount;
    private long congestionEventCount;
    private long spuriousCongestionEventCount;
    private long lostMtuProbeCount;
    private long blackHoleCount;

    /**
     * Loss recovery for a new connection.
     *
     * @param side this endpoint's role; a client's address is always validated, a server's peer
     *     address is not until {@link #setAddressValidated()}
     * @param config the configuration
     * @param timers the connection's timers, where {@link Timer#LOSS_DETECTION} and {@link
     *     Timer#MAX_ACK_DELAY} are set
     * @param random the source of randomness for skipped packet numbers
     * @param now the current time
     */
    public Recovery(Side side, RecoveryConfig config, TimerTable timers, RandomGenerator random, long now) {
        this.side = side;
        this.config = config;
        this.timers = timers;
        this.random = random;
        for (SpaceId id : SpaceId.values()) {
            spaces[id.ordinal()] = new PacketSpace(id, now);
        }
        this.rtt = new RttEstimator(config.initialRtt());
        this.congestion = config.congestionControllerFactory().build(now, config.initialMtu());
        this.pacer = new Pacer(config.initialRtt(), congestion.initialWindow(), config.initialMtu(),
                config.maxOutgoingBytesPerSecond(), now);
        this.mtud = config.mtuDiscovery() == null
                ? MtuDiscovery.disabled(config.initialMtu(), config.minMtu())
                : MtuDiscovery.enabled(config.initialMtu(), config.minMtu(), -1, config.mtuDiscovery());
        this.ackFrequency = new AckFrequencyState(config.maxAckDelay());
        this.packetNumberFilter = new PacketNumberFilter(random);
        this.addressValidated = side.isClient();
    }

    // ---------------------------------------------------------------------------------------
    // Accessors and inputs

    /**
     * A packet number space.
     *
     * @param id which space
     * @return the space
     */
    public PacketSpace space(SpaceId id) {
        return spaces[id.ordinal()];
    }

    /**
     * The RTT estimator.
     *
     * @return the estimator
     */
    public RttEstimator rtt() {
        return rtt;
    }

    /**
     * The congestion controller.
     *
     * @return the controller
     */
    public Controller congestion() {
        return congestion;
    }

    /**
     * MTU discovery.
     *
     * @return the discovery state
     */
    public MtuDiscovery mtud() {
        return mtud;
    }

    /**
     * The ACK delays of both endpoints.
     *
     * @return the ACK frequency state
     */
    public AckFrequencyState ackFrequency() {
        return ackFrequency;
    }

    /**
     * Bytes in flight.
     *
     * @return the size of congestion-controlled packets neither acknowledged nor lost
     */
    public long bytesInFlight() {
        return inFlightBytes;
    }

    /**
     * Ack-eliciting packets in flight.
     *
     * @return the count
     */
    public long ackElicitingInFlight() {
        return inFlightAckEliciting;
    }

    /**
     * The number of probe timeouts since the last acknowledgement, which sets the backoff.
     *
     * @return the PTO count
     */
    public int ptoCount() {
        return ptoCount;
    }

    /**
     * Whether a packet of some size fits the congestion window.
     *
     * @param bytes the packet's size
     * @return true if sending it would exceed the window
     */
    public boolean isCongestionBlocked(long bytes) {
        return inFlightBytes + bytes > congestion.window();
    }

    /**
     * Records whether the application, not the congestion window, limited the last send; ACKs then
     * do not grow the window.
     *
     * @param appLimited whether sending was application limited
     */
    public void setAppLimited(boolean appLimited) {
        this.appLimited = appLimited;
    }

    /**
     * Whether the application, not the congestion window or the pacer, limited the last send.
     *
     * @return the flag ACKs are processed with
     */
    public boolean isAppLimited() {
        return appLimited;
    }

    /**
     * Records that the handshake is confirmed (RFC 9001 section 4.1.2); until then the probe
     * timeout ignores the application data space (RFC 9002 section 6.2.1).
     *
     * @param confirmed whether it is confirmed
     */
    public void setHandshakeConfirmed(boolean confirmed) {
        this.handshakeConfirmed = confirmed;
    }

    /** Stops loss detection for good, as the connection closes. */
    public void close() {
        closed = true;
        timers.stop(Timer.LOSS_DETECTION);
    }

    /**
     * Whether ECN-marked packets are being sent; an ACK without ECN counts or with invalid ones
     * turns it off.
     *
     * @return true while ECN is in use
     */
    public boolean sendingEcn() {
        return sendingEcn;
    }

    /**
     * Sets whether ECN is in use, for a connection that cannot mark packets.
     *
     * @param sendingEcn whether outgoing packets carry ECT(0)
     */
    public void setSendingEcn(boolean sendingEcn) {
        this.sendingEcn = sendingEcn;
    }

    /**
     * Applies the peer's transport parameters: its {@code ack_delay_exponent}, {@code max_ack_delay}
     * and {@code max_udp_payload_size}.
     *
     * @param params the peer's parameters
     */
    public void setPeerParams(TransportParameters params) {
        peerAckDelayExponent = params.ackDelayExponent();
        ackFrequency.setPeerMaxAckDelay(params.maxAckDelay() * 1_000_000L);
        mtud.onPeerMaxUdpPayloadSizeReceived((int) Math.min(params.maxUdpPayloadSize(), MtuDiscoveryConfig.MAX_UDP_PAYLOAD));
    }

    /** Records that the peer's address is validated, lifting the anti-amplification limit. */
    public void setAddressValidated() {
        addressValidated = true;
    }

    /**
     * Whether a server must not send yet: until the peer's address is validated it may send at most
     * three times what it received (RFC 9000 section 8.1).
     *
     * @param bytesToSend the bytes about to be sent
     * @return true if they would exceed the limit
     */
    public boolean antiAmplificationBlocked(long bytesToSend) {
        return !addressValidated && totalReceived * 3 < totalSent + bytesToSend;
    }

    /**
     * How many more bytes the anti-amplification limit lets this endpoint send.
     *
     * @return three times the bytes received less those sent, at least 0; {@link Long#MAX_VALUE}
     *     once the peer's address is validated
     */
    public long antiAmplificationBudget() {
        return addressValidated ? Long.MAX_VALUE : Math.max(0, totalReceived * 3 - totalSent);
    }

    // ---------------------------------------------------------------------------------------
    // Sending

    /**
     * Allocates the next packet number of a space; the application data space occasionally skips
     * one (see {@link PacketNumberFilter}).
     *
     * @param id the space
     * @return the packet number
     */
    public long nextPacketNumber(SpaceId id) {
        PacketSpace space = space(id);
        return id == SpaceId.DATA ? packetNumberFilter.allocate(random, space) : space.getTxNumber();
    }

    /**
     * The packet number {@link #nextPacketNumber} would allocate.
     *
     * @param id the space
     * @return the packet number
     */
    public long peekPacketNumber(SpaceId id) {
        PacketSpace space = space(id);
        return id == SpaceId.DATA ? packetNumberFilter.peek(space) : space.nextPacketNumber();
    }

    /**
     * Records a sent packet: in-flight counts, the time of the last ack-eliciting packet, pacing,
     * and the loss detection timer.
     *
     * @param now the current time
     * @param id the packet's space
     * @param packetNumber its number
     * @param packet what to remember about it
     */
    public void onPacketSent(long now, SpaceId id, long packetNumber, SentPacket packet) {
        PacketSpace space = space(id);
        addInFlight(packet);
        SentPacket forgotten = space.sent(packetNumber, packet);
        if (forgotten != null) {
            removeInFlight(forgotten);
        }
        sentPacketCount++;
        if (packet.size() != 0) {
            if (packet.ackEliciting()) {
                space.timeOfLastAckElicitingPacket = now;
            }
            setLossDetectionTimer(now);
            pacer.onTransmit(packet.size());
        }
    }

    /**
     * Records a sent datagram, for the congestion controller and the anti-amplification limit.
     *
     * @param now the current time
     * @param bytes the datagram's size
     * @param lastPacketNumber the number of the last packet in it
     */
    public void onDatagramSent(long now, long bytes, long lastPacketNumber) {
        totalSent += bytes;
        congestion.onSent(now, bytes, lastPacketNumber);
    }

    /**
     * Records a received datagram, for the anti-amplification limit.
     *
     * @param bytes the datagram's size
     */
    public void onDatagramReceived(long bytes) {
        totalReceived += bytes;
    }

    /**
     * When pacing allows a packet; sets or stops {@link Timer#PACING}.
     *
     * @param now the current time
     * @param bytesToSend the packet's size
     * @return the time to try again, or {@link NanoClock#NONE} to send now
     */
    public long pacingDelay(long now, long bytesToSend) {
        long t = pacer.delay(rtt.get(), bytesToSend, mtud.currentMtu(), congestion.window(), now);
        if (t == NanoClock.NONE) {
            timers.stop(Timer.PACING);
        } else {
            timers.set(Timer.PACING, t);
        }
        return t;
    }

    // ---------------------------------------------------------------------------------------
    // Receiving

    /**
     * Records an authenticated packet: duplicate detection, ACK bookkeeping, and the {@link
     * Timer#MAX_ACK_DELAY} timer in the application data space.
     *
     * @param now the current time
     * @param id the packet's space
     * @param packetNumber its number
     * @param ackEliciting whether it is ack-eliciting
     * @return true if it is a duplicate, to be dropped
     */
    public boolean onPacketReceived(long now, SpaceId id, long packetNumber, boolean ackEliciting) {
        PacketSpace space = space(id);
        if (space.onPacketReceived(now, packetNumber, ackEliciting)) {
            return true;
        }
        if (id == SpaceId.DATA) {
            long deadline = space.pendingAcks.maxAckDelayTimeout(ackFrequency.maxAckDelay());
            if (deadline != NanoClock.NONE) {
                timers.set(Timer.MAX_ACK_DELAY, deadline);
            }
        }
        return false;
    }

    /**
     * Records that an ACK frame was sent in a space.
     *
     * @param id the space
     */
    public void onAcksSent(SpaceId id) {
        space(id).pendingAcks.acksSent();
        if (id == SpaceId.DATA) {
            timers.stop(Timer.MAX_ACK_DELAY);
        }
    }

    /** Handles the expiry of {@link Timer#MAX_ACK_DELAY}: an ACK is now due. */
    public void onMaxAckDelayTimeout() {
        space(SpaceId.DATA).pendingAcks.onMaxAckDelayTimeout();
    }

    /**
     * Processes an ACK frame (RFC 9002 section 6 and appendix A.7): acknowledges packets, takes an
     * RTT sample, detects loss, validates ECN counts and rearms the loss detection timer.
     *
     * @param now the current time
     * @param id the space the ACK arrived in
     * @param ack the frame
     * @param listener receives the acknowledged and lost packets
     * @throws QuicException {@code PROTOCOL_VIOLATION} if the ACK covers a packet number never sent
     */
    public void onAckReceived(long now, SpaceId id, Frame.Ack ack, Listener listener) throws QuicException {
        PacketSpace space = space(id);
        if (ack.largest() >= space.nextPacketNumber) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION, "unsent packet acked");
        }
        boolean newLargest = false;
        if (space.largestAckedPacket < 0 || ack.largest() > space.largestAckedPacket) {
            space.largestAckedPacket = ack.largest();
            SentPacket info = space.sentPackets.get(ack.largest());
            if (info != null) {
                // A misbehaving peer may ack a packet never sent; at worst the window shrinks
                space.largestAckedPacketSent = info.timeSent();
            }
            newLargest = true;
        }
        if (detectSpuriousLoss(ack, space)) {
            spuriousCongestionEventCount++;
            congestion.onSpuriousCongestionEvent();
        }
        // Look only at packets actually tracked, so huge ranges cost nothing
        RangeSet newlyAcked = new RangeSet();
        for (Frame.AckRange range : ack.ranges()) {
            packetNumberFilter.checkAck(id, range.smallest(), range.largest());
            for (Long pn : space.sentPackets.range(range.smallest(), range.largest() + 1).keySet()) {
                newlyAcked.insertOne(pn);
            }
        }
        if (newlyAcked.isEmpty()) {
            return;
        }
        boolean ackElicitingAcked = false;
        long newlyAckedCount = 0;
        for (long pn : newlyAcked.elements().toArray()) {
            SentPacket info = space.take(pn);
            if (info == null) {
                continue;
            }
            newlyAckedCount++;
            if (info.largestAcked() >= 0) {
                // The peer has our ACK of everything up to here; stop acknowledging those packets
                // (RFC 9000 section 13.2.4)
                space.pendingAcks.subtractBelow(info.largestAcked());
            }
            ackElicitingAcked |= info.ackEliciting();
            // An MTU probe raises the MTU when acknowledged
            if (mtud.onAcked(id, pn, info.size())) {
                congestion.onMtuUpdate(mtud.currentMtu());
            }
            if (id == SpaceId.DATA) {
                ackFrequency.onAcked(pn);
            }
            onPacketAcked(now, id, pn, info, listener);
        }
        congestion.onEndAcks(now, inFlightBytes, appLimited, space.largestAckedPacket);

        if (newLargest && ackElicitingAcked) {
            long ackDelay = 0;
            if (id == SpaceId.DATA) {
                long micros = ack.ackDelay() > (Long.MAX_VALUE >>> peerAckDelayExponent)
                        ? Long.MAX_VALUE
                        : ack.ackDelay() << peerAckDelayExponent;
                ackDelay = Math.min(ackFrequency.peerMaxAckDelay(), saturatingMul(micros, 1_000));
            }
            long sample = Math.max(0, now - space.largestAckedPacketSent);
            rtt.update(ackDelay, sample);
            if (firstAfterRttSampleSpace == null) {
                firstAfterRttSampleSpace = id;
                firstAfterRttSamplePacket = space.nextPacketNumber;
            }
        }

        detectLostPackets(now, id, true, listener);

        if (peerCompletedAddressValidation()) {
            ptoCount = 0;
        }

        if (sendingEcn) {
            if (ack.ecn() != null) {
                // Only in-order ACKs give a well-defined increase to compare with
                if (newLargest) {
                    processEcn(now, space, newlyAckedCount, ack.ecn(), space.largestAckedPacketSent);
                }
            } else {
                sendingEcn = false; // ECN starts on, so an ACK without counts turns it off
            }
        }
        setLossDetectionTimer(now);
    }

    /** True if the ACK acknowledged every packet deemed lost: the last congestion event was spurious. */
    private static boolean detectSpuriousLoss(Frame.Ack ack, PacketSpace space) {
        if (space.lostPackets.isEmpty()) {
            return false;
        }
        for (Frame.AckRange range : ack.ranges()) {
            space.lostPackets.subMap(range.smallest(), true, range.largest(), true).clear();
        }
        return space.lostPackets.isEmpty();
    }

    /** Forgets lost packets sent more than two PTOs ago, which will not be acknowledged. */
    private void drainLostPackets(long now, PacketSpace space) {
        long twoPto = 2 * rtt.ptoBase();
        space.lostPackets.values().removeIf(timeSent -> Math.max(0, now - timeSent) > twoPto);
    }

    private void processEcn(long now, PacketSpace space, long newlyAcked, Frame.EcnCounts ecn, long largestSentTime) {
        boolean ce;
        try {
            ce = space.detectEcn(newlyAcked, ecn);
        } catch (IllegalArgumentException e) {
            // Halt ECN; the counts may be garbage, so forget them too
            sendingEcn = false;
            space.ecnFeedback = new Frame.EcnCounts(0, 0, 0);
            return;
        }
        if (ce) {
            congestionEventCount++;
            congestion.onCongestionEvent(now, largestSentTime, false, true, 0);
        }
    }

    private void onPacketAcked(long now, SpaceId id, long pn, SentPacket info, Listener listener) {
        removeInFlight(info);
        if (info.ackEliciting()) {
            congestion.onAck(now, info.timeSent(), info.size(), appLimited, rtt);
        }
        listener.onPacketAcked(id, pn, info);
    }

    // ---------------------------------------------------------------------------------------
    // Loss detection

    /**
     * Handles the expiry of {@link Timer#LOSS_DETECTION}: time-threshold loss detection if a loss
     * time is set, otherwise a probe timeout, which asks for one or two probe packets (see {@link
     * PacketSpace#lossProbes()}) and doubles the next timeout.
     *
     * @param now the current time
     * @param listener receives lost packets
     */
    public void onLossDetectionTimeout(long now, Listener listener) {
        Deadline loss = lossTimeAndSpace();
        if (loss != null) {
            detectLostPackets(now, loss.space(), false, listener);
            setLossDetectionTimer(now);
            return;
        }
        Deadline pto = ptoTimeAndSpace(now);
        if (pto == null) {
            return;
        }
        // Without ack-eliciting packets in flight this is the client's anti-deadlock probe
        int count = inFlightAckEliciting == 0 ? 1 : 2;
        PacketSpace space = space(pto.space());
        space.lossProbes = (int) Math.min((long) space.lossProbes + count, Integer.MAX_VALUE);
        ptoCount = ptoCount == Integer.MAX_VALUE ? ptoCount : ptoCount + 1;
        setLossDetectionTimer(now);
    }

    /**
     * Detects lost packets in a space (RFC 9002 section 6.1, appendix A.10): packets sent before
     * the largest acknowledged that are {@code packetThreshold} packets older, or older than {@code
     * timeThreshold} RTTs.
     */
    private void detectLostPackets(long now, SpaceId id, boolean dueToAck, Listener listener) {
        PacketSpace space = space(id);
        List<Long> lost = new ArrayList<>();
        long lostMtuProbe = -1;
        long inFlightMtuProbe = id == SpaceId.DATA ? mtud.inFlightMtuProbe() : -1;
        long lossDelay = Math.max((long) (rtt.conservative() * config.timeThreshold()), RttEstimator.TIMER_GRANULARITY);
        long largestAcked = space.largestAckedPacket;
        long packetThreshold = config.packetThreshold();
        long lostBytes = 0;
        // The PTO always includes max_ack_delay here, as in the application data space (RFC 9001
        // section 7.6.1)
        long congestionPeriod = saturatingMul(pto(SpaceId.DATA), config.persistentCongestionThreshold());
        long persistentCongestionStart = NanoClock.NONE;
        long prevPacket = -1;
        boolean inPersistentCongestion = false;
        space.lossTime = NanoClock.NONE;

        for (Map.Entry<Long, SentPacket> e : space.sentPackets.range(0, largestAcked).entrySet()) {
            long packet = e.getKey();
            SentPacket info = e.getValue();
            if (prevPacket < 0 || prevPacket != packet - 1) {
                persistentCongestionStart = NanoClock.NONE; // a packet in between was acknowledged
            }
            boolean tooOld = Math.max(0, now - info.timeSent()) >= lossDelay;
            if (tooOld || largestAcked >= packet + packetThreshold) {
                if (packet == inFlightMtuProbe) {
                    lostMtuProbe = packet; // not a congestion signal
                } else {
                    lost.add(packet);
                    lostBytes += info.size();
                    if (info.ackEliciting() && dueToAck) {
                        if (persistentCongestionStart != NanoClock.NONE) {
                            if (info.timeSent() - persistentCongestionStart > congestionPeriod) {
                                inPersistentCongestion = true;
                            }
                        } else if (sentAfterFirstRttSample(id, packet)) {
                            persistentCongestionStart = info.timeSent();
                        }
                    }
                }
            } else {
                long nextLossTime = info.timeSent() + lossDelay;
                space.lossTime = space.lossTime == NanoClock.NONE ? nextLossTime : Math.min(space.lossTime, nextLossTime);
                persistentCongestionStart = NanoClock.NONE;
            }
            prevPacket = packet;
        }

        drainLostPackets(now, space);

        if (!lost.isEmpty()) {
            long oldBytesInFlight = inFlightBytes;
            long largestLostSent = space.sentPackets.get(lost.get(lost.size() - 1)).timeSent();
            lostPacketCount += lost.size();
            lostByteCount += lostBytes;
            for (long pn : lost) {
                SentPacket info = space.take(pn);
                removeInFlight(info);
                if (info.retransmits() != null) {
                    space.pending.merge(info.retransmits());
                }
                listener.onPacketLost(id, pn, info);
                if (id == SpaceId.DATA) {
                    mtud.onNonProbeLost(pn, info.size());
                }
                space.lostPackets.put(pn, info.timeSent());
            }
            if (mtud.blackHoleDetected(now)) {
                blackHoleCount++;
                congestion.onMtuUpdate(mtud.currentMtu());
            }
            // Lost ACK-only packets carry no congestion penalty
            if (oldBytesInFlight != inFlightBytes) {
                congestionEventCount++;
                congestion.onCongestionEvent(now, largestLostSent, inPersistentCongestion, false, lostBytes);
            }
        }
        if (lostMtuProbe >= 0) {
            SentPacket info = space.take(lostMtuProbe);
            removeInFlight(info);
            mtud.onProbeLost();
            lostMtuProbeCount++;
        }
    }

    /** Whether a packet was sent after the first RTT sample was taken. */
    private boolean sentAfterFirstRttSample(SpaceId id, long packet) {
        if (firstAfterRttSampleSpace == null) {
            return false;
        }
        int c = Integer.compare(firstAfterRttSampleSpace.ordinal(), id.ordinal());
        return c < 0 || (c == 0 && firstAfterRttSamplePacket < packet);
    }

    private Deadline lossTimeAndSpace() {
        Deadline best = null;
        for (PacketSpace s : spaces) {
            if (s.lossTime != NanoClock.NONE && (best == null || s.lossTime < best.time())) {
                best = new Deadline(s.lossTime, s.id());
            }
        }
        return best;
    }

    /** The earliest probe timeout and its space (RFC 9002 appendix A.8). */
    private Deadline ptoTimeAndSpace(long now) {
        long backoff = 1L << Math.min(ptoCount, MAX_BACKOFF_EXPONENT);
        long duration = saturatingMul(rtt.ptoBase(), backoff);
        if (inFlightAckEliciting == 0) {
            // The client's anti-deadlock probe (RFC 9002 section 6.2.2.1): Handshake if it has the
            // keys, else Initial
            SpaceId id = space(SpaceId.HANDSHAKE).keys != null ? SpaceId.HANDSHAKE : SpaceId.INITIAL;
            return new Deadline(now + duration, id);
        }
        Deadline result = null;
        for (PacketSpace s : spaces) {
            if (!s.hasInFlight()) {
                continue;
            }
            if (s.id() == SpaceId.DATA) {
                if (!handshakeConfirmed) {
                    return result; // skip application data until the handshake is confirmed
                }
                duration = saturatingAdd(duration, saturatingMul(ackFrequency.maxAckDelayForPto(), backoff));
            }
            if (s.timeOfLastAckElicitingPacket == NanoClock.NONE) {
                continue;
            }
            long pto = saturatingAdd(s.timeOfLastAckElicitingPacket, duration);
            if (result == null || pto < result.time()) {
                result = new Deadline(pto, s.id());
            }
        }
        return result;
    }

    /**
     * Whether the peer must have validated this endpoint's address: always for a server; for a
     * client once a Handshake or 1-RTT packet is acknowledged, or the handshake keys are discarded
     * while 1-RTT keys are installed.
     *
     * @return true if the peer completed address validation
     */
    public boolean peerCompletedAddressValidation() {
        if (side.isServer() || closed) {
            return true;
        }
        return space(SpaceId.HANDSHAKE).largestAckedPacket >= 0 || space(SpaceId.DATA).largestAckedPacket >= 0
                || (space(SpaceId.DATA).keys != null && space(SpaceId.HANDSHAKE).keys == null);
    }

    /**
     * Arms or stops {@link Timer#LOSS_DETECTION} (RFC 9002 appendix A.8).
     *
     * @param now the current time
     */
    public void setLossDetectionTimer(long now) {
        if (closed) {
            return; // never rearm on a closed connection
        }
        Deadline loss = lossTimeAndSpace();
        if (loss != null) {
            timers.set(Timer.LOSS_DETECTION, loss.time()); // time-threshold loss detection
            return;
        }
        if (antiAmplificationBlocked(1)) {
            timers.stop(Timer.LOSS_DETECTION); // nothing could be sent anyway
            return;
        }
        if (inFlightAckEliciting == 0 && peerCompletedAddressValidation()) {
            // Nothing to detect, and no anti-amplification deadlock to prevent
            timers.stop(Timer.LOSS_DETECTION);
            return;
        }
        Deadline pto = ptoTimeAndSpace(now);
        if (pto != null) {
            timers.set(Timer.LOSS_DETECTION, pto.time());
        } else {
            timers.stop(Timer.LOSS_DETECTION);
        }
    }

    /**
     * The probe timeout of a space, without backoff: {@code smoothed_rtt + max(4 * rttvar,
     * kGranularity)}, plus the peer's {@code max_ack_delay} in the application data space.
     *
     * @param id the space
     * @return nanoseconds
     */
    public long pto(SpaceId id) {
        long maxAckDelay = id == SpaceId.DATA ? ackFrequency.maxAckDelayForPto() : 0;
        return rtt.ptoBase() + maxAckDelay;
    }

    /**
     * Discards the Initial or Handshake space once its keys are no longer needed (RFC 9001 section
     * 4.9, RFC 9002 section 6.4): its keys, sent packets and in-flight bytes are dropped, and the PTO
     * backoff restarts.
     *
     * @param now the current time
     * @param id {@link SpaceId#INITIAL} or {@link SpaceId#HANDSHAKE}
     */
    public void discardSpace(long now, SpaceId id) {
        if (id == SpaceId.DATA) {
            throw new IllegalArgumentException("the application data space is never discarded");
        }
        PacketSpace space = space(id);
        space.keys = null;
        space.timeOfLastAckElicitingPacket = NanoClock.NONE;
        space.lossTime = NanoClock.NONE;
        space.lossProbes = 0;
        for (SentPacket p : space.sentPackets.clear()) {
            removeInFlight(p);
        }
        space.unackedNonAckElicitingTail = 0;
        ptoCount = 0;
        setLossDetectionTimer(now);
    }

    /**
     * Restarts {@link Timer#IDLE}: the idle timeout, but at least three PTOs (RFC 9000 section
     * 10.1).
     *
     * @param now the current time
     * @param id the space of the packet that prompted the reset
     * @param idleTimeout the negotiated idle timeout in nanoseconds, or 0 for none
     */
    public void resetIdleTimer(long now, SpaceId id, long idleTimeout) {
        if (idleTimeout <= 0) {
            return;
        }
        if (closed) {
            timers.stop(Timer.IDLE);
            return;
        }
        timers.set(Timer.IDLE, now + Math.max(idleTimeout, 3 * pto(id)));
    }

    /**
     * Sets {@link Timer#KEY_DISCARD} to three PTOs after a start time, when old keys may go (RFC
     * 9001 sections 4.9.3 and 6.5).
     *
     * @param start when the timer starts, such as when the key update was acknowledged
     * @param id the space whose PTO applies
     */
    public void setKeyDiscardTimer(long start, SpaceId id) {
        timers.set(Timer.KEY_DISCARD, start + 3 * pto(id));
    }

    // ---------------------------------------------------------------------------------------
    // Statistics

    /**
     * Packets sent.
     *
     * @return the count
     */
    public long sentPackets() {
        return sentPacketCount;
    }

    /**
     * Packets deemed lost, not counting MTU probes.
     *
     * @return the count
     */
    public long lostPackets() {
        return lostPacketCount;
    }

    /**
     * Bytes of packets deemed lost.
     *
     * @return the count
     */
    public long lostBytes() {
        return lostByteCount;
    }

    /**
     * Congestion events, from loss or ECN.
     *
     * @return the count
     */
    public long congestionEvents() {
        return congestionEventCount;
    }

    /**
     * Congestion events found spurious.
     *
     * @return the count
     */
    public long spuriousCongestionEvents() {
        return spuriousCongestionEventCount;
    }

    /**
     * MTU probes lost.
     *
     * @return the count
     */
    public long lostMtuProbes() {
        return lostMtuProbeCount;
    }

    /**
     * MTU black holes detected.
     *
     * @return the count
     */
    public long blackHolesDetected() {
        return blackHoleCount;
    }

    // ---------------------------------------------------------------------------------------

    private void addInFlight(SentPacket p) {
        inFlightBytes += p.size();
        inFlightAckEliciting += p.ackEliciting() ? 1 : 0;
    }

    private void removeInFlight(SentPacket p) {
        inFlightBytes -= p.size();
        inFlightAckEliciting -= p.ackEliciting() ? 1 : 0;
    }

    private static long saturatingMul(long a, long b) {
        long hi = Math.multiplyHigh(a, b);
        long lo = a * b;
        return (hi == 0 && lo >= 0) ? lo : Long.MAX_VALUE;
    }

    private static long saturatingAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
    }
}
