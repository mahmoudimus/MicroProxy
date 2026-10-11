/*
 * Ported from quinn-proto src/connection/sent_packets.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import java.util.Collection;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

/**
 * The sent packets of one packet number space that are neither acknowledged nor lost, by packet
 * number. Storage depends on the number of packets tracked, not on the distance between their
 * numbers.
 *
 * <p><b>Threads.</b> Not thread-safe; owned by one connection.
 */
public final class SentPackets {

    private final TreeMap<Long, SentPacket> packets = new TreeMap<>();
    /** The number of packets with a nonzero size. */
    private int inFlight;

    /** No packets. */
    public SentPackets() {}

    /**
     * Adds a packet, whose number must exceed every number added before.
     *
     * @param pn the packet number
     * @param packet the packet
     * @throws IllegalArgumentException if {@code pn} does not increase
     */
    public void insert(long pn, SentPacket packet) {
        if (!packets.isEmpty() && pn <= packets.lastKey()) {
            throw new IllegalArgumentException("packet number " + pn + " not above " + packets.lastKey());
        }
        if (packet.size() != 0) {
            inFlight++;
        }
        packets.put(pn, packet);
    }

    /**
     * Removes a packet.
     *
     * @param pn the packet number
     * @return the packet, or null if it was not tracked
     */
    public SentPacket remove(long pn) {
        SentPacket p = packets.remove(pn);
        if (p != null && p.size() != 0) {
            inFlight--;
        }
        return p;
    }

    /**
     * A packet.
     *
     * @param pn the packet number
     * @return the packet, or null if not tracked
     */
    public SentPacket get(long pn) {
        return packets.get(pn);
    }

    /**
     * Whether any tracked packet counts in flight.
     *
     * @return true if one has a nonzero size
     */
    public boolean hasInFlight() {
        return inFlight != 0;
    }

    /**
     * The packets numbered {@code [from, to)}, in increasing order.
     *
     * @param from the first packet number
     * @param to one past the last packet number
     * @return a live view
     */
    public NavigableMap<Long, SentPacket> range(long from, long to) {
        if (to <= from) {
            return new TreeMap<>();
        }
        return packets.subMap(from, true, to, false);
    }

    /**
     * The first packet numbered above {@code pn}.
     *
     * @param pn the packet number
     * @return the entry, or null
     */
    public Map.Entry<Long, SentPacket> higher(long pn) {
        return packets.higherEntry(pn);
    }

    /**
     * Every packet, in increasing order.
     *
     * @return a live view
     */
    public Collection<SentPacket> values() {
        return packets.values();
    }

    /**
     * The number of packets tracked.
     *
     * @return the count
     */
    public int size() {
        return packets.size();
    }

    /**
     * Removes every packet.
     *
     * @return the packets removed, in increasing order
     */
    public Collection<SentPacket> clear() {
        Collection<SentPacket> all = new java.util.ArrayList<>(packets.values());
        packets.clear();
        inFlight = 0;
        return all;
    }
}
