/*
 * Ported from quinn-proto src/lib.rs (StreamId) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.VarInt;

/**
 * A stream ID (RFC 9000 section 2.1): the two low bits give the initiator and direction, the rest
 * the stream's index among the streams of that type.
 *
 * @param value the 62-bit stream ID as sent on the wire
 */
public record StreamId(long value) implements Comparable<StreamId> {

    /**
     * A stream ID.
     *
     * @param value 0 to 2<sup>62</sup>-1
     */
    public StreamId {
        if (value < 0 || value > VarInt.MAX) {
            throw new IllegalArgumentException("stream ID " + value);
        }
    }

    /**
     * The stream ID of a stream type and index.
     *
     * @param initiator the side that opens the stream
     * @param dir the stream's directionality
     * @param index the stream's index among streams of its type, below 2<sup>60</sup>
     * @return the stream ID
     */
    public static StreamId of(Side initiator, Dir dir, long index) {
        return new StreamId(index << 2 | (long) dir.ordinal() << 1 | initiator.ordinal());
    }

    /**
     * The side that opened the stream.
     *
     * @return the initiator
     */
    public Side initiator() {
        return (value & 1) == 0 ? Side.CLIENT : Side.SERVER;
    }

    /**
     * The stream's directionality.
     *
     * @return {@link Dir#BI} or {@link Dir#UNI}
     */
    public Dir dir() {
        return (value & 2) == 0 ? Dir.BI : Dir.UNI;
    }

    /**
     * The stream's index among streams of its type.
     *
     * @return the index
     */
    public long index() {
        return value >>> 2;
    }

    @Override
    public int compareTo(StreamId o) {
        return Long.compare(value, o.value);
    }

    /** As in {@code client bidirectional stream 0}. */
    @Override
    public String toString() {
        return (initiator() == Side.CLIENT ? "client " : "server ")
                + (dir() == Dir.BI ? "bidirectional" : "unidirectional") + " stream " + index();
    }
}
