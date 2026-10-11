/*
 * Ported from quinn-proto src/frame.rs (Frame, its structs and their encoders), the budgeted
 * CRYPTO and STREAM writers of src/connection/mod.rs and src/connection/send_buffer.rs, and
 * src/coding.rs (Apache-2.0).
 */
package io.github.mahmoudimus.quic.frame;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.VarInt;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A QUIC frame (RFC 9000 section 19, RFC 9221 and the ACK frequency extension). {@link
 * FrameDecoder} reads frames; {@link #encode(ByteBuffer)} writes one.
 *
 * <p>Frames that carry bytes (CRYPTO, STREAM, DATAGRAM, NEW_TOKEN and the close reasons) hold a
 * {@link ByteBuffer} view: decoded frames point into the decrypted packet without copying, so
 * copy the bytes if they must outlive the packet buffer. Equality compares the bytes. The
 * accessors return independent views.
 *
 * <p>Large frames have budgeted writers, like quinn's packet assembly: {@link
 * Crypto#encode(ByteBuffer, long, ByteBuffer, int)} and {@link Stream#encode(ByteBuffer, long,
 * long, ByteBuffer, boolean, int)} write as much data as fits a byte budget, and {@link
 * ConnectionClose#encode(ByteBuffer, int)} truncates its reason.
 */
public sealed interface Frame permits Frame.Padding, Frame.Ping, Frame.Ack, Frame.ResetStream, Frame.StopSending,
        Frame.Crypto, Frame.NewToken, Frame.Stream, Frame.MaxData, Frame.MaxStreamData, Frame.MaxStreams,
        Frame.DataBlocked, Frame.StreamDataBlocked, Frame.StreamsBlocked, Frame.NewConnectionId,
        Frame.RetireConnectionId, Frame.PathChallenge, Frame.PathResponse, Frame.ConnectionClose,
        Frame.ApplicationClose, Frame.HandshakeDone, Frame.Datagram, Frame.ImmediateAck, Frame.AckFrequency {

    /** The largest stream count MAX_STREAMS and STREAMS_BLOCKED may carry, 2<sup>60</sup>. */
    long MAX_STREAM_COUNT = 1L << 60;

    /**
     * The frame type.
     *
     * @return the type
     */
    FrameType type();

    /**
     * The exact type code this frame encodes with, flags included.
     *
     * @return the type code
     */
    long typeCode();

    /**
     * The encoded length.
     *
     * @return the bytes {@link #encode} writes
     */
    int encodedLength();

    /**
     * Writes the frame at the buffer's position.
     *
     * @param out the buffer
     * @throws BufferOverflowException if fewer than {@link #encodedLength()} bytes remain; nothing
     *     is written then
     */
    void encode(ByteBuffer out);

    /**
     * Whether a packet containing this frame must be acknowledged.
     *
     * @return the type's ack-eliciting property
     */
    default boolean isAckEliciting() {
        return type().isAckEliciting();
    }

    /**
     * A run of PADDING frames (type 0x00), each a single zero byte.
     *
     * @param length how many padding bytes, at least 1
     */
    record Padding(int length) implements Frame {

        /**
         * Padding.
         *
         * @param length how many padding bytes, at least 1
         */
        public Padding {
            if (length < 1) {
                throw new IllegalArgumentException("padding length " + length);
            }
        }

        @Override
        public FrameType type() {
            return FrameType.PADDING;
        }

        @Override
        public long typeCode() {
            return 0x00;
        }

        @Override
        public int encodedLength() {
            return length;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, length);
            for (int i = 0; i < length; i++) {
                out.put((byte) 0);
            }
        }
    }

    /** A PING frame (type 0x01). */
    record Ping() implements Frame {

        @Override
        public FrameType type() {
            return FrameType.PING;
        }

        @Override
        public long typeCode() {
            return 0x01;
        }

        @Override
        public int encodedLength() {
            return 1;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, 1);
            out.put((byte) 0x01);
        }
    }

    /**
     * An inclusive range of acknowledged packet numbers.
     *
     * @param smallest the smallest packet number in the range
     * @param largest the largest packet number in the range
     */
    record AckRange(long smallest, long largest) {

        /**
         * A range.
         *
         * @param smallest the smallest packet number
         * @param largest the largest packet number, at least {@code smallest}
         */
        public AckRange {
            requireVarInt("smallest", smallest);
            requireVarInt("largest", largest);
            if (smallest > largest) {
                throw new IllegalArgumentException("ACK range " + smallest + ".." + largest);
            }
        }

        /**
         * Whether a packet number lies in the range.
         *
         * @param packetNumber the packet number
         * @return true if {@code smallest <= packetNumber <= largest}
         */
        public boolean contains(long packetNumber) {
            return packetNumber >= smallest && packetNumber <= largest;
        }
    }

    /**
     * The ECN counts of an ACK frame of type 0x03 (RFC 9000 section 19.3.2).
     *
     * @param ect0 packets received with the ECT(0) codepoint
     * @param ect1 packets received with the ECT(1) codepoint
     * @param ce packets received with the CE codepoint
     */
    record EcnCounts(long ect0, long ect1, long ce) {

        /**
         * ECN counts.
         *
         * @param ect0 packets received with the ECT(0) codepoint
         * @param ect1 packets received with the ECT(1) codepoint
         * @param ce packets received with the CE codepoint
         */
        public EcnCounts {
            requireVarInt("ect0", ect0);
            requireVarInt("ect1", ect1);
            requireVarInt("ce", ce);
        }
    }

    /**
     * An ACK frame (types 0x02 and 0x03). Ranges run from the largest packet number down, and
     * consecutive ranges are separated by at least one unacknowledged packet number, so they encode
     * exactly as quinn's {@code Ack::encode} does.
     *
     * @param ranges the acknowledged ranges, largest first, at least one
     * @param ackDelay the ACK Delay field, in units of 2<sup>ack_delay_exponent</sup> microseconds
     * @param ecn the ECN counts, or null for a type 0x02 frame
     */
    record Ack(List<AckRange> ranges, long ackDelay, EcnCounts ecn) implements Frame {

        /**
         * An ACK frame.
         *
         * @param ranges the acknowledged ranges, largest first, separated by gaps
         * @param ackDelay the encoded ACK delay
         * @param ecn the ECN counts, or null
         */
        public Ack {
            ranges = List.copyOf(ranges);
            if (ranges.isEmpty()) {
                throw new IllegalArgumentException("ACK frame without ranges");
            }
            for (int i = 1; i < ranges.size(); i++) {
                if (ranges.get(i).largest() > ranges.get(i - 1).smallest() - 2) {
                    throw new IllegalArgumentException("ACK ranges must descend with gaps: " + ranges);
                }
            }
            requireVarInt("ackDelay", ackDelay);
        }

        /**
         * An ACK frame for a set of packet numbers, in any order and with duplicates: they are
         * sorted and merged into ranges.
         *
         * @param ackDelay the encoded ACK delay
         * @param ecn the ECN counts, or null
         * @param packetNumbers the acknowledged packet numbers, at least one
         * @return the frame
         */
        public static Ack of(long ackDelay, EcnCounts ecn, long... packetNumbers) {
            long[] sorted = packetNumbers.clone();
            Arrays.sort(sorted);
            List<AckRange> ranges = new ArrayList<>();
            int i = sorted.length - 1;
            while (i >= 0) {
                long hi = sorted[i];
                long lo = hi;
                while (i > 0 && (sorted[i - 1] == lo || sorted[i - 1] == lo - 1)) {
                    lo = sorted[--i];
                }
                i--;
                ranges.add(new AckRange(lo, hi));
            }
            return new Ack(ranges, ackDelay, ecn);
        }

        /**
         * The largest acknowledged packet number.
         *
         * @return the first range's largest packet number
         */
        public long largest() {
            return ranges.get(0).largest();
        }

        /**
         * Whether the frame acknowledges a packet number.
         *
         * @param packetNumber the packet number
         * @return true if a range contains it
         */
        public boolean contains(long packetNumber) {
            for (AckRange r : ranges) {
                if (r.contains(packetNumber)) return true;
            }
            return false;
        }

        @Override
        public FrameType type() {
            return FrameType.ACK;
        }

        @Override
        public long typeCode() {
            return ecn == null ? 0x02 : 0x03;
        }

        @Override
        public int encodedLength() {
            AckRange first = ranges.get(0);
            int n = 1 + VarInt.size(first.largest()) + VarInt.size(ackDelay) + VarInt.size(ranges.size() - 1)
                    + VarInt.size(first.largest() - first.smallest());
            long prev = first.smallest();
            for (int i = 1; i < ranges.size(); i++) {
                AckRange r = ranges.get(i);
                n += VarInt.size(prev - r.largest() - 2) + VarInt.size(r.largest() - r.smallest());
                prev = r.smallest();
            }
            if (ecn != null) {
                n += VarInt.size(ecn.ect0()) + VarInt.size(ecn.ect1()) + VarInt.size(ecn.ce());
            }
            return n;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            AckRange first = ranges.get(0);
            out.put((byte) typeCode());
            VarInt.write(out, first.largest());
            VarInt.write(out, ackDelay);
            VarInt.write(out, ranges.size() - 1);
            VarInt.write(out, first.largest() - first.smallest());
            long prev = first.smallest();
            for (int i = 1; i < ranges.size(); i++) {
                AckRange r = ranges.get(i);
                VarInt.write(out, prev - r.largest() - 2);
                VarInt.write(out, r.largest() - r.smallest());
                prev = r.smallest();
            }
            if (ecn != null) {
                VarInt.write(out, ecn.ect0());
                VarInt.write(out, ecn.ect1());
                VarInt.write(out, ecn.ce());
            }
        }
    }

    /**
     * A RESET_STREAM frame (type 0x04).
     *
     * @param streamId the stream ID
     * @param errorCode the application error code
     * @param finalSize the stream's final size
     */
    record ResetStream(long streamId, long errorCode, long finalSize) implements Frame {

        /**
         * A RESET_STREAM frame.
         *
         * @param streamId the stream ID
         * @param errorCode the application error code
         * @param finalSize the stream's final size
         */
        public ResetStream {
            requireVarInt("streamId", streamId);
            requireVarInt("errorCode", errorCode);
            requireVarInt("finalSize", finalSize);
        }

        @Override
        public FrameType type() {
            return FrameType.RESET_STREAM;
        }

        @Override
        public long typeCode() {
            return 0x04;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(streamId) + VarInt.size(errorCode) + VarInt.size(finalSize);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x04);
            VarInt.write(out, streamId);
            VarInt.write(out, errorCode);
            VarInt.write(out, finalSize);
        }
    }

    /**
     * A STOP_SENDING frame (type 0x05).
     *
     * @param streamId the stream ID
     * @param errorCode the application error code
     */
    record StopSending(long streamId, long errorCode) implements Frame {

        /**
         * A STOP_SENDING frame.
         *
         * @param streamId the stream ID
         * @param errorCode the application error code
         */
        public StopSending {
            requireVarInt("streamId", streamId);
            requireVarInt("errorCode", errorCode);
        }

        @Override
        public FrameType type() {
            return FrameType.STOP_SENDING;
        }

        @Override
        public long typeCode() {
            return 0x05;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(streamId) + VarInt.size(errorCode);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x05);
            VarInt.write(out, streamId);
            VarInt.write(out, errorCode);
        }
    }

    /**
     * A CRYPTO frame (type 0x06), carrying TLS handshake bytes.
     *
     * @param offset the offset of the data in the level's crypto stream
     * @param data the data
     */
    record Crypto(long offset, ByteBuffer data) implements Frame {

        /**
         * A CRYPTO frame.
         *
         * @param offset the stream offset
         * @param data the data between its position and limit
         */
        public Crypto {
            requireVarInt("offset", offset);
            data = data.slice();
            if (offset + data.remaining() > VarInt.MAX) {
                throw new IllegalArgumentException("CRYPTO data past 2^62-1");
            }
        }

        /**
         * The data.
         *
         * @return an independent view of the data
         */
        @Override
        public ByteBuffer data() {
            return data.duplicate();
        }

        /**
         * Writes as much of the data as fits a byte budget in one CRYPTO frame, with an exact
         * Length field, as quinn fills packets with handshake data.
         *
         * @param out the buffer, written at its position
         * @param offset the crypto stream offset of the first byte
         * @param data the data to send; its position moves past the bytes written
         * @param budget the most bytes the frame may take (also bounded by {@code
         *     out.remaining()})
         * @return the data bytes written; 0 if {@code data} is empty, in which case nothing is
         *     written; -1 if not even one byte fits
         */
        public static int encode(ByteBuffer out, long offset, ByteBuffer data, int budget) {
            if (!data.hasRemaining()) {
                return 0;
            }
            int avail = Math.min(budget, out.remaining()) - 1 - VarInt.size(offset);
            int n = fitWithLength(avail, data.remaining());
            if (n <= 0) {
                return -1;
            }
            out.put((byte) 0x06);
            VarInt.write(out, offset);
            VarInt.write(out, n);
            out.put(data.slice(data.position(), n));
            data.position(data.position() + n);
            return n;
        }

        @Override
        public FrameType type() {
            return FrameType.CRYPTO;
        }

        @Override
        public long typeCode() {
            return 0x06;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(offset) + VarInt.size(data.remaining()) + data.remaining();
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x06);
            VarInt.write(out, offset);
            VarInt.write(out, data.remaining());
            out.put(data.duplicate());
        }
    }

    /**
     * A NEW_TOKEN frame (type 0x07), with a token for future connections.
     *
     * @param token the token, not empty
     */
    record NewToken(ByteBuffer token) implements Frame {

        /**
         * A NEW_TOKEN frame.
         *
         * @param token the token between its position and limit, not empty
         */
        public NewToken {
            token = token.slice();
            if (!token.hasRemaining()) {
                throw new IllegalArgumentException("empty NEW_TOKEN token");
            }
        }

        /**
         * The token.
         *
         * @return an independent view of the token
         */
        @Override
        public ByteBuffer token() {
            return token.duplicate();
        }

        @Override
        public FrameType type() {
            return FrameType.NEW_TOKEN;
        }

        @Override
        public long typeCode() {
            return 0x07;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(token.remaining()) + token.remaining();
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x07);
            VarInt.write(out, token.remaining());
            out.put(token.duplicate());
        }
    }

    /**
     * A STREAM frame (types 0x08 to 0x0f). {@link #encode(ByteBuffer)} always writes the Length
     * field, and the Offset field when the offset is not zero.
     *
     * @param streamId the stream ID
     * @param offset the offset of the data in the stream
     * @param data the data
     * @param fin whether the data ends the stream
     */
    record Stream(long streamId, long offset, ByteBuffer data, boolean fin) implements Frame {

        /**
         * A STREAM frame.
         *
         * @param streamId the stream ID
         * @param offset the stream offset
         * @param data the data between its position and limit
         * @param fin whether the data ends the stream
         */
        public Stream {
            requireVarInt("streamId", streamId);
            requireVarInt("offset", offset);
            data = data.slice();
            if (offset + data.remaining() > VarInt.MAX) {
                throw new IllegalArgumentException("STREAM data past 2^62-1");
            }
        }

        /**
         * The data.
         *
         * @return an independent view of the data
         */
        @Override
        public ByteBuffer data() {
            return data.duplicate();
        }

        /**
         * Writes as much stream data as fits a byte budget in one STREAM frame, as quinn's
         * {@code write_stream_frames} does. When all the data fits with a Length field the frame
         * has one; otherwise the frame omits it, fills the whole budget and must be the last frame
         * in the packet, so pass the packet's remaining space as the budget. FIN is set only if
         * all the data is written.
         *
         * @param out the buffer, written at its position
         * @param streamId the stream ID
         * @param offset the stream offset of the first byte
         * @param data the data to send; its position moves past the bytes written
         * @param fin whether the data ends the stream
         * @param budget the most bytes the frame may take (also bounded by {@code
         *     out.remaining()})
         * @return the data bytes written (0 for a FIN-only or empty frame), or -1 if the frame
         *     did not fit and nothing was written
         */
        public static int encode(ByteBuffer out, long streamId, long offset, ByteBuffer data, boolean fin, int budget) {
            requireVarInt("streamId", streamId);
            requireVarInt("offset", offset);
            int len = data.remaining();
            int header = 1 + VarInt.size(streamId) + (offset != 0 ? VarInt.size(offset) : 0);
            int avail = Math.min(budget, out.remaining()) - header;
            int withLength = fitWithLength(avail, len);
            int n;
            boolean lengthField;
            if (withLength == len) {
                n = len;
                lengthField = true;
            } else if (avail > 0) {
                n = avail;
                lengthField = false;
            } else {
                return -1;
            }
            boolean finBit = fin && n == len;
            out.put((byte) (0x08 | (offset != 0 ? 0x04 : 0) | (lengthField ? 0x02 : 0) | (finBit ? 0x01 : 0)));
            VarInt.write(out, streamId);
            if (offset != 0) {
                VarInt.write(out, offset);
            }
            if (lengthField) {
                VarInt.write(out, n);
            }
            out.put(data.slice(data.position(), n));
            data.position(data.position() + n);
            return n;
        }

        @Override
        public FrameType type() {
            return FrameType.STREAM;
        }

        @Override
        public long typeCode() {
            return 0x08 | (offset != 0 ? 0x04 : 0) | 0x02 | (fin ? 0x01 : 0);
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(streamId) + (offset != 0 ? VarInt.size(offset) : 0)
                    + VarInt.size(data.remaining()) + data.remaining();
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) typeCode());
            VarInt.write(out, streamId);
            if (offset != 0) {
                VarInt.write(out, offset);
            }
            VarInt.write(out, data.remaining());
            out.put(data.duplicate());
        }
    }

    /**
     * A MAX_DATA frame (type 0x10).
     *
     * @param maximum the connection's flow control limit, in bytes
     */
    record MaxData(long maximum) implements Frame {

        /**
         * A MAX_DATA frame.
         *
         * @param maximum the connection's flow control limit
         */
        public MaxData {
            requireVarInt("maximum", maximum);
        }

        @Override
        public FrameType type() {
            return FrameType.MAX_DATA;
        }

        @Override
        public long typeCode() {
            return 0x10;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(maximum);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x10);
            VarInt.write(out, maximum);
        }
    }

    /**
     * A MAX_STREAM_DATA frame (type 0x11).
     *
     * @param streamId the stream ID
     * @param maximum the stream's flow control limit, in bytes
     */
    record MaxStreamData(long streamId, long maximum) implements Frame {

        /**
         * A MAX_STREAM_DATA frame.
         *
         * @param streamId the stream ID
         * @param maximum the stream's flow control limit
         */
        public MaxStreamData {
            requireVarInt("streamId", streamId);
            requireVarInt("maximum", maximum);
        }

        @Override
        public FrameType type() {
            return FrameType.MAX_STREAM_DATA;
        }

        @Override
        public long typeCode() {
            return 0x11;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(streamId) + VarInt.size(maximum);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x11);
            VarInt.write(out, streamId);
            VarInt.write(out, maximum);
        }
    }

    /**
     * A MAX_STREAMS frame (0x12 bidirectional, 0x13 unidirectional).
     *
     * @param bidirectional whether the limit is for bidirectional streams
     * @param maximum the cumulative stream count limit, at most 2<sup>60</sup>
     */
    record MaxStreams(boolean bidirectional, long maximum) implements Frame {

        /**
         * A MAX_STREAMS frame.
         *
         * @param bidirectional whether the limit is for bidirectional streams
         * @param maximum the stream count limit, at most 2<sup>60</sup>
         */
        public MaxStreams {
            if (maximum < 0 || maximum > MAX_STREAM_COUNT) {
                throw new IllegalArgumentException("stream count " + maximum);
            }
        }

        @Override
        public FrameType type() {
            return FrameType.MAX_STREAMS;
        }

        @Override
        public long typeCode() {
            return bidirectional ? 0x12 : 0x13;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(maximum);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) typeCode());
            VarInt.write(out, maximum);
        }
    }

    /**
     * A DATA_BLOCKED frame (type 0x14).
     *
     * @param limit the connection limit at which the sender is blocked
     */
    record DataBlocked(long limit) implements Frame {

        /**
         * A DATA_BLOCKED frame.
         *
         * @param limit the connection limit at which the sender is blocked
         */
        public DataBlocked {
            requireVarInt("limit", limit);
        }

        @Override
        public FrameType type() {
            return FrameType.DATA_BLOCKED;
        }

        @Override
        public long typeCode() {
            return 0x14;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(limit);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x14);
            VarInt.write(out, limit);
        }
    }

    /**
     * A STREAM_DATA_BLOCKED frame (type 0x15).
     *
     * @param streamId the stream ID
     * @param limit the stream limit at which the sender is blocked
     */
    record StreamDataBlocked(long streamId, long limit) implements Frame {

        /**
         * A STREAM_DATA_BLOCKED frame.
         *
         * @param streamId the stream ID
         * @param limit the stream limit at which the sender is blocked
         */
        public StreamDataBlocked {
            requireVarInt("streamId", streamId);
            requireVarInt("limit", limit);
        }

        @Override
        public FrameType type() {
            return FrameType.STREAM_DATA_BLOCKED;
        }

        @Override
        public long typeCode() {
            return 0x15;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(streamId) + VarInt.size(limit);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x15);
            VarInt.write(out, streamId);
            VarInt.write(out, limit);
        }
    }

    /**
     * A STREAMS_BLOCKED frame (0x16 bidirectional, 0x17 unidirectional).
     *
     * @param bidirectional whether the limit is for bidirectional streams
     * @param limit the stream count limit at which the sender is blocked, at most 2<sup>60</sup>
     */
    record StreamsBlocked(boolean bidirectional, long limit) implements Frame {

        /**
         * A STREAMS_BLOCKED frame.
         *
         * @param bidirectional whether the limit is for bidirectional streams
         * @param limit the stream count limit, at most 2<sup>60</sup>
         */
        public StreamsBlocked {
            if (limit < 0 || limit > MAX_STREAM_COUNT) {
                throw new IllegalArgumentException("stream count " + limit);
            }
        }

        @Override
        public FrameType type() {
            return FrameType.STREAMS_BLOCKED;
        }

        @Override
        public long typeCode() {
            return bidirectional ? 0x16 : 0x17;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(limit);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) typeCode());
            VarInt.write(out, limit);
        }
    }

    /**
     * A NEW_CONNECTION_ID frame (type 0x18).
     *
     * @param sequence the sequence number of the connection ID
     * @param retirePriorTo the sequence number below which connection IDs must be retired, at
     *     most {@code sequence}
     * @param connectionId the new connection ID, 1 to 20 bytes
     * @param resetToken the stateless reset token for the connection ID
     */
    record NewConnectionId(long sequence, long retirePriorTo, ConnectionId connectionId,
            StatelessResetToken resetToken) implements Frame {

        /**
         * A NEW_CONNECTION_ID frame.
         *
         * @param sequence the sequence number
         * @param retirePriorTo the Retire Prior To field, at most {@code sequence}
         * @param connectionId the connection ID, 1 to 20 bytes
         * @param resetToken the stateless reset token
         */
        public NewConnectionId {
            requireVarInt("sequence", sequence);
            requireVarInt("retirePriorTo", retirePriorTo);
            if (retirePriorTo > sequence) {
                throw new IllegalArgumentException("retirePriorTo " + retirePriorTo + " above sequence " + sequence);
            }
            if (connectionId.isEmpty()) {
                throw new IllegalArgumentException("empty connection ID");
            }
            Objects.requireNonNull(resetToken, "resetToken");
        }

        @Override
        public FrameType type() {
            return FrameType.NEW_CONNECTION_ID;
        }

        @Override
        public long typeCode() {
            return 0x18;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(sequence) + VarInt.size(retirePriorTo) + 1 + connectionId.length()
                    + StatelessResetToken.LENGTH;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x18);
            VarInt.write(out, sequence);
            VarInt.write(out, retirePriorTo);
            out.put((byte) connectionId.length());
            connectionId.writeTo(out);
            resetToken.writeTo(out);
        }
    }

    /**
     * A RETIRE_CONNECTION_ID frame (type 0x19).
     *
     * @param sequence the sequence number of the connection ID being retired
     */
    record RetireConnectionId(long sequence) implements Frame {

        /**
         * A RETIRE_CONNECTION_ID frame.
         *
         * @param sequence the sequence number of the connection ID being retired
         */
        public RetireConnectionId {
            requireVarInt("sequence", sequence);
        }

        @Override
        public FrameType type() {
            return FrameType.RETIRE_CONNECTION_ID;
        }

        @Override
        public long typeCode() {
            return 0x19;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(sequence);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            out.put((byte) 0x19);
            VarInt.write(out, sequence);
        }
    }

    /**
     * A PATH_CHALLENGE frame (type 0x1a).
     *
     * @param data the 8 bytes of challenge data, big-endian
     */
    record PathChallenge(long data) implements Frame {

        @Override
        public FrameType type() {
            return FrameType.PATH_CHALLENGE;
        }

        @Override
        public long typeCode() {
            return 0x1a;
        }

        @Override
        public int encodedLength() {
            return 9;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, 9);
            out.put((byte) 0x1a);
            out.putLong(data);
        }
    }

    /**
     * A PATH_RESPONSE frame (type 0x1b).
     *
     * @param data the 8 bytes echoed from the PATH_CHALLENGE, big-endian
     */
    record PathResponse(long data) implements Frame {

        @Override
        public FrameType type() {
            return FrameType.PATH_RESPONSE;
        }

        @Override
        public long typeCode() {
            return 0x1b;
        }

        @Override
        public int encodedLength() {
            return 9;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, 9);
            out.put((byte) 0x1b);
            out.putLong(data);
        }
    }

    /**
     * A CONNECTION_CLOSE frame for a transport error (type 0x1c).
     *
     * @param errorCode the transport error code
     * @param frameType the type of the frame that caused the error, or 0 if unknown
     * @param reason the reason phrase, UTF-8 by convention
     */
    record ConnectionClose(long errorCode, long frameType, ByteBuffer reason) implements Frame {

        /**
         * A transport CONNECTION_CLOSE frame.
         *
         * @param errorCode the transport error code
         * @param frameType the type of the offending frame, or 0
         * @param reason the reason phrase between its position and limit
         */
        public ConnectionClose {
            requireVarInt("errorCode", errorCode);
            requireVarInt("frameType", frameType);
            reason = reason.slice();
        }

        /**
         * A transport CONNECTION_CLOSE frame with a text reason.
         *
         * @param errorCode the transport error code
         * @param frameType the type of the offending frame, or 0
         * @param reason the reason phrase
         * @return the frame
         */
        public static ConnectionClose of(long errorCode, long frameType, String reason) {
            return new ConnectionClose(errorCode, frameType, ByteBuffer.wrap(reason.getBytes(StandardCharsets.UTF_8)));
        }

        /**
         * The reason phrase.
         *
         * @return an independent view of the reason bytes
         */
        @Override
        public ByteBuffer reason() {
            return reason.duplicate();
        }

        /**
         * The reason phrase as text.
         *
         * @return the reason decoded as UTF-8, with malformed bytes replaced
         */
        public String reasonPhrase() {
            return StandardCharsets.UTF_8.decode(reason.duplicate()).toString();
        }

        /**
         * Writes the frame, truncating the reason phrase to fit a byte budget, as quinn does.
         *
         * @param out the buffer, written at its position
         * @param budget the most bytes the frame may take (also bounded by {@code
         *     out.remaining()})
         * @return false if not even an empty reason fits, in which case nothing is written
         */
        public boolean encode(ByteBuffer out, int budget) {
            int avail = Math.min(budget, out.remaining()) - 1 - VarInt.size(errorCode) - VarInt.size(frameType);
            int n = fitWithLength(avail, reason.remaining());
            if (n < 0) {
                return false;
            }
            out.put((byte) 0x1c);
            VarInt.write(out, errorCode);
            VarInt.write(out, frameType);
            VarInt.write(out, n);
            out.put(reason.slice(0, n));
            return true;
        }

        @Override
        public FrameType type() {
            return FrameType.CONNECTION_CLOSE;
        }

        @Override
        public long typeCode() {
            return 0x1c;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(errorCode) + VarInt.size(frameType) + VarInt.size(reason.remaining())
                    + reason.remaining();
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            encode(out, Integer.MAX_VALUE);
        }
    }

    /**
     * A CONNECTION_CLOSE frame for an application error (type 0x1d), allowed only in 0-RTT and
     * 1-RTT packets.
     *
     * @param errorCode the application error code
     * @param reason the reason phrase, UTF-8 by convention
     */
    record ApplicationClose(long errorCode, ByteBuffer reason) implements Frame {

        /**
         * An application CONNECTION_CLOSE frame.
         *
         * @param errorCode the application error code
         * @param reason the reason phrase between its position and limit
         */
        public ApplicationClose {
            requireVarInt("errorCode", errorCode);
            reason = reason.slice();
        }

        /**
         * An application CONNECTION_CLOSE frame with a text reason.
         *
         * @param errorCode the application error code
         * @param reason the reason phrase
         * @return the frame
         */
        public static ApplicationClose of(long errorCode, String reason) {
            return new ApplicationClose(errorCode, ByteBuffer.wrap(reason.getBytes(StandardCharsets.UTF_8)));
        }

        /**
         * The reason phrase.
         *
         * @return an independent view of the reason bytes
         */
        @Override
        public ByteBuffer reason() {
            return reason.duplicate();
        }

        /**
         * The reason phrase as text.
         *
         * @return the reason decoded as UTF-8, with malformed bytes replaced
         */
        public String reasonPhrase() {
            return StandardCharsets.UTF_8.decode(reason.duplicate()).toString();
        }

        /**
         * Writes the frame, truncating the reason phrase to fit a byte budget.
         *
         * @param out the buffer, written at its position
         * @param budget the most bytes the frame may take (also bounded by {@code
         *     out.remaining()})
         * @return false if not even an empty reason fits, in which case nothing is written
         */
        public boolean encode(ByteBuffer out, int budget) {
            int avail = Math.min(budget, out.remaining()) - 1 - VarInt.size(errorCode);
            int n = fitWithLength(avail, reason.remaining());
            if (n < 0) {
                return false;
            }
            out.put((byte) 0x1d);
            VarInt.write(out, errorCode);
            VarInt.write(out, n);
            out.put(reason.slice(0, n));
            return true;
        }

        @Override
        public FrameType type() {
            return FrameType.APPLICATION_CLOSE;
        }

        @Override
        public long typeCode() {
            return 0x1d;
        }

        @Override
        public int encodedLength() {
            return 1 + VarInt.size(errorCode) + VarInt.size(reason.remaining()) + reason.remaining();
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            encode(out, Integer.MAX_VALUE);
        }
    }

    /** A HANDSHAKE_DONE frame (type 0x1e). */
    record HandshakeDone() implements Frame {

        @Override
        public FrameType type() {
            return FrameType.HANDSHAKE_DONE;
        }

        @Override
        public long typeCode() {
            return 0x1e;
        }

        @Override
        public int encodedLength() {
            return 1;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, 1);
            out.put((byte) 0x1e);
        }
    }

    /**
     * A DATAGRAM frame (RFC 9221; 0x30 without and 0x31 with a Length field). {@link
     * #encode(ByteBuffer)} writes the Length field.
     *
     * @param data the unreliable datagram payload
     */
    record Datagram(ByteBuffer data) implements Frame {

        /**
         * A DATAGRAM frame.
         *
         * @param data the payload between its position and limit
         */
        public Datagram {
            data = data.slice();
        }

        /**
         * The payload.
         *
         * @return an independent view of the payload
         */
        @Override
        public ByteBuffer data() {
            return data.duplicate();
        }

        /**
         * The encoded length with or without the Length field.
         *
         * @param withLength whether to count the Length field
         * @return the frame length in bytes
         */
        public int encodedLength(boolean withLength) {
            return 1 + (withLength ? VarInt.size(data.remaining()) : 0) + data.remaining();
        }

        /**
         * Writes the frame, with the Length field or, when it ends the packet, without.
         *
         * @param out the buffer, written at its position
         * @param withLength whether to write the Length field (type 0x31)
         * @throws BufferOverflowException if the frame does not fit; nothing is written then
         */
        public void encode(ByteBuffer out, boolean withLength) {
            ensure(out, encodedLength(withLength));
            out.put((byte) (withLength ? 0x31 : 0x30));
            if (withLength) {
                VarInt.write(out, data.remaining());
            }
            out.put(data.duplicate());
        }

        @Override
        public FrameType type() {
            return FrameType.DATAGRAM;
        }

        @Override
        public long typeCode() {
            return 0x31;
        }

        @Override
        public int encodedLength() {
            return encodedLength(true);
        }

        @Override
        public void encode(ByteBuffer out) {
            encode(out, true);
        }
    }

    /** An IMMEDIATE_ACK frame (type 0x1f) of the QUIC ACK frequency extension. */
    record ImmediateAck() implements Frame {

        @Override
        public FrameType type() {
            return FrameType.IMMEDIATE_ACK;
        }

        @Override
        public long typeCode() {
            return 0x1f;
        }

        @Override
        public int encodedLength() {
            return 1;
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, 1);
            out.put((byte) 0x1f);
        }
    }

    /**
     * An ACK_FREQUENCY frame (type 0xaf) of the QUIC ACK frequency extension, as quinn implements
     * it.
     *
     * @param sequenceNumber the sequence number, which orders ACK_FREQUENCY frames
     * @param ackElicitingThreshold how many ack-eliciting packets may arrive before an ACK
     * @param requestMaxAckDelay the requested maximum ACK delay, in microseconds
     * @param reorderingThreshold how much reordering triggers an immediate ACK
     */
    record AckFrequency(long sequenceNumber, long ackElicitingThreshold, long requestMaxAckDelay,
            long reorderingThreshold) implements Frame {

        /**
         * An ACK_FREQUENCY frame.
         *
         * @param sequenceNumber the sequence number
         * @param ackElicitingThreshold the ack-eliciting threshold
         * @param requestMaxAckDelay the requested maximum ACK delay, in microseconds
         * @param reorderingThreshold the reordering threshold
         */
        public AckFrequency {
            requireVarInt("sequenceNumber", sequenceNumber);
            requireVarInt("ackElicitingThreshold", ackElicitingThreshold);
            requireVarInt("requestMaxAckDelay", requestMaxAckDelay);
            requireVarInt("reorderingThreshold", reorderingThreshold);
        }

        @Override
        public FrameType type() {
            return FrameType.ACK_FREQUENCY;
        }

        @Override
        public long typeCode() {
            return 0xaf;
        }

        @Override
        public int encodedLength() {
            return VarInt.size(0xaf) + VarInt.size(sequenceNumber) + VarInt.size(ackElicitingThreshold)
                    + VarInt.size(requestMaxAckDelay) + VarInt.size(reorderingThreshold);
        }

        @Override
        public void encode(ByteBuffer out) {
            ensure(out, encodedLength());
            VarInt.write(out, 0xaf);
            VarInt.write(out, sequenceNumber);
            VarInt.write(out, ackElicitingThreshold);
            VarInt.write(out, requestMaxAckDelay);
            VarInt.write(out, reorderingThreshold);
        }
    }

    private static void requireVarInt(String name, long value) {
        if (value < 0 || value > VarInt.MAX) {
            throw new IllegalArgumentException(name + " out of varint range: " + value);
        }
    }

    private static void ensure(ByteBuffer out, int length) {
        if (out.remaining() < length) {
            throw new BufferOverflowException();
        }
    }

    /**
     * The most bytes of a length-prefixed field that fit in {@code avail} bytes, prefix included.
     *
     * @return up to {@code len}, or -1 if not even an empty field fits
     */
    private static int fitWithLength(int avail, int len) {
        int best = -1;
        for (int size : new int[] {1, 2, 4, 8}) {
            long n = Math.min(Math.min(len, (long) avail - size), VarInt.maxForSize(size));
            if (n > best) {
                best = (int) n;
            }
        }
        return best;
    }
}
