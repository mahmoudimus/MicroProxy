/*
 * Ported from quinn-proto src/frame.rs (Iter::try_next, scan_ack_blocks) (Apache-2.0), with the
 * validation rules of RFC 9000 section 19 and the packet type rules of Table 3.
 */
package io.github.mahmoudimus.quic.frame;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.packet.PacketType;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes the frames of a decrypted packet payload. Every malformed frame is a {@link
 * FrameException} with {@code FRAME_ENCODING_ERROR} (RFC 9000 section 12.4), except a frame in a
 * packet type that does not allow it, a frame type in a longer encoding than needed, and an empty
 * payload, which are {@code PROTOCOL_VIOLATION}s. Nothing else is thrown for any input.
 *
 * <p>Decoded frames that carry bytes are views of the payload buffer. All methods are static and
 * thread-safe as long as the buffer is not shared.
 */
public final class FrameDecoder {

    private FrameDecoder() {}

    /**
     * Decodes every frame of a packet payload, checking each against the packet type.
     *
     * @param payload the plaintext payload between its position and limit; its position moves to
     *     the limit
     * @param packetType the type of the packet the payload came in
     * @return the frames, with each run of PADDING as one {@link Frame.Padding}
     * @throws FrameException if the payload is empty or a frame is malformed or not allowed
     */
    public static List<Frame> decodeAll(ByteBuffer payload, PacketType packetType) throws FrameException {
        if (!payload.hasRemaining()) {
            throw new FrameException(QuicException.PROTOCOL_VIOLATION, 0, "packet payload is empty");
        }
        List<Frame> frames = new ArrayList<>();
        while (payload.hasRemaining()) {
            Frame frame = decode(payload);
            if (!frame.type().isAllowedIn(packetType)) {
                throw new FrameException(QuicException.PROTOCOL_VIOLATION, frame.typeCode(),
                        frame.type() + " frame not allowed in " + packetType + " packets");
            }
            frames.add(frame);
        }
        return frames;
    }

    /**
     * Decodes one frame at the buffer's position.
     *
     * @param in the payload; its position moves past the frame
     * @return the frame; a run of PADDING bytes is one {@link Frame.Padding}
     * @throws FrameException if the frame is malformed, truncated or of an unknown type
     */
    public static Frame decode(ByteBuffer in) throws FrameException {
        int start = in.position();
        long type;
        try {
            type = VarInt.read(in);
        } catch (BufferUnderflowException e) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, 0, "truncated frame type");
        }
        if (in.position() - start != VarInt.size(type)) {
            throw new FrameException(QuicException.PROTOCOL_VIOLATION, type, "frame type not minimally encoded");
        }
        FrameType frameType = FrameType.forCode(type);
        if (frameType == null) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, String.format("unknown frame type 0x%x", type));
        }
        try {
            return decodeBody(in, type, frameType);
        } catch (BufferUnderflowException e) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "truncated " + frameType + " frame");
        } catch (IllegalArgumentException e) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type,
                    "malformed " + frameType + " frame: " + e.getMessage());
        }
    }

    private static Frame decodeBody(ByteBuffer in, long type, FrameType frameType) throws FrameException {
        return switch (frameType) {
            case PADDING -> {
                int n = 1;
                while (in.hasRemaining() && in.get(in.position()) == 0) {
                    in.get();
                    n++;
                }
                yield new Frame.Padding(n);
            }
            case PING -> new Frame.Ping();
            case ACK -> decodeAck(in, type);
            case RESET_STREAM -> new Frame.ResetStream(VarInt.read(in), VarInt.read(in), VarInt.read(in));
            case STOP_SENDING -> new Frame.StopSending(VarInt.read(in), VarInt.read(in));
            case CRYPTO -> {
                long offset = VarInt.read(in);
                ByteBuffer data = takeLength(in, type);
                if (offset + data.remaining() > VarInt.MAX) {
                    throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "CRYPTO data past 2^62-1");
                }
                yield new Frame.Crypto(offset, data);
            }
            case NEW_TOKEN -> {
                ByteBuffer token = takeLength(in, type);
                if (!token.hasRemaining()) {
                    throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "empty NEW_TOKEN token");
                }
                yield new Frame.NewToken(token);
            }
            case STREAM -> {
                long id = VarInt.read(in);
                long offset = (type & 0x04) != 0 ? VarInt.read(in) : 0;
                ByteBuffer data;
                if ((type & 0x02) != 0) {
                    data = takeLength(in, type);
                } else {
                    data = in.slice(in.position(), in.remaining());
                    in.position(in.limit());
                }
                if (offset + data.remaining() > VarInt.MAX) {
                    throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "STREAM data past 2^62-1");
                }
                yield new Frame.Stream(id, offset, data, (type & 0x01) != 0);
            }
            case MAX_DATA -> new Frame.MaxData(VarInt.read(in));
            case MAX_STREAM_DATA -> new Frame.MaxStreamData(VarInt.read(in), VarInt.read(in));
            case MAX_STREAMS -> new Frame.MaxStreams(type == 0x12, VarInt.read(in));
            case DATA_BLOCKED -> new Frame.DataBlocked(VarInt.read(in));
            case STREAM_DATA_BLOCKED -> new Frame.StreamDataBlocked(VarInt.read(in), VarInt.read(in));
            case STREAMS_BLOCKED -> new Frame.StreamsBlocked(type == 0x16, VarInt.read(in));
            case NEW_CONNECTION_ID -> {
                long sequence = VarInt.read(in);
                long retirePriorTo = VarInt.read(in);
                if (retirePriorTo > sequence) {
                    throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "Retire Prior To above Sequence Number");
                }
                int length = in.get() & 0xff;
                if (length == 0 || length > ConnectionId.MAX_LENGTH) {
                    throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "connection ID length " + length);
                }
                ConnectionId id = ConnectionId.read(in, length);
                yield new Frame.NewConnectionId(sequence, retirePriorTo, id, StatelessResetToken.read(in));
            }
            case RETIRE_CONNECTION_ID -> new Frame.RetireConnectionId(VarInt.read(in));
            case PATH_CHALLENGE -> new Frame.PathChallenge(in.getLong());
            case PATH_RESPONSE -> new Frame.PathResponse(in.getLong());
            case CONNECTION_CLOSE -> {
                long code = VarInt.read(in);
                long frame = VarInt.read(in);
                yield new Frame.ConnectionClose(code, frame, takeLength(in, type));
            }
            case APPLICATION_CLOSE -> new Frame.ApplicationClose(VarInt.read(in), takeLength(in, type));
            case HANDSHAKE_DONE -> new Frame.HandshakeDone();
            case IMMEDIATE_ACK -> new Frame.ImmediateAck();
            case DATAGRAM -> {
                ByteBuffer data;
                if ((type & 0x01) != 0) {
                    data = takeLength(in, type);
                } else {
                    data = in.slice(in.position(), in.remaining());
                    in.position(in.limit());
                }
                yield new Frame.Datagram(data);
            }
            case ACK_FREQUENCY -> new Frame.AckFrequency(VarInt.read(in), VarInt.read(in), VarInt.read(in), VarInt.read(in));
        };
    }

    private static Frame.Ack decodeAck(ByteBuffer in, long type) throws FrameException {
        long largest = VarInt.read(in);
        long delay = VarInt.read(in);
        long extraRanges = VarInt.read(in);
        long firstRange = VarInt.read(in);
        // Every further range takes at least two bytes, which bounds the loop by the payload size.
        if (extraRanges > in.remaining() / 2) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "ACK Range Count exceeds the frame");
        }
        long smallest = largest - firstRange;
        if (smallest < 0) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "First ACK Range below zero");
        }
        List<Frame.AckRange> ranges = new ArrayList<>((int) extraRanges + 1);
        ranges.add(new Frame.AckRange(smallest, largest));
        for (long i = 0; i < extraRanges; i++) {
            long gap = VarInt.read(in);
            long length = VarInt.read(in);
            long rangeLargest = smallest - gap - 2;
            if (rangeLargest < 0 || rangeLargest - length < 0) {
                throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "ACK range below zero");
            }
            smallest = rangeLargest - length;
            ranges.add(new Frame.AckRange(smallest, rangeLargest));
        }
        Frame.EcnCounts ecn = null;
        if (type == 0x03) {
            ecn = new Frame.EcnCounts(VarInt.read(in), VarInt.read(in), VarInt.read(in));
        }
        return new Frame.Ack(ranges, delay, ecn);
    }

    private static ByteBuffer takeLength(ByteBuffer in, long type) throws FrameException {
        long length = VarInt.read(in);
        if (length > in.remaining()) {
            throw new FrameException(QuicException.FRAME_ENCODING_ERROR, type, "length exceeds the frame");
        }
        ByteBuffer slice = in.slice(in.position(), (int) length);
        in.position(in.position() + (int) length);
        return slice;
    }
}
