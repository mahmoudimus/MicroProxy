package org.microproxy.contentviews;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.microproxy.http.HttpBodies;

/**
 * gRPC's message framing: a body is a sequence of messages, each a compressed flag (one byte), a
 * length (four bytes, big-endian) and that many bytes of payload, compressed with the coding the
 * {@code grpc-encoding} header names when the flag is set.
 *
 * <pre>{@code
 * List<byte[]> messages = Grpc.messages(body, request.headers().get("grpc-encoding"));
 * ProtoMessage first = Protobuf.decode(messages.getFirst());
 * byte[] rewritten = Grpc.join(List.of(Protobuf.encode(changed)));
 * }</pre>
 *
 * <p>Also here: the status codes, and {@code google.rpc.Status} from the {@code
 * grpc-status-details-bin} trailer.
 */
public final class Grpc {

    /** The largest a message may grow to when it is decompressed. */
    public static final int DEFAULT_MAX_MESSAGE_BYTES = HttpBodies.DEFAULT_MAX_DECODED_BYTES;

    private static final String[] CODES = {
        "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS",
        "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE",
        "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"
    };

    private Grpc() {}

    /**
     * One framed message, as it is on the wire.
     *
     * @param compressed whether the compressed flag is set
     * @param payload the payload, still compressed when {@code compressed} (not copied)
     */
    public record Frame(boolean compressed, byte[] payload) {
        /**
         * Wraps a payload.
         *
         * @param compressed whether the compressed flag is set
         * @param payload the payload
         */
        public Frame {
            Objects.requireNonNull(payload, "payload");
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Frame f && f.compressed == compressed && Arrays.equals(f.payload, payload);
        }

        @Override
        public int hashCode() {
            return Boolean.hashCode(compressed) * 31 + Arrays.hashCode(payload);
        }

        @Override
        public String toString() {
            return "Frame[" + (compressed ? "compressed, " : "") + payload.length + " bytes]";
        }
    }

    /**
     * Splits a body into its framed messages.
     *
     * @param body a whole gRPC request or response body
     * @return the frames, in order
     * @throws DecodeException if a flag is neither 0 nor 1, or the body ends inside a frame
     */
    public static List<Frame> split(byte[] body) throws DecodeException {
        Scan scan = scan(body, false);
        if (scan.trailers() != null) throw new DecodeException("invalid gRPC: a gRPC-Web trailers frame");
        if (scan.rest() > 0) {
            throw new DecodeException("invalid gRPC: the body ends inside a message (" + scan.restDeclared()
                    + "-byte message, " + scan.rest() + " bytes of frame present)");
        }
        return scan.frames();
    }

    /**
     * Splits a body into its messages, decompressing those that are compressed.
     *
     * @param body a whole gRPC request or response body
     * @param encoding the message's {@code grpc-encoding} header, or {@code null} for none
     * @return the messages' payloads, uncompressed
     * @throws DecodeException if the body is not framed correctly, or a message cannot be
     *     decompressed
     */
    public static List<byte[]> messages(byte[] body, String encoding) throws DecodeException {
        List<byte[]> out = new ArrayList<>();
        for (Frame f : split(body)) {
            out.add(f.compressed() ? decompress(f.payload(), encoding, DEFAULT_MAX_MESSAGE_BYTES) : f.payload());
        }
        return out;
    }

    /**
     * Frames messages without compressing them.
     *
     * @param messages the payloads
     * @return the body
     */
    public static byte[] join(List<byte[]> messages) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] m : messages) frame(out, false, m);
        return out.toByteArray();
    }

    /**
     * Frames messages, compressing each with {@code encoding}.
     *
     * @param messages the payloads, uncompressed
     * @param encoding {@code gzip} or {@code deflate} to compress, {@code identity} or {@code null}
     *     not to
     * @return the body
     * @throws IllegalArgumentException if the proxy cannot compress with {@code encoding}
     */
    public static byte[] join(List<byte[]> messages, String encoding) {
        String coding = coding(encoding);
        if (coding == null) return join(messages);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] m : messages) frame(out, true, compress(m, coding));
        return out.toByteArray();
    }

    /**
     * Compresses one message's payload.
     *
     * @param payload the payload
     * @param encoding {@code gzip} or {@code deflate}
     * @return the compressed payload
     * @throws IllegalArgumentException if the proxy cannot compress with {@code encoding}
     */
    public static byte[] compress(byte[] payload, String encoding) {
        String coding = coding(encoding);
        if (coding == null) return payload.clone();
        try {
            return HttpBodies.encode(coding, payload);
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot compress with grpc-encoding " + encoding
                    + "; gzip and deflate can be produced");
        }
    }

    /**
     * Decompresses one message's payload.
     *
     * @param payload the compressed payload
     * @param encoding the {@code grpc-encoding}: {@code gzip}, {@code deflate}, {@code identity},
     *     and {@code zstd} with the zstd-decoder module
     * @param maxBytes the largest the result may be
     * @return the payload, uncompressed
     * @throws DecodeException if the encoding is missing or unsupported, or the data corrupt or too large
     */
    public static byte[] decompress(byte[] payload, String encoding, int maxBytes) throws DecodeException {
        if (encoding == null || encoding.isBlank()) {
            throw new DecodeException("invalid gRPC: a compressed message without grpc-encoding");
        }
        String coding = coding(encoding);
        if (coding == null) return payload;
        try {
            return HttpBodies.decode(coding, payload, maxBytes);
        } catch (IOException | RuntimeException e) {
            throw new DecodeException("cannot decompress a gRPC message (grpc-encoding " + encoding + "): "
                    + e.getMessage(), e);
        }
    }

    /** The content coding for a {@code grpc-encoding}, or {@code null} for none. */
    private static String coding(String encoding) {
        if (encoding == null) return null;
        String e = encoding.strip().toLowerCase(Locale.ROOT);
        return e.isEmpty() || e.equals("identity") ? null : e;
    }

    private static void frame(ByteArrayOutputStream out, boolean compressed, byte[] payload) {
        out.write(compressed ? 1 : 0);
        out.write(payload.length >>> 24);
        out.write(payload.length >>> 16);
        out.write(payload.length >>> 8);
        out.write(payload.length);
        out.writeBytes(payload);
    }

    /**
     * The frames of a body, and what is left over: a gRPC-Web trailers frame's payload, and the
     * bytes of an incomplete frame at the end (and the length it declared, or -1).
     */
    record Scan(List<Frame> frames, byte[] trailers, int rest, long restDeclared) {}

    /** Reads frames as far as they go; with {@code web}, a flag of 0x80 marks a gRPC-Web trailers frame. */
    static Scan scan(byte[] body, boolean web) throws DecodeException {
        List<Frame> frames = new ArrayList<>();
        int pos = 0;
        while (pos < body.length) {
            int flag = body[pos] & 0xff;
            boolean trailers = web && (flag & 0x80) != 0;
            if ((flag & 0x7f) > 1 || flag > 1 && !trailers) {
                throw new DecodeException("invalid gRPC: message flag " + flag + " at byte " + pos);
            }
            if (body.length - pos < 5) return new Scan(frames, null, body.length - pos, -1);
            long length = ((body[pos + 1] & 0xffL) << 24) | ((body[pos + 2] & 0xff) << 16)
                    | ((body[pos + 3] & 0xff) << 8) | (body[pos + 4] & 0xff);
            if (length > body.length - pos - 5) return new Scan(frames, null, body.length - pos, length);
            byte[] payload = Arrays.copyOfRange(body, pos + 5, pos + 5 + (int) length);
            pos += 5 + (int) length;
            if (trailers) return new Scan(frames, payload, body.length - pos, -1);
            frames.add(new Frame(flag == 1, payload));
        }
        return new Scan(frames, null, 0, -1);
    }

    // ---------------------------------------------------------------------------------------
    // Status
    // ---------------------------------------------------------------------------------------

    /**
     * The name of a status code.
     *
     * @param code the {@code grpc-status} value
     * @return its name, such as {@code INVALID_ARGUMENT}, or {@code null} for an unknown code
     */
    public static String codeName(int code) {
        return code >= 0 && code < CODES.length ? CODES[code] : null;
    }

    /**
     * Decodes {@code grpc-message}, which is percent-encoded UTF-8.
     *
     * @param value the field's value
     * @return the message
     */
    public static String message(String value) {
        if (value.indexOf('%') < 0) return value;
        try {
            return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    /**
     * One entry of a status's details: a {@code google.protobuf.Any}.
     *
     * @param typeUrl the type URL, such as {@code type.googleapis.com/google.rpc.BadRequest}
     * @param value the serialized message (not copied)
     */
    public record Detail(String typeUrl, byte[] value) {
        /**
         * Wraps a detail.
         *
         * @param typeUrl the type URL
         * @param value the serialized message
         */
        public Detail {
            Objects.requireNonNull(typeUrl, "typeUrl");
            Objects.requireNonNull(value, "value");
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Detail d && d.typeUrl.equals(typeUrl) && Arrays.equals(d.value, value);
        }

        @Override
        public int hashCode() {
            return typeUrl.hashCode() * 31 + Arrays.hashCode(value);
        }

        @Override
        public String toString() {
            return "Detail[" + typeUrl + ", " + value.length + " bytes]";
        }
    }

    /**
     * A {@code google.rpc.Status}, as servers send it in {@code grpc-status-details-bin}.
     *
     * @param code the status code
     * @param message the developer-facing message
     * @param details further details
     */
    public record Status(int code, String message, List<Detail> details) {
        /**
         * Copies the details.
         *
         * @param code the status code
         * @param message the message
         * @param details the details
         */
        public Status {
            Objects.requireNonNull(message, "message");
            details = List.copyOf(details);
        }

        /** {@return the code's name, or {@code null} for an unknown code} */
        public String codeName() {
            return Grpc.codeName(code);
        }

        /** {@return the status serialized as a {@code google.rpc.Status} message} */
        public byte[] toByteArray() {
            List<ProtoField> fields = new ArrayList<>();
            if (code != 0) fields.add(new ProtoField(1, new ProtoValue.Varint(code)));
            if (!message.isEmpty()) fields.add(new ProtoField(2, new ProtoValue.Text(message)));
            for (Detail d : details) {
                fields.add(new ProtoField(3, new ProtoValue.Message(new ProtoMessage(List.of(
                        new ProtoField(1, new ProtoValue.Text(d.typeUrl())),
                        new ProtoField(2, new ProtoValue.Bytes(d.value())))))));
            }
            return Protobuf.encode(new ProtoMessage(fields));
        }

        /** {@return the value of a {@code grpc-status-details-bin} field carrying this status} */
        public String toTrailer() {
            return Base64.getEncoder().withoutPadding().encodeToString(toByteArray());
        }
    }

    /**
     * Decodes a serialized {@code google.rpc.Status}.
     *
     * @param status the serialized message
     * @return the status
     * @throws DecodeException if it is not a status message
     */
    public static Status status(byte[] status) throws DecodeException {
        int code = 0;
        String message = "";
        List<Detail> details = new ArrayList<>();
        for (ProtoWire.Raw f : ProtoWire.read(status, 0, status.length, false, 0)) {
            if (f.number() == 1 && f.wireType() == ProtoValue.WIRE_VARINT) {
                code = (int) f.bits();
            } else if (f.number() == 2 && f.wireType() == ProtoValue.WIRE_LEN) {
                message = new String(f.data(), f.offset(), f.length(), StandardCharsets.UTF_8);
            } else if (f.number() == 3 && f.wireType() == ProtoValue.WIRE_LEN) {
                String typeUrl = "";
                byte[] value = new byte[0];
                for (ProtoWire.Raw a : ProtoWire.read(f.data(), f.offset(), f.offset() + f.length(), false, 0)) {
                    if (a.number() == 1 && a.wireType() == ProtoValue.WIRE_LEN) {
                        typeUrl = new String(a.data(), a.offset(), a.length(), StandardCharsets.UTF_8);
                    } else if (a.number() == 2 && a.wireType() == ProtoValue.WIRE_LEN) {
                        value = a.bytes();
                    }
                }
                details.add(new Detail(typeUrl, value));
            } else {
                throw new DecodeException("invalid google.rpc.Status: unexpected field " + f.number());
            }
        }
        return new Status(code, message, details);
    }

    /**
     * Decodes the value of a {@code grpc-status-details-bin} field: base64 (padded or not) of a
     * {@code google.rpc.Status}.
     *
     * @param value the field's value
     * @return the status
     * @throws DecodeException if the value is not base64 of a status message
     */
    public static Status statusFromTrailer(String value) throws DecodeException {
        return status(base64(value));
    }

    /** Decodes the base64 of a binary ({@code -bin}) metadata value, padded or not. */
    static byte[] base64(String value) throws DecodeException {
        String v = value.strip();
        try {
            return (v.indexOf('-') >= 0 || v.indexOf('_') >= 0 ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(v);
        } catch (IllegalArgumentException e) {
            throw new DecodeException("invalid base64 in binary gRPC metadata: " + e.getMessage(), e);
        }
    }
}
