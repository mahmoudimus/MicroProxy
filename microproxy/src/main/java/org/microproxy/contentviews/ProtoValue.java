package org.microproxy.contentviews;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * One value of a protobuf field: what its wire type says, plus how a length-delimited value was
 * understood. Without a schema, {@link Protobuf#decode(byte[])} guesses whether length-delimited
 * bytes are {@link Text}, a nested {@link Message} or plain {@link Bytes}; with one, the declared
 * field types decide, and repeated scalars sent packed become {@link Packed}.
 *
 * <p>Every value re-encodes to the wire form it was read from ({@link Protobuf#encode(ProtoMessage)}).
 */
public sealed interface ProtoValue {

    /** Wire type 0: base-128 varint. */
    int WIRE_VARINT = 0;
    /** Wire type 1: eight little-endian bytes. */
    int WIRE_FIXED64 = 1;
    /** Wire type 2: a length, then that many bytes. */
    int WIRE_LEN = 2;
    /** Wire type 3: the start of a group. */
    int WIRE_START_GROUP = 3;
    /** Wire type 4: the end of a group. */
    int WIRE_END_GROUP = 4;
    /** Wire type 5: four little-endian bytes. */
    int WIRE_FIXED32 = 5;

    /** {@return the wire type this value is encoded with} */
    int wireType();

    /**
     * A varint (wire type 0): {@code int32}, {@code int64}, {@code uint32}, {@code uint64},
     * {@code sint32}, {@code sint64}, {@code bool} or an enum.
     *
     * @param value the 64 bits of the varint; negative when the top bit is set, as for negative
     *     {@code int32} and {@code int64} values
     */
    record Varint(long value) implements ProtoValue {
        @Override
        public int wireType() {
            return WIRE_VARINT;
        }

        /** {@return the value read as zigzag-encoded, as {@code sint32} and {@code sint64} are} */
        public long zigzag() {
            return Protobuf.zigzagDecode(value);
        }

        /** {@return the value as an unsigned 64-bit decimal number} */
        public String unsigned() {
            return Long.toUnsignedString(value);
        }
    }

    /**
     * Four bytes (wire type 5): {@code fixed32}, {@code sfixed32} or {@code float}.
     *
     * @param bits the 32 bits
     */
    record Fixed32(int bits) implements ProtoValue {
        @Override
        public int wireType() {
            return WIRE_FIXED32;
        }

        /** {@return the bits as a {@code float}} */
        public float asFloat() {
            return Float.intBitsToFloat(bits);
        }

        /** {@return the bits as an unsigned number} */
        public long unsigned() {
            return Integer.toUnsignedLong(bits);
        }
    }

    /**
     * Eight bytes (wire type 1): {@code fixed64}, {@code sfixed64} or {@code double}.
     *
     * @param bits the 64 bits
     */
    record Fixed64(long bits) implements ProtoValue {
        @Override
        public int wireType() {
            return WIRE_FIXED64;
        }

        /** {@return the bits as a {@code double}} */
        public double asDouble() {
            return Double.longBitsToDouble(bits);
        }

        /** {@return the bits as an unsigned 64-bit decimal number} */
        public String unsigned() {
            return Long.toUnsignedString(bits);
        }
    }

    /**
     * Length-delimited bytes (wire type 2) that are neither text nor a message, or that a schema
     * declares as {@code bytes}.
     *
     * @param data the bytes (not copied; do not change them)
     */
    record Bytes(byte[] data) implements ProtoValue {
        /**
         * Wraps {@code data}.
         *
         * @param data the bytes
         */
        public Bytes {
            Objects.requireNonNull(data, "data");
        }

        @Override
        public int wireType() {
            return WIRE_LEN;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes b && Arrays.equals(data, b.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }

        @Override
        public String toString() {
            return "Bytes[" + HexFormat.of().formatHex(data) + "]";
        }
    }

    /**
     * Length-delimited UTF-8 text (wire type 2): a {@code string}, or bytes that read as text.
     *
     * @param text the decoded text
     */
    record Text(String text) implements ProtoValue {
        /**
         * Wraps {@code text}.
         *
         * @param text the text
         */
        public Text {
            Objects.requireNonNull(text, "text");
        }

        @Override
        public int wireType() {
            return WIRE_LEN;
        }

        /** {@return the text as UTF-8, as it is encoded} */
        public byte[] utf8() {
            return text.getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * A nested message (wire type 2).
     *
     * @param message the nested message
     */
    record Message(ProtoMessage message) implements ProtoValue {
        /**
         * Wraps {@code message}.
         *
         * @param message the nested message
         */
        public Message {
            Objects.requireNonNull(message, "message");
        }

        @Override
        public int wireType() {
            return WIRE_LEN;
        }
    }

    /**
     * A packed repeated scalar field (wire type 2): several {@link Varint}, {@link Fixed32} or
     * {@link Fixed64} values in one length-delimited value. Only decoding with a schema produces
     * it, since without one packed values cannot be told from other bytes.
     *
     * @param elements the values, all of one wire type
     */
    record Packed(List<ProtoValue> elements) implements ProtoValue {
        /**
         * Wraps {@code elements}.
         *
         * @param elements the varint or fixed-width values
         * @throws IllegalArgumentException if an element is not a varint or fixed-width value
         */
        public Packed {
            elements = List.copyOf(elements);
            for (ProtoValue e : elements) {
                if (!(e instanceof Varint || e instanceof Fixed32 || e instanceof Fixed64)) {
                    throw new IllegalArgumentException("packed elements are varints or fixed-width values, not " + e);
                }
            }
        }

        @Override
        public int wireType() {
            return WIRE_LEN;
        }
    }

    /**
     * A group (wire types 3 and 4), proto2's deprecated way of nesting a message.
     *
     * @param message the group's fields
     */
    record Group(ProtoMessage message) implements ProtoValue {
        /**
         * Wraps {@code message}.
         *
         * @param message the group's fields
         */
        public Group {
            Objects.requireNonNull(message, "message");
        }

        @Override
        public int wireType() {
            return WIRE_START_GROUP;
        }
    }
}
