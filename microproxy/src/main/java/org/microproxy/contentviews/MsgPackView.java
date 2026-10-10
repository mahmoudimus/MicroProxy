/*
 * The content types and the YAML output follow mitmproxy_rs (https://github.com/mitmproxy/mitmproxy_rs),
 * mitmproxy-contentviews/src/msgpack.rs; the decoder is written from the MessagePack
 * specification (https://github.com/msgpack/msgpack/blob/master/spec.md). Copyright (c) 2022,
 * Fabio Valentini and Maximilian Hils. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy_rs.txt.
 */
package org.microproxy.contentviews;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * MessagePack bodies as YAML. Every format of the specification is read: nil, booleans, integers
 * up to 64 bits (unsigned too), float 32 and 64, str, bin, arrays, maps and extensions (the
 * timestamp extension, type -1, as an instant). Several values one after another are separated
 * by {@code ---}.
 */
final class MsgPackView implements ContentView {

    private static final Set<String> TYPES = Set.of("application/msgpack", "application/x-msgpack",
            "application/vnd.msgpack");
    private static final int MAX_DEPTH = 128;
    private static final HexFormat HEX = HexFormat.of();

    @Override
    public String name() {
        return "msgpack";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        return TYPES.contains(metadata.mediaType()) ? 1 : 0;
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        return render(data);
    }

    static String render(byte[] data) throws DecodeException {
        Reader r = new Reader(data);
        List<String> documents = new ArrayList<>();
        do {
            documents.add(Yaml.emit(r.value(0)));
        } while (r.pos < data.length);
        return String.join("---\n", documents);
    }

    private static final class Reader {
        private final byte[] data;
        private int pos;

        Reader(byte[] data) {
            this.data = data;
        }

        Yaml.Node value(int depth) throws DecodeException {
            if (depth > MAX_DEPTH) throw error("nested more than " + MAX_DEPTH + " deep");
            int b = u8();
            if (b <= 0x7f) return scalar(String.valueOf(b));
            if (b >= 0xe0) return scalar(String.valueOf((byte) b));
            if ((b & 0xf0) == 0x80) return map(b & 0x0f, depth);
            if ((b & 0xf0) == 0x90) return array(b & 0x0f, depth);
            if ((b & 0xe0) == 0xa0) return str(b & 0x1f);
            return switch (b) {
                case 0xc0 -> scalar("null");
                case 0xc2 -> scalar("false");
                case 0xc3 -> scalar("true");
                case 0xc4 -> bin(u8());
                case 0xc5 -> bin(u16());
                case 0xc6 -> bin(u32());
                case 0xc7 -> ext(u8());
                case 0xc8 -> ext(u16());
                case 0xc9 -> ext(u32());
                case 0xca -> scalar(ProtoText.formatFloat(Float.intBitsToFloat((int) fixed(4))));
                case 0xcb -> scalar(ProtoText.formatDouble(Double.longBitsToDouble(fixed(8))));
                case 0xcc -> scalar(String.valueOf(u8()));
                case 0xcd -> scalar(String.valueOf(u16()));
                case 0xce -> scalar(String.valueOf(fixed(4)));
                case 0xcf -> scalar(Long.toUnsignedString(fixed(8)));
                case 0xd0 -> scalar(String.valueOf((byte) u8()));
                case 0xd1 -> scalar(String.valueOf((short) u16()));
                case 0xd2 -> scalar(String.valueOf((int) fixed(4)));
                case 0xd3 -> scalar(String.valueOf(fixed(8)));
                case 0xd4 -> extBody(1);
                case 0xd5 -> extBody(2);
                case 0xd6 -> extBody(4);
                case 0xd7 -> extBody(8);
                case 0xd8 -> extBody(16);
                case 0xd9 -> str(u8());
                case 0xda -> str(u16());
                case 0xdb -> str(u32());
                case 0xdc -> array(u16(), depth);
                case 0xdd -> array(u32(), depth);
                case 0xde -> map(u16(), depth);
                case 0xdf -> map(u32(), depth);
                default -> throw error("unused format byte 0x" + Integer.toHexString(b));
            };
        }

        private Yaml.Node array(long n, int depth) throws DecodeException {
            // Each element takes at least a byte: a longer count is a lie, not a reason to allocate.
            if (n > data.length - pos) throw error("array of " + n + " elements runs past the end");
            List<Yaml.Node> items = new ArrayList<>((int) n);
            for (long i = 0; i < n; i++) items.add(value(depth + 1));
            return new Yaml.Sequence(items);
        }

        private Yaml.Node map(long n, int depth) throws DecodeException {
            if (n > (data.length - pos) / 2) throw error("map of " + n + " entries runs past the end");
            Yaml.Mapping out = new Yaml.Mapping();
            for (long i = 0; i < n; i++) {
                Yaml.Node key = value(depth + 1);
                out.put(key(key), value(depth + 1));
            }
            return out;
        }

        /** A key as YAML text: scalars as they are, collections flattened to a quoted string. */
        private static String key(Yaml.Node key) {
            if (key instanceof Yaml.Scalar s) return s.text();
            return Yaml.string(Yaml.emit(key).strip().replace('\n', ' '));
        }

        private Yaml.Node str(long n) throws DecodeException {
            byte[] bytes = take(n);
            String s = ProtoDecoder.utf8(bytes, 0, bytes.length);
            return s != null ? scalar(Yaml.string(s)) : new Yaml.Scalar("!binary " + Yaml.string(HEX.formatHex(bytes)),
                    "str that is not UTF-8");
        }

        private Yaml.Node bin(long n) throws DecodeException {
            return scalar("!binary " + Yaml.string(HEX.formatHex(take(n))));
        }

        private Yaml.Node ext(long n) throws DecodeException {
            return extBody((int) Math.min(n, Integer.MAX_VALUE));
        }

        private Yaml.Node extBody(int n) throws DecodeException {
            byte type = (byte) u8();
            byte[] body = take(n);
            if (type == -1) {
                Instant t = timestamp(body);
                if (t != null) return new Yaml.Scalar(t.toString(), "timestamp");
            }
            return scalar("!ext" + type + " " + Yaml.string(HEX.formatHex(body)));
        }

        /**
         * The timestamp extension: 32-bit seconds; 30-bit nanoseconds and 34-bit seconds; or 32-bit
         * nanoseconds and 64-bit seconds.
         */
        private static Instant timestamp(byte[] b) {
            try {
                return switch (b.length) {
                    case 4 -> Instant.ofEpochSecond(be(b, 0, 4));
                    case 8 -> {
                        long v = be(b, 0, 8);
                        yield Instant.ofEpochSecond(v & 0x3ffffffffL, v >>> 34);
                    }
                    case 12 -> Instant.ofEpochSecond(be(b, 4, 8), be(b, 0, 4));
                    default -> null;
                };
            } catch (DateTimeException | ArithmeticException e) {
                return null;
            }
        }

        private static long be(byte[] b, int from, int n) {
            long v = 0;
            for (int i = 0; i < n; i++) v = (v << 8) | (b[from + i] & 0xff);
            return v;
        }

        private static Yaml.Node scalar(String text) {
            return new Yaml.Scalar(text);
        }

        private int u8() throws DecodeException {
            if (pos >= data.length) throw error("unexpected end");
            return data[pos++] & 0xff;
        }

        private int u16() throws DecodeException {
            return (int) fixed(2);
        }

        private long u32() throws DecodeException {
            return fixed(4);
        }

        /** {@code n} bytes, big-endian, as an unsigned number (all 64 bits for eight). */
        private long fixed(int n) throws DecodeException {
            if (data.length - pos < n) throw error("unexpected end");
            long v = 0;
            for (int i = 0; i < n; i++) v = (v << 8) | (data[pos++] & 0xff);
            return v;
        }

        private byte[] take(long n) throws DecodeException {
            if (n > data.length - pos) throw error(n + " bytes run past the end");
            byte[] out = Arrays.copyOfRange(data, pos, pos + (int) n);
            pos += (int) n;
            return out;
        }

        private DecodeException error(String what) {
            return new DecodeException("invalid msgpack: " + what + " at byte " + pos);
        }
    }
}
