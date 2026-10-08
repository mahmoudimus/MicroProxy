package org.microproxy.tls;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/** The handful of DER (ASN.1) encodings needed to build X.509 certificates. */
final class Der {

    private static final DateTimeFormatter UTC_TIME = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'");
    private static final DateTimeFormatter GENERALIZED_TIME = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");

    private Der() {}

    static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int bytes = len > 0xffffff ? 4 : len > 0xffff ? 3 : len > 0xff ? 2 : 1;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) {
                out.write(len >>> (8 * i));
            }
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    static byte[] sequence(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    static byte[] set(byte[]... parts) {
        return tlv(0x31, concat(parts));
    }

    static byte[] integer(BigInteger value) {
        return tlv(0x02, value.toByteArray());
    }

    static byte[] integer(long value) {
        return integer(BigInteger.valueOf(value));
    }

    static byte[] bool(boolean value) {
        return tlv(0x01, new byte[] {(byte) (value ? 0xff : 0)});
    }

    static byte[] nullValue() {
        return new byte[] {0x05, 0x00};
    }

    static byte[] octetString(byte[] value) {
        return tlv(0x04, value);
    }

    static byte[] bitString(byte[] value, int unusedBits) {
        byte[] content = new byte[value.length + 1];
        content[0] = (byte) unusedBits;
        System.arraycopy(value, 0, content, 1, value.length);
        return tlv(0x03, content);
    }

    static byte[] utf8String(String value) {
        return tlv(0x0c, value.getBytes(StandardCharsets.UTF_8));
    }

    /** {@code [n] EXPLICIT}: a constructed context-specific wrapper. */
    static byte[] explicit(int tagNumber, byte[] content) {
        return tlv(0xa0 | tagNumber, content);
    }

    /** {@code [n] IMPLICIT} of a primitive type. */
    static byte[] implicitPrimitive(int tagNumber, byte[] content) {
        return tlv(0x80 | tagNumber, content);
    }

    static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, Long.parseLong(arcs[0]) * 40 + Long.parseLong(arcs[1]));
        for (int i = 2; i < arcs.length; i++) {
            writeBase128(out, Long.parseLong(arcs[i]));
        }
        return tlv(0x06, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long value) {
        int groups = 1;
        for (long v = value >>> 7; v != 0; v >>>= 7) {
            groups++;
        }
        for (int i = groups - 1; i >= 0; i--) {
            int b = (int) ((value >>> (7 * i)) & 0x7f);
            out.write(i == 0 ? b : b | 0x80);
        }
    }

    /** UTCTime for years 1950-2049 and GeneralizedTime otherwise, as RFC 5280 requires. */
    static byte[] time(Instant instant) {
        ZonedDateTime t = instant.atZone(ZoneOffset.UTC).withNano(0);
        if (t.getYear() >= 1950 && t.getYear() < 2050) {
            return tlv(0x17, UTC_TIME.format(t).getBytes(StandardCharsets.US_ASCII));
        }
        return tlv(0x18, GENERALIZED_TIME.format(t).getBytes(StandardCharsets.US_ASCII));
    }
}
