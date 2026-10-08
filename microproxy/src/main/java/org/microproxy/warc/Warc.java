package org.microproxy.warc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Small helpers shared by the WARC classes. */
final class Warc {

    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private Warc() {}

    static MessageDigest sha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code sha1:} plus the RFC 4648 base32 form of {@code digest}, as WARC digests are written. */
    static String digestString(byte[] digest) {
        return "sha1:" + base32(digest);
    }

    static String base32(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32[(buffer >>> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0) out.append(BASE32[(buffer << (5 - bits)) & 31]);
        while (out.length() % 8 != 0) out.append('=');
        return out.toString();
    }
}
