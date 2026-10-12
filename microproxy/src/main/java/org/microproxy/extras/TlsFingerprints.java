package org.microproxy.extras;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.microproxy.ClientHello;

/**
 * TLS client fingerprints of a {@link ClientHello}, as access logs show them ({@code
 * %TLS_JA3_FINGERPRINT%}, {@code %TLS_JA4_FINGERPRINT%}): JA3, the MD5 of the hello's version,
 * cipher suites, extensions, groups and point formats, and JA4, a readable prefix and two
 * truncated SHA-256 hashes of the sorted cipher suites and extensions. GREASE values (RFC 8701)
 * are left out of both, as the algorithms say.
 */
public final class TlsFingerprints {

    private static final HexFormat HEX = HexFormat.of();
    private static final int EXT_SERVER_NAME = 0x0000;
    private static final int EXT_SUPPORTED_GROUPS = 0x000a;
    private static final int EXT_EC_POINT_FORMATS = 0x000b;
    private static final int EXT_SIGNATURE_ALGORITHMS = 0x000d;
    private static final int EXT_ALPN = 0x0010;
    private static final int EXT_SUPPORTED_VERSIONS = 0x002b;

    private TlsFingerprints() {}

    /** The fields of a ClientHello the fingerprints read, GREASE values removed. */
    private record Fields(int legacyVersion, int[] ciphers, int[] extensions, int[] groups, int[] pointFormats,
            int[] signatureAlgorithms, int[] versions, boolean sni, byte[] firstAlpn) {}

    /**
     * The JA3 string: {@code version,ciphers,extensions,groups,point_formats}, each list's values
     * in decimal, in the hello's order, separated by {@code -}.
     *
     * @param hello the ClientHello
     * @return the JA3 string, or {@code null} when the hello cannot be read
     */
    public static String ja3String(ClientHello hello) {
        Fields f = parse(hello.raw());
        if (f == null) return null;
        return f.legacyVersion() + "," + decimals(f.ciphers()) + "," + decimals(f.extensions()) + ","
                + decimals(f.groups()) + "," + decimals(f.pointFormats());
    }

    /**
     * The JA3 fingerprint: the lowercase hex MD5 of {@link #ja3String}.
     *
     * @param hello the ClientHello
     * @return the fingerprint, or {@code null} when the hello cannot be read
     */
    public static String ja3(ClientHello hello) {
        String s = ja3String(hello);
        return s == null ? null : HEX.formatHex(digest("MD5", s));
    }

    /**
     * The JA4 fingerprint of a hello sent over TCP.
     *
     * @param hello the ClientHello
     * @return the fingerprint, or {@code null} when the hello cannot be read
     */
    public static String ja4(ClientHello hello) {
        return ja4(hello, false);
    }

    /**
     * The JA4 fingerprint: {@code a_b_c}, where {@code a} is the transport ({@code t} for TCP,
     * {@code q} for QUIC), the highest TLS version offered ({@code 13}, {@code 12}, ...), {@code d}
     * with SNI or {@code i} without, the counts of cipher suites and extensions (two digits each),
     * and the first and last characters of the first ALPN protocol ({@code 00} without); {@code b}
     * is the first 12 hex digits of the SHA-256 of the sorted cipher suites (4-digit hex, comma
     * separated); {@code c} the same of the sorted extensions without SNI and ALPN, followed by
     * {@code _} and the signature algorithms in their order when there are any.
     *
     * @param hello the ClientHello
     * @param quic whether the hello came in QUIC Initial packets
     * @return the fingerprint, or {@code null} when the hello cannot be read
     */
    public static String ja4(ClientHello hello, boolean quic) {
        Fields f = parse(hello.raw());
        if (f == null) return null;
        StringBuilder a = new StringBuilder(10);
        a.append(quic ? 'q' : 't').append(versionCode(f));
        a.append(f.sni() ? 'd' : 'i');
        twoDigits(a, f.ciphers().length);
        twoDigits(a, f.extensions().length);
        a.append(alpnCode(f.firstAlpn()));

        int[] ciphers = f.ciphers().clone();
        Arrays.sort(ciphers);
        String b = ciphers.length == 0 ? "000000000000" : truncatedSha256(hexList(ciphers));

        int[] extensions = Arrays.stream(f.extensions()).filter(e -> e != EXT_SERVER_NAME && e != EXT_ALPN).sorted()
                .toArray();
        String c;
        if (extensions.length == 0) {
            c = "000000000000";
        } else {
            String list = hexList(extensions);
            if (f.signatureAlgorithms().length > 0) list += "_" + hexList(f.signatureAlgorithms());
            c = truncatedSha256(list);
        }
        return a + "_" + b + "_" + c;
    }

    private static String versionCode(Fields f) {
        int version = f.legacyVersion();
        if (f.versions().length > 0) {
            version = 0;
            for (int v : f.versions()) version = Math.max(version, v);
        }
        return switch (version) {
            case 0x0304 -> "13";
            case 0x0303 -> "12";
            case 0x0302 -> "11";
            case 0x0301 -> "10";
            case 0x0300 -> "s3";
            case 0x0002 -> "s2";
            case 0xfeff -> "d1";
            case 0xfefd -> "d2";
            case 0xfefc -> "d3";
            default -> "00";
        };
    }

    private static String alpnCode(byte[] alpn) {
        if (alpn == null || alpn.length == 0) return "00";
        int first = alpn[0] & 0xff;
        int last = alpn[alpn.length - 1] & 0xff;
        if (alphanumeric(first) && alphanumeric(last)) return "" + (char) first + (char) last;
        String hex = HEX.formatHex(alpn);
        return "" + hex.charAt(0) + hex.charAt(hex.length() - 1);
    }

    private static boolean alphanumeric(int c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    private static void twoDigits(StringBuilder sb, int n) {
        int v = Math.min(n, 99);
        if (v < 10) sb.append('0');
        sb.append(v);
    }

    private static String decimals(int[] values) {
        StringBuilder sb = new StringBuilder();
        for (int v : values) {
            if (!sb.isEmpty()) sb.append('-');
            sb.append(v);
        }
        return sb.toString();
    }

    private static String hexList(int[] values) {
        StringBuilder sb = new StringBuilder(values.length * 5);
        for (int v : values) {
            if (!sb.isEmpty()) sb.append(',');
            sb.append(HEX.toHexDigits((short) v));
        }
        return sb.toString();
    }

    private static String truncatedSha256(String s) {
        return HEX.formatHex(digest("SHA-256", s)).substring(0, 12);
    }

    private static byte[] digest(String algorithm, String s) {
        try {
            return MessageDigest.getInstance(algorithm).digest(s.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " is missing", e);
        }
    }

    /** Reads the handshake message (type, 3-byte length, body); null if it is not a readable ClientHello. */
    private static Fields parse(byte[] raw) {
        try {
            int p = 0;
            if (raw.length < 4 || raw[0] != 1) return null;
            p = 4;
            int legacyVersion = u16(raw, p);
            p += 2 + 32;
            p += 1 + u8(raw, p);
            int cipherLength = u16(raw, p);
            p += 2;
            int[] ciphers = nonGrease16(raw, p, cipherLength);
            p += cipherLength;
            p += 1 + u8(raw, p);
            List<Integer> extensions = new ArrayList<>();
            int[] groups = new int[0];
            int[] pointFormats = new int[0];
            int[] signatureAlgorithms = new int[0];
            int[] versions = new int[0];
            boolean sni = false;
            byte[] firstAlpn = null;
            if (p + 2 <= raw.length) {
                int end = p + 2 + u16(raw, p);
                p += 2;
                if (end > raw.length) return null;
                while (p + 4 <= end) {
                    int type = u16(raw, p);
                    int length = u16(raw, p + 2);
                    int data = p + 4;
                    if (data + length > end) return null;
                    if (!ClientHello.isGrease(type)) extensions.add(type);
                    switch (type) {
                        case EXT_SERVER_NAME -> sni = true;
                        case EXT_SUPPORTED_GROUPS -> groups = nonGrease16(raw, data + 2, u16(raw, data));
                        case EXT_EC_POINT_FORMATS -> {
                            int n = u8(raw, data);
                            pointFormats = new int[n];
                            for (int i = 0; i < n; i++) pointFormats[i] = u8(raw, data + 1 + i);
                        }
                        case EXT_SIGNATURE_ALGORITHMS -> signatureAlgorithms = nonGrease16(raw, data + 2, u16(raw, data));
                        case EXT_SUPPORTED_VERSIONS -> versions = nonGrease16(raw, data + 1, u8(raw, data));
                        case EXT_ALPN -> {
                            if (length >= 3) {
                                int n = u8(raw, data + 2);
                                firstAlpn = Arrays.copyOfRange(raw, data + 3, data + 3 + n);
                            }
                        }
                        default -> {
                            // not part of the fingerprints
                        }
                    }
                    p = data + length;
                }
            }
            return new Fields(legacyVersion, ciphers, extensions.stream().mapToInt(Integer::intValue).toArray(), groups,
                    pointFormats, signatureAlgorithms, versions, sni, firstAlpn);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    private static int[] nonGrease16(byte[] raw, int offset, int length) {
        int[] values = new int[length / 2];
        int n = 0;
        for (int i = 0; i + 1 < length; i += 2) {
            int v = u16(raw, offset + i);
            if (!ClientHello.isGrease(v)) values[n++] = v;
        }
        return Arrays.copyOf(values, n);
    }

    private static int u8(byte[] b, int i) {
        return b[i] & 0xff;
    }

    private static int u16(byte[] b, int i) {
        if (i + 1 >= b.length) throw new IndexOutOfBoundsException(i);
        return (b[i] & 0xff) << 8 | b[i + 1] & 0xff;
    }
}
