package io.github.mahmoudimus.quic;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HexFormat;
import java.util.Properties;

/** The RFC 9001 and RFC 9369 sample packets, and hex helpers for tests. */
public final class TestVectors {

    private static final Properties VECTORS = load();

    private TestVectors() {}

    /**
     * Bytes from hex, ignoring whitespace.
     *
     * @param s hex digits
     * @return the bytes
     */
    public static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s+", ""));
    }

    /**
     * Hex from bytes.
     *
     * @param b the bytes
     * @return lowercase hex
     */
    public static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    /**
     * A sample packet from the RFC text, such as {@code rfc9001.client-initial.protected}.
     *
     * @param key the vector name
     * @return its bytes
     */
    public static byte[] vector(String key) {
        String v = VECTORS.getProperty(key);
        if (v == null) {
            throw new IllegalArgumentException("no vector " + key);
        }
        return hex(v);
    }

    private static Properties load() {
        Properties p = new Properties();
        try (InputStream in = TestVectors.class.getResourceAsStream("rfc-packet-vectors.properties")) {
            p.load(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return p;
    }
}
