package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.ClientHello;

/**
 * JA3 and JA4 of hand-built ClientHellos. The first has the cipher suites, extensions, groups and
 * point formats of the JA3 algorithm's published example (with GREASE values added, which the
 * algorithm drops), so its fingerprint must be the published one; the JA4 values were computed
 * from the JA4 definition on their own.
 */
class TlsFingerprintsTest {

    /** The published JA3 example: its string and MD5. */
    static final String JA3_EXAMPLE = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
    static final String JA3_EXAMPLE_MD5 = "ada70206e40642a3e4461f35503241d5";

    /** The ClientHello of the published JA3 example, GREASE values added, with SNI {@code example.test}. */
    static ClientHello ja3Example() {
        return hello("example.test", 0x0301,
                new int[] {0x0a0a, 47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
                ext(0x1a1a, new byte[0]),
                ext(0x0000, serverName("example.test")),
                ext(0x000a, u16List(0x2a2a, 23, 24, 25)),
                ext(0x000b, new byte[] {1, 0}));
    }

    /** A TLS 1.3 ClientHello offering h2, with signature algorithms and GREASE throughout. */
    static ClientHello modern() {
        return hello("example.test", 0x0303,
                new int[] {0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
                ext(0x3a3a, new byte[0]),
                ext(0x0000, serverName("example.test")),
                ext(0x0017, new byte[0]),
                ext(0xff01, new byte[] {0}),
                ext(0x000a, u16List(0x4a4a, 0x001d, 0x0017)),
                ext(0x000b, new byte[] {1, 0}),
                ext(0x0010, alpn("h2", "http/1.1")),
                ext(0x000d, u16List(0x0403, 0x0804, 0x0401)),
                ext(0x002b, versions(0x1a1a, 0x0304, 0x0303)),
                ext(0x0033, new byte[] {0, 0}));
    }

    @Test
    void ja3MatchesThePublishedExample() throws Exception {
        ClientHello hello = ja3Example();
        assertEquals(JA3_EXAMPLE, TlsFingerprints.ja3String(hello));
        assertEquals(JA3_EXAMPLE_MD5, TlsFingerprints.ja3(hello));
        // The hash is MD5 of the string, as the algorithm defines it.
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("MD5")
                .digest(JA3_EXAMPLE.getBytes(StandardCharsets.US_ASCII))), TlsFingerprints.ja3(hello));
    }

    @Test
    void ja3OfAModernHelloDropsGrease() {
        assertEquals("771,4865-4866-4867-49195-49199,0-23-65281-10-11-16-13-43-51,29-23,0",
                TlsFingerprints.ja3String(modern()));
        assertEquals("f4b0e15aa564d82b7ace9b2d00bbea9d", TlsFingerprints.ja3(modern()));
    }

    @Test
    void ja4() {
        assertEquals("t10d120300_d94e65cdb899_33a13ba74d1c", TlsFingerprints.ja4(ja3Example()));
        assertEquals("t13d0509h2_e133e205ac38_f5e0aee4b195", TlsFingerprints.ja4(modern()));
        assertEquals("q13d0509h2_e133e205ac38_f5e0aee4b195", TlsFingerprints.ja4(modern(), true));
    }

    @Test
    void ja4WithoutSniOrExtensionsAndAnOddAlpn() {
        ClientHello bare = hello(null, 0x0303, new int[] {0x1301});
        assertEquals("t12i010000_0f2cb44170f4_000000000000", TlsFingerprints.ja4(bare));
        ClientHello odd = hello(null, 0x0303, new int[] {0x1301}, ext(0x0010, alpn("\u0001x")));
        assertEquals("t12i0101" + "08", TlsFingerprints.ja4(odd).substring(0, 10), "hex of the first ALPN, first and last digits");
    }

    @Test
    void unreadableHellosHaveNoFingerprint() {
        ClientHello broken = new ClientHello(null, List.of(), List.of(), List.of(), List.of(), new byte[] {1, 0, 0, 9, 3});
        assertNull(TlsFingerprints.ja3(broken));
        assertNull(TlsFingerprints.ja4(broken));
    }

    // -------------------------------------------------------------------------------------------
    // Building ClientHellos
    // -------------------------------------------------------------------------------------------

    static ClientHello hello(String sni, int legacyVersion, int[] ciphers, byte[]... extensions) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        u16(body, legacyVersion);
        body.writeBytes(new byte[32]);
        body.write(0);
        u16(body, ciphers.length * 2);
        for (int c : ciphers) u16(body, c);
        body.write(1);
        body.write(0);
        if (extensions.length > 0) {
            ByteArrayOutputStream all = new ByteArrayOutputStream();
            for (byte[] e : extensions) all.writeBytes(e);
            u16(body, all.size());
            body.writeBytes(all.toByteArray());
        }
        byte[] b = body.toByteArray();
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write(1);
        message.write(b.length >>> 16);
        message.write(b.length >>> 8);
        message.write(b.length);
        message.writeBytes(b);
        return new ClientHello(sni, List.of(), List.of(), List.of(), List.of(), message.toByteArray());
    }

    static byte[] ext(int type, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        u16(out, type);
        u16(out, body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    static byte[] u16List(int... values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        u16(out, values.length * 2);
        for (int v : values) u16(out, v);
        return out.toByteArray();
    }

    private static byte[] versions(int... values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(values.length * 2);
        for (int v : values) u16(out, v);
        return out.toByteArray();
    }

    private static byte[] serverName(String host) {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        u16(out, name.length + 3);
        out.write(0);
        u16(out, name.length);
        out.writeBytes(name);
        return out.toByteArray();
    }

    private static byte[] alpn(String... protocols) {
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        for (String p : protocols) {
            byte[] b = p.getBytes(StandardCharsets.ISO_8859_1);
            list.write(b.length);
            list.writeBytes(b);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        u16(out, list.size());
        out.writeBytes(list.toByteArray());
        return out.toByteArray();
    }

    private static void u16(ByteArrayOutputStream out, int v) {
        out.write(v >>> 8);
        out.write(v);
    }
}
