package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** ECHConfigList parsing and the choice of configuration (RFC 9849 section 4). */
class EchConfigTest {

    static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < KEY.length; i++) KEY[i] = (byte) (i + 1);
    }

    /** One ECHConfig: version, length and contents. */
    static byte[] config(int version, int id, int kem, byte[] key, int[][] suites, int maxName, String publicName,
            int... extensionTypes) {
        Writer w = new Writer();
        w.u16(version);
        int contents = w.open(2);
        w.u8(id).u16(kem).vector16(key);
        int s = w.open(2);
        for (int[] suite : suites) w.u16(suite[0]).u16(suite[1]);
        w.close(s);
        w.u8(maxName).vector8(publicName.getBytes(StandardCharsets.US_ASCII));
        int exts = w.open(2);
        for (int type : extensionTypes) w.u16(type).vector16(new byte[] {1, 2});
        w.close(exts);
        w.close(contents);
        return w.toByteArray();
    }

    static byte[] config(int id, int[][] suites) {
        return config(EchConfig.VERSION, id, Hpke.KEM_X25519_HKDF_SHA256, KEY, suites, 32, "public.example");
    }

    static byte[] list(byte[]... configs) {
        Writer w = new Writer();
        int l = w.open(2);
        for (byte[] c : configs) w.bytes(c);
        w.close(l);
        return w.toByteArray();
    }

    @Test
    void parsesAConfig() throws QuicException {
        byte[] c = config(EchConfig.VERSION, 0x42, 0x0020, KEY, new int[][] {{1, 1}, {1, 3}}, 64, "public.example", 0x0123);
        List<EchConfig> parsed = EchConfig.parseList(list(c));
        assertEquals(1, parsed.size());
        EchConfig e = parsed.get(0);
        assertArrayEquals(c, e.raw());
        assertEquals(0x42, e.configId());
        assertEquals(0x0020, e.kemId());
        assertArrayEquals(KEY, e.publicKey());
        assertEquals(List.of(new EchConfig.SymmetricSuite(1, 1), new EchConfig.SymmetricSuite(1, 3)), e.cipherSuites());
        assertEquals(64, e.maximumNameLength());
        assertEquals("public.example", e.publicName());
        assertEquals(1, e.extensions().size());
        assertEquals(0x0123, e.extensions().get(0).type());
        assertFalse(e.extensions().get(0).mandatory());

        EchConfig.Selected selected = EchConfig.select(list(c));
        assertEquals(e.configId(), selected.config().configId());
        assertEquals(1, selected.kdfId());
        assertEquals(Hpke.Aead.AES_128_GCM, selected.aead());
    }

    /** As Go's server prints one: one config, AES-128-GCM, public.test. */
    @Test
    void parsesGosServerConfigList() throws QuicException {
        byte[] list = Base64.getDecoder().decode(
                "AD7+DQA6BwAgACDeKASza+w5BT5qvC9QmZVsddm4R7D53+7457oigCpRewAEAAEAAUALcHVibGljLnRlc3QAAA==");
        EchConfig.Selected s = EchConfig.select(list);
        assertEquals(7, s.config().configId());
        assertEquals("public.test", s.config().publicName());
        assertEquals(64, s.config().maximumNameLength());
        assertEquals(Hpke.Aead.AES_128_GCM, s.aead());
        assertArrayEquals(Arrays.copyOfRange(list, 2, list.length), s.config().raw());
    }

    @Test
    void otherVersionsAreSkippedByTheirLength() throws QuicException {
        byte[] future = config(0xfe0e, 1, 0x0020, KEY, new int[][] {{1, 1}}, 0, "future.example");
        byte[] current = config(2, new int[][] {{1, 2}});
        List<EchConfig> parsed = EchConfig.parseList(list(future, current));
        assertEquals(1, parsed.size());
        EchConfig.Selected s = EchConfig.select(list(future, current));
        assertEquals(2, s.config().configId());
        assertEquals(Hpke.Aead.AES_256_GCM, s.aead());
    }

    @Test
    void unsupportedSuitesAreSkipped() throws QuicException {
        // HKDF-SHA384 only, then an export-only AEAD, then a supported one
        byte[] sha384 = config(1, new int[][] {{2, 1}});
        byte[] exportOnly = config(2, new int[][] {{1, 0xffff}});
        byte[] good = config(3, new int[][] {{3, 1}, {1, 0xffff}, {1, 3}, {1, 1}});
        EchConfig.Selected s = EchConfig.select(list(sha384, exportOnly, good));
        assertEquals(3, s.config().configId());
        assertEquals(Hpke.Aead.CHACHA20_POLY1305, s.aead(), "the first supported suite of the config");
        assertNull(EchConfig.select(list(sha384, exportOnly)));
    }

    @Test
    void unusableConfigsAreSkipped() throws QuicException {
        byte[] p256 = config(EchConfig.VERSION, 1, 0x0010, new byte[65], new int[][] {{1, 1}}, 0, "public.example");
        byte[] shortKey = config(EchConfig.VERSION, 2, 0x0020, new byte[31], new int[][] {{1, 1}}, 0, "public.example");
        byte[] mandatory = config(EchConfig.VERSION, 3, 0x0020, KEY, new int[][] {{1, 1}}, 0, "public.example", 0x8001);
        byte[] twice = config(EchConfig.VERSION, 4, 0x0020, KEY, new int[][] {{1, 1}}, 0, "public.example", 5, 5);
        byte[] ipv4 = config(EchConfig.VERSION, 5, 0x0020, KEY, new int[][] {{1, 1}}, 0, "192.168.0.1");
        byte[] good = config(EchConfig.VERSION, 6, 0x0020, KEY, new int[][] {{1, 1}}, 0, "public.example", 0x0001);
        assertEquals(6, EchConfig.select(list(p256, shortKey, mandatory, twice, ipv4, good)).config().configId());
        assertNull(EchConfig.select(list(p256, shortKey, mandatory, twice, ipv4)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"public.example", "a", "x-1.example", "cloudflare-ech.com", "a.b.c.d.example0x"})
    void validPublicNames(String name) {
        assertTrue(EchConfig.validPublicName(name), name);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".example", "example.", "a..b", "-a.example", "a-.example", "under_score.example",
        "10.0.0.1", "example.123", "example.0x1f", "example.0X", "spa ce.example",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example"})
    void invalidPublicNames(String name) {
        assertFalse(EchConfig.validPublicName(name), name);
    }

    @Test
    void malformedListsAreDecodeErrors() {
        byte[] good = config(1, new int[][] {{1, 1}});
        byte[] valid = list(good);
        List<byte[]> bad = List.of(
                new byte[0],
                new byte[] {0},
                new byte[] {0, 0}, // empty
                Arrays.copyOf(valid, valid.length - 1), // truncated
                Arrays.copyOf(valid, valid.length + 1), // trailing byte
                list(Arrays.copyOf(good, good.length - 1)), // a config shorter than its length
                list(good, new byte[] {(byte) 0xfe, 0x0d, 0}), // a truncated second config
                list(config(EchConfig.VERSION, 1, 0x20, KEY, new int[0][], 0, "public.example")), // no suites
                list(config(EchConfig.VERSION, 1, 0x20, new byte[0], new int[][] {{1, 1}}, 0, "public.example")),
                list(config(EchConfig.VERSION, 1, 0x20, KEY, new int[][] {{1, 1}}, 0, ""))); // empty public_name
        for (byte[] b : bad) {
            QuicException e = assertThrows(QuicException.class, () -> EchConfig.select(b), Arrays.toString(b));
            assertEquals(TlsAlert.DECODE_ERROR, TlsAlert.fromErrorCode(e.code()));
        }
        // contents longer than their fields
        byte[] padded = Arrays.copyOf(good, good.length + 1);
        padded[3]++;
        assertThrows(QuicException.class, () -> EchConfig.parseList(list(padded)));
        // a suite list that is not whole pairs
        Writer w = new Writer();
        w.u16(EchConfig.VERSION);
        int c = w.open(2);
        w.u8(1).u16(0x20).vector16(KEY).vector16(new byte[] {0, 1, 0}).u8(0).vector8(new byte[] {'a'}).u16(0);
        w.close(c);
        assertThrows(QuicException.class, () -> EchConfig.parseList(list(w.toByteArray())));
    }
}
