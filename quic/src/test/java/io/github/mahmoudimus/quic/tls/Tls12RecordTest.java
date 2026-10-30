package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.mahmoudimus.quic.QuicException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class Tls12RecordTest {

    @Test
    void prfSha256MatchesThePublishedVector() {
        // the TLS 1.2 PRF test vector for P_SHA256 (secret, seed, label "test label", 100 bytes)
        HexFormat hex = HexFormat.of();
        byte[] out = Tls12Prf.prf(Tls12CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                hex.parseHex("9bbe436ba940f017b17652849a71db35"), "test label",
                hex.parseHex("a0ba9f936cda311827a6f796ffd5198c"), 100);
        assertEquals("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14ba"
                + "f9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a"
                + "5110fff70187347b66", hex.formatHex(out));
    }

    private static byte[][] keys(Tls12CipherSuite suite) {
        Tls12Prf.Keys k = Tls12Prf.keys(suite, new byte[48], new byte[32], new byte[32]);
        return new byte[][] {k.clientMac(), k.clientKey(), k.clientIv()};
    }

    private static byte[] sealAll(Tls12CipherSuite suite, byte[]... records) throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer w = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
        byte[][] k = keys(suite);
        w.writeKeys12(suite, k[0], k[1], k[2], new SecureRandom());
        for (byte[] r : records) w.write(TlsRecordLayer.APPLICATION_DATA, r);
        w.flush();
        return wire.toByteArray();
    }

    private static TlsRecordLayer reader(Tls12CipherSuite suite, byte[] wire) throws QuicException {
        TlsRecordLayer r = new TlsRecordLayer(new ByteArrayInputStream(wire), new ByteArrayOutputStream());
        byte[][] k = keys(suite);
        r.readKeys12(suite, k[0], k[1], k[2]);
        return r;
    }

    @Test
    void cbcCannotBeInstalledEvenIfItWasAdvertised() {
        for (Tls12CipherSuite suite : Tls12CipherSuite.values()) {
            if (!suite.bulk.cbc()) continue;
            byte[][] k = keys(suite);
            TlsRecordLayer layer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream());
            assertThrows(IllegalArgumentException.class,
                    () -> layer.writeKeys12(suite, k[0], k[1], k[2], new SecureRandom()), suite.toString());
            assertThrows(IllegalArgumentException.class,
                    () -> layer.readKeys12(suite, k[0], k[1], k[2]), suite.toString());
        }
    }

    @Test
    void everyAeadSuiteSealsAndOpensRecordsInSequence() throws Exception {
        for (Tls12CipherSuite suite : Tls12CipherSuite.values()) {
            if (suite.bulk.cbc()) continue;
            byte[][] messages = {new byte[0], "x".getBytes(), new byte[15], new byte[16], new byte[17], new byte[20000]};
            for (byte[] m : messages) Arrays.fill(m, (byte) 0x5a);
            TlsRecordLayer r = reader(suite, sealAll(suite, messages));
            ByteArrayOutputStream got = new ByteArrayOutputStream();
            for (TlsRecordLayer.Record rec; (rec = r.read()) != null; ) {
                assertEquals(TlsRecordLayer.APPLICATION_DATA, rec.type(), suite.toString());
                got.write(rec.fragment());
            }
            ByteArrayOutputStream expected = new ByteArrayOutputStream();
            for (byte[] m : messages) expected.write(m);
            assertArrayEquals(expected.toByteArray(), got.toByteArray(), suite.toString());
        }
    }

    @Test
    void aFlippedBitAnywhereIsBadRecordMac() throws Exception {
        for (Tls12CipherSuite suite : Tls12CipherSuite.values()) {
            if (suite.bulk.cbc()) continue;
            byte[] wire = sealAll(suite, new byte[40]);
            for (int at : new int[] {5, wire.length / 2, wire.length - 1}) {
                byte[] tampered = wire.clone();
                tampered[at] ^= 1;
                QuicException e = assertThrows(QuicException.class, () -> reader(suite, tampered).read(), suite + " at " + at);
                assertEquals(TlsAlert.BAD_RECORD_MAC, TlsAlert.fromErrorCode(e.code()), suite.toString());
            }
        }
    }

    @Test
    void recordsOutOfSequenceDoNotOpen() throws Exception {
        Tls12CipherSuite suite = Tls12CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
        byte[] wire = sealAll(suite, new byte[10], new byte[10]);
        int first = 5 + (((wire[3] & 0xff) << 8) | (wire[4] & 0xff));
        // the second record alone, read as if it were the first
        byte[] second = Arrays.copyOfRange(wire, first, wire.length);
        assertThrows(QuicException.class, () -> reader(suite, second).read());
    }
}
