package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;

/** Functional observations for the formal models, not a refinement proof of the Java implementation. */
class FormalRecordModelTest {

    private static final long AES_LIMIT = 1L << 23;
    private static final byte[] PAYLOAD = {0, 1, 2, 3, 7, (byte) 0x80, (byte) 0xff};
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] NONCE_IV = HEX.parseHex("000102030405060708090a0b");
    private static final long GOLDEN_SEQUENCE = 0x0102030405060708L;

    private record SuiteCase(CipherSuite tls13, Tls12CipherSuite tls12, long limit) {
        String name() {
            return tls13 != null ? tls13.name() : tls12.name();
        }

        void installWrite(TlsRecordLayer layer) throws QuicException {
            if (tls13 != null) {
                layer.writeKeys(tls13, material(tls13.hkdf().hashLength()));
            } else {
                layer.writeKeys12(tls12, new byte[0], material(tls12.bulk.keyLength),
                        material(tls12.bulk.ivLength), new SecureRandom());
            }
        }

        void installRead(TlsRecordLayer layer) throws QuicException {
            if (tls13 != null) {
                layer.readKeys(tls13, material(tls13.hkdf().hashLength()));
            } else {
                layer.readKeys12(tls12, new byte[0], material(tls12.bulk.keyLength),
                        material(tls12.bulk.ivLength));
            }
        }

        int wireLength() {
            int innerType = tls13 != null ? 1 : 0;
            int explicitNonce = tls12 != null && tls12.bulk != Tls12CipherSuite.Bulk.CHACHA20_POLY1305 ? 8 : 0;
            return 5 + PAYLOAD.length + innerType + explicitNonce + PacketKey.TAG_LENGTH;
        }
    }

    private static List<SuiteCase> suites() {
        return List.of(
                new SuiteCase(CipherSuite.TLS_AES_128_GCM_SHA256, null, AES_LIMIT),
                new SuiteCase(CipherSuite.TLS_AES_256_GCM_SHA384, null, AES_LIMIT),
                new SuiteCase(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, null, Long.MAX_VALUE),
                new SuiteCase(null, Tls12CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, AES_LIMIT),
                new SuiteCase(null, Tls12CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, AES_LIMIT),
                new SuiteCase(null, Tls12CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, Long.MAX_VALUE));
    }

    @Test
    void protectedReadAndWriteGuardsMatchPerKeyAllocationBoundaries() throws Exception {
        List<String> observations = new ArrayList<>();
        for (SuiteCase suite : suites()) {
            long limit = suite.limit();
            long[] boundaries = limit == Long.MAX_VALUE
                    ? new long[] {0, 1, limit - 2, limit - 1, limit}
                    : new long[] {0, 1, limit - 2, limit - 1, limit, limit + 1};
            for (long before : boundaries) observeBoundary(suite, before, observations);
            // Signed-invalid counters are tested in Java but excluded from the Nat-model export.
            for (long before : new long[] {-1, Long.MIN_VALUE}) {
                observeBoundary(suite, before, observations);
            }
            observeLastTwoAllocations(suite, observations);
        }
        export("records.jsonl", observations);
    }

    private static void observeBoundary(SuiteCase suite, long before, List<String> observations) throws Exception {
        String where = suite.name() + " sequence " + before;
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer writer = layer(new byte[0], wire);
        suite.installWrite(writer);
        assertEquals(suite.limit(), limit(writer, "write"), where);
        sequence(writer, "write", before);
        boolean accepted = before >= 0 && before < suite.limit();
        if (accepted) {
            writer.write(TlsRecordLayer.APPLICATION_DATA, PAYLOAD);
            assertEquals(before + 1, sequence(writer, "write"), where);
            assertEquals(suite.wireLength(), wire.size(), where);
            byte[] encoded = wire.toByteArray();
            assertEquals(TlsRecordLayer.APPLICATION_DATA, encoded[0] & 0xff, where);
            assertEquals(3, encoded[1] & 0xff, where);
            assertEquals(3, encoded[2] & 0xff, where);
            assertEquals(encoded.length - 5, ((encoded[3] & 0xff) << 8) | (encoded[4] & 0xff), where);
            observe(observations, writer, "write", before, true);

            ByteArrayOutputStream peerOutput = new ByteArrayOutputStream();
            TlsRecordLayer peer = layer(encoded, peerOutput);
            suite.installRead(peer);
            assertEquals(suite.limit(), limit(peer, "read"), where);
            sequence(peer, "read", before);
            TlsRecordLayer.Record opened = peer.read();
            assertEquals(TlsRecordLayer.APPLICATION_DATA, opened.type(), where);
            assertArrayEquals(PAYLOAD, opened.fragment(), where);
            assertEquals(before + 1, sequence(peer, "read"), where);
            observe(observations, peer, "read", before, true);
            assertNull(peer.read(), where);
            assertEquals(before + 1, sequence(peer, "read"), where);
            assertEquals(0, peerOutput.size(), where);
        } else {
            IOException failure = assertThrows(IOException.class,
                    () -> writer.write(TlsRecordLayer.APPLICATION_DATA, PAYLOAD), where);
            assertTrue(failure.getMessage().contains("key usage limit"), where);
            assertEquals(0, wire.size(), where);
            assertEquals(before, sequence(writer, "write"), where);
            observe(observations, writer, "write", before, false);

            // A complete protected record passes framing, then the usage guard must reject
            // before attempting authentication with the exhausted or signed-invalid counter.
            ByteArrayOutputStream peerOutput = new ByteArrayOutputStream();
            TlsRecordLayer peer = layer(sealAtZero(suite), peerOutput);
            suite.installRead(peer);
            assertEquals(suite.limit(), limit(peer, "read"), where);
            sequence(peer, "read", before);
            QuicException rejected = assertThrows(QuicException.class, peer::read, where);
            assertEquals(TlsAlert.INTERNAL_ERROR, TlsAlert.fromErrorCode(rejected.code()), where);
            assertTrue(rejected.getMessage().contains("key usage limit"), where);
            assertEquals(before, sequence(peer, "read"), where);
            assertEquals(0, peerOutput.size(), where);
            observe(observations, peer, "read", before, false);
        }
    }

    private static void observeLastTwoAllocations(SuiteCase suite, List<String> observations) throws Exception {
        String where = suite.name() + " last two allocations";
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer writer = layer(new byte[0], wire);
        suite.installWrite(writer);
        sequence(writer, "write", suite.limit() - 2);
        for (int i = 0; i < 2; i++) {
            long before = sequence(writer, "write");
            writer.write(TlsRecordLayer.APPLICATION_DATA, PAYLOAD);
            assertEquals(before + 1, sequence(writer, "write"), where);
            assertEquals((i + 1) * suite.wireLength(), wire.size(), where);
            observe(observations, writer, "write", before, true);
        }
        assertThrows(IOException.class, () -> writer.write(TlsRecordLayer.APPLICATION_DATA, PAYLOAD), where);
        assertEquals(suite.limit(), sequence(writer, "write"), where);
        assertEquals(2 * suite.wireLength(), wire.size(), where);
        observe(observations, writer, "write", suite.limit(), false);

        byte[] encoded = wire.toByteArray();
        ByteArrayOutputStream incoming = new ByteArrayOutputStream();
        incoming.writeBytes(encoded);
        incoming.write(encoded, 0, suite.wireLength());
        ByteArrayOutputStream peerOutput = new ByteArrayOutputStream();
        TlsRecordLayer peer = layer(incoming.toByteArray(), peerOutput);
        suite.installRead(peer);
        sequence(peer, "read", suite.limit() - 2);
        for (int i = 0; i < 2; i++) {
            long before = sequence(peer, "read");
            TlsRecordLayer.Record opened = peer.read();
            assertEquals(TlsRecordLayer.APPLICATION_DATA, opened.type(), where);
            assertArrayEquals(PAYLOAD, opened.fragment(), where);
            assertEquals(before + 1, sequence(peer, "read"), where);
            observe(observations, peer, "read", before, true);
        }
        QuicException failure = assertThrows(QuicException.class, peer::read, where);
        assertEquals(TlsAlert.INTERNAL_ERROR, TlsAlert.fromErrorCode(failure.code()), where);
        assertEquals(suite.limit(), sequence(peer, "read"), where);
        assertEquals(0, peerOutput.size(), where);
        observe(observations, peer, "read", suite.limit(), false);
    }

    @Test
    void isolatedTlsAndQuicNonceEncodingMatchesUnsignedBigEndianVectors() throws Exception {
        assertArrayEquals(HEX.parseHex("00010203050705030d0f0d03"), expectedNonce(NONCE_IV, GOLDEN_SEQUENCE));
        List<String> observations = new ArrayList<>();
        long[] sequences = {0, 1, 255, 256, AES_LIMIT - 1, 1L << 31, 1L << 32,
            GOLDEN_SEQUENCE, 1L << 62, Long.MAX_VALUE};
        for (CipherSuite suite : CipherSuite.values()) {
            for (long sequence : sequences) {
                String where = suite.name() + " nonce sequence " + sequence;
                byte[] expected = expectedNonce(NONCE_IV, sequence);
                PacketKey packet = PacketKey.of(suite, material(suite.keyLength()), NONCE_IV);
                byte[] packetNonce = packet.nonce(sequence);
                assertArrayEquals(expected, packetNonce, where);
                observeNonce(observations, NONCE_IV, sequence, packetNonce);

                TlsRecordLayer isolated = layer(new byte[0], new ByteArrayOutputStream());
                isolated.writeKeys(suite, material(suite.hkdf().hashLength()));
                Object protection = protection(isolated, "write");
                Field ivField = protection.getClass().getDeclaredField("iv");
                ivField.setAccessible(true);
                byte[] iv = (byte[]) ivField.get(protection);
                System.arraycopy(NONCE_IV, 0, iv, 0, NONCE_IV.length);
                sequence(isolated, "write", sequence);
                var cipherMethod = protection.getClass().getDeclaredMethod("cipher", int.class);
                cipherMethod.setAccessible(true);
                // This direct call isolates nonce encoding. High sequences may exceed a suite's
                // record cap (or QUIC's packet-number range); no record/packet is sent, no
                // exhausted key is used through the guarded record API, and this object is discarded.
                Cipher cipher = (Cipher) cipherMethod.invoke(protection, Cipher.ENCRYPT_MODE);
                byte[] tlsNonce = cipher.getIV();
                assertArrayEquals(expected, tlsNonce, where);
                observeNonce(observations, NONCE_IV, sequence, tlsNonce);
            }
        }
        export("nonces.jsonl", observations);
    }

    private static byte[] expectedNonce(byte[] iv, long sequence) {
        byte[] padded = ByteBuffer.allocate(12).putInt(0).putLong(sequence).array();
        byte[] result = iv.clone();
        for (int i = 0; i < result.length; i++) result[i] ^= padded[i];
        return result;
    }

    private static byte[] material(int size) {
        byte[] result = new byte[size];
        for (int i = 0; i < result.length; i++) result[i] = (byte) (17 * i + 3);
        return result;
    }

    private static TlsRecordLayer layer(byte[] input, ByteArrayOutputStream output) {
        return new TlsRecordLayer(new ByteArrayInputStream(input), output);
    }

    private static byte[] sealAtZero(SuiteCase suite) throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer writer = layer(new byte[0], wire);
        suite.installWrite(writer);
        writer.write(TlsRecordLayer.APPLICATION_DATA, PAYLOAD);
        return wire.toByteArray();
    }

    private static Object protection(TlsRecordLayer layer, String direction) throws Exception {
        Field field = TlsRecordLayer.class.getDeclaredField(direction);
        field.setAccessible(true);
        return field.get(layer);
    }

    private static Field counterField(Object protection, String name) throws Exception {
        Field field = protection.getClass().getSuperclass().getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static void sequence(TlsRecordLayer layer, String direction, long sequence) throws Exception {
        Object protection = protection(layer, direction);
        counterField(protection, "sequence").setLong(protection, sequence);
    }

    private static long sequence(TlsRecordLayer layer, String direction) throws Exception {
        Object protection = protection(layer, direction);
        return counterField(protection, "sequence").getLong(protection);
    }

    private static long limit(TlsRecordLayer layer, String direction) throws Exception {
        Object protection = protection(layer, direction);
        return counterField(protection, "recordLimit").getLong(protection);
    }

    private static void observe(List<String> observations, TlsRecordLayer layer, String direction,
            long before, boolean accepted) throws Exception {
        if (before < 0) return;
        observations.add("{\"kind\":\"record\",\"limit\":" + limit(layer, direction)
                + ",\"before\":" + before + ",\"accepted\":" + accepted
                + ",\"after\":" + sequence(layer, direction) + "}");
    }

    private static void observeNonce(List<String> observations, byte[] iv, long sequence, byte[] nonce) {
        assertTrue(sequence >= 0);
        assertEquals(12, iv.length);
        assertEquals(12, nonce.length);
        observations.add("{\"kind\":\"nonce\",\"iv\":\"" + HEX.formatHex(iv)
                + "\",\"sequence\":" + sequence + ",\"nonce\":\"" + HEX.formatHex(nonce) + "\"}");
    }

    private static void export(String filename, List<String> observations) throws IOException {
        String directory = System.getProperty("microproxy.formal.output");
        if (directory != null) {
            Path destination = Path.of(directory).resolve(filename);
            Files.createDirectories(destination.getParent());
            Files.write(destination, observations, StandardCharsets.UTF_8);
        }
    }
}
