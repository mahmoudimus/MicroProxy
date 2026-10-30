package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TlsRecordLayerTest {

    private static final Map<String, byte[]> RFC8448 = load();

    private static Map<String, byte[]> load() {
        Map<String, byte[]> out = new HashMap<>();
        try (InputStream in = TlsRecordLayerTest.class.getResourceAsStream("/rfc8448-records.txt");
                BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            for (String line; (line = r.readLine()) != null; ) {
                if (line.startsWith("#") || line.isBlank()) continue;
                int eq = line.indexOf('=');
                out.put(line.substring(0, eq), HexFormat.of().parseHex(line.substring(eq + 1)));
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    private static TlsRecordLayer reading(byte[] wire) {
        return new TlsRecordLayer(new ByteArrayInputStream(wire), new ByteArrayOutputStream());
    }

    /** Reach a key boundary without encrypting millions of records. */
    private static void sequence(TlsRecordLayer layer, String direction, long value) throws Exception {
        var field = TlsRecordLayer.class.getDeclaredField(direction);
        field.setAccessible(true);
        Object protection = field.get(layer);
        var sequence = protection.getClass().getSuperclass().getDeclaredField("sequence");
        sequence.setAccessible(true);
        sequence.setLong(protection, value);
    }

    @Test
    void aMultiRecordWriteStopsBeforeTheAesKeyLimit() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer writer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
        writer.writeKeys(CipherSuite.TLS_AES_128_GCM_SHA256, new byte[32]);
        sequence(writer, "write", (1L << 23) - 1);
        assertThrows(IOException.class, () -> writer.write(TlsRecordLayer.APPLICATION_DATA, new byte[20000]));
        assertEquals(5 + 16384 + 1 + 16, wire.size());
    }

    @Test
    void readKeyLimitIsCheckedBeforeAuthentication() throws Exception {
        TlsRecordLayer reader = reading(RFC8448.get("server_record"));
        reader.readKeys(CipherSuite.TLS_AES_128_GCM_SHA256, RFC8448.get("server_hs_secret"));
        sequence(reader, "read", 1L << 23);
        QuicException failure = assertThrows(QuicException.class, reader::read);
        assertEquals(TlsAlert.INTERNAL_ERROR, TlsAlert.fromErrorCode(failure.code()));
        assertTrue(failure.getMessage().contains("key usage"));
    }

    @Test
    void anExhaustedCounterNeverWrapsAndEmitsAnotherNonce() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer writer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
        writer.writeKeys(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, new byte[32]);
        sequence(writer, "write", -1L);
        assertThrows(IOException.class, () -> writer.write(TlsRecordLayer.APPLICATION_DATA, new byte[] {1}));
        assertEquals(0, wire.size());
    }

    @Test
    void tls12AesKeysCannotBeUsedPastTheirLimit() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer writer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
        writer.writeKeys12(Tls12CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                new byte[0], new byte[16], new byte[4], new java.security.SecureRandom());
        sequence(writer, "write", 1L << 23);
        assertThrows(IOException.class, () -> writer.write(TlsRecordLayer.APPLICATION_DATA, new byte[] {1}));
        assertEquals(0, wire.size());
    }

    @Test
    void decryptsRfc8448sServerFlight() throws Exception {
        TlsRecordLayer layer = reading(RFC8448.get("server_record"));
        layer.readKeys(CipherSuite.TLS_AES_128_GCM_SHA256, RFC8448.get("server_hs_secret"));
        TlsRecordLayer.Record record = layer.read();
        assertEquals(TlsRecordLayer.HANDSHAKE, record.type());
        assertArrayEquals(RFC8448.get("server_payload"), record.fragment());
        assertNull(layer.read());
    }

    @Test
    void encryptsRfc8448sClientFinished() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer layer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
        layer.writeKeys(CipherSuite.TLS_AES_128_GCM_SHA256, RFC8448.get("client_hs_secret"));
        layer.write(TlsRecordLayer.HANDSHAKE, RFC8448.get("client_payload"));
        layer.flush();
        assertArrayEquals(RFC8448.get("client_record"), wire.toByteArray());
    }

    @Test
    void plaintextRecordsBeforeKeysWithTheInitialVersion() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TlsRecordLayer layer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
        layer.write(TlsRecordLayer.HANDSHAKE, new byte[] {1, 2, 3});
        layer.plaintextVersion(0x0303);
        layer.write(TlsRecordLayer.HANDSHAKE, new byte[] {4});
        layer.flush();
        // the ClientHello's record says TLS 1.0, as browsers' do (RFC 8446 section 5.1)
        assertArrayEquals(new byte[] {22, 3, 1, 0, 3, 1, 2, 3, 22, 3, 3, 0, 1, 4}, wire.toByteArray());
    }

    @Test
    void largeDataIsSplitIntoFullRecordsAndReadBack() throws Exception {
        byte[] secret = new byte[48];
        for (CipherSuite suite : CipherSuite.values()) {
            byte[] key = java.util.Arrays.copyOf(secret, suite.hkdf().hashLength());
            ByteArrayOutputStream wire = new ByteArrayOutputStream();
            TlsRecordLayer writer = new TlsRecordLayer(new ByteArrayInputStream(new byte[0]), wire);
            writer.writeKeys(suite, key);
            byte[] data = new byte[40000];
            for (int i = 0; i < data.length; i++) data[i] = (byte) i;
            writer.write(TlsRecordLayer.APPLICATION_DATA, data);
            writer.flush();
            TlsRecordLayer reader = reading(wire.toByteArray());
            reader.readKeys(suite, key);
            ByteArrayOutputStream got = new ByteArrayOutputStream();
            int records = 0;
            for (TlsRecordLayer.Record r; (r = reader.read()) != null; records++) {
                assertEquals(TlsRecordLayer.APPLICATION_DATA, r.type());
                assertTrue(r.fragment().length <= TlsRecordLayer.MAX_FRAGMENT);
                got.write(r.fragment());
            }
            assertEquals(3, records, suite.toString());
            assertArrayEquals(data, got.toByteArray(), suite.toString());
        }
    }

    @Test
    void aTamperedRecordIsBadRecordMac() throws Exception {
        byte[] wire = RFC8448.get("server_record").clone();
        wire[40] ^= 1;
        TlsRecordLayer layer = reading(wire);
        layer.readKeys(CipherSuite.TLS_AES_128_GCM_SHA256, RFC8448.get("server_hs_secret"));
        QuicException e = assertThrows(QuicException.class, layer::read);
        assertEquals(TlsAlert.BAD_RECORD_MAC, TlsAlert.fromErrorCode(e.code()));
    }

    @Test
    void anOversizedRecordIsRecordOverflow() {
        byte[] header = {22, 3, 3, (byte) 0x40, 1};
        QuicException e = assertThrows(QuicException.class, () -> reading(header).read());
        assertEquals(TlsAlert.RECORD_OVERFLOW, TlsAlert.fromErrorCode(e.code()));
    }

    @Test
    void anUnprotectedRecordAfterKeysIsUnexpectedExceptChangeCipherSpec() throws Exception {
        TlsRecordLayer ccs = reading(new byte[] {20, 3, 3, 0, 1, 1});
        ccs.readKeys(CipherSuite.TLS_AES_128_GCM_SHA256, new byte[32]);
        assertEquals(TlsRecordLayer.CHANGE_CIPHER_SPEC, ccs.read().type());
        TlsRecordLayer handshake = reading(new byte[] {22, 3, 3, 0, 1, 1});
        handshake.readKeys(CipherSuite.TLS_AES_128_GCM_SHA256, new byte[32]);
        QuicException e = assertThrows(QuicException.class, handshake::read);
        assertEquals(TlsAlert.UNEXPECTED_MESSAGE, TlsAlert.fromErrorCode(e.code()));
    }

    @Test
    void aRecordCutShortIsAnEofError() {
        assertThrows(java.io.EOFException.class, () -> reading(new byte[] {23, 3, 3, 0, 5, 1}).read());
    }
}
