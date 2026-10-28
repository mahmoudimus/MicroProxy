package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.mahmoudimus.quic.CipherSuite;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.SecureRandom;
import java.time.InstantSource;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class TlsKeyUsageTest {

    private static void field(Object target, String name, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static TlsRecordLayer records(TlsClientConnection connection) throws Exception {
        var field = TlsClientConnection.class.getDeclaredField("records");
        field.setAccessible(true);
        return (TlsRecordLayer) field.get(connection);
    }

    private static void sequence(TlsRecordLayer records, String direction, long value) throws Exception {
        var field = TlsRecordLayer.class.getDeclaredField(direction);
        field.setAccessible(true);
        Object protection = field.get(records);
        var sequence = protection.getClass().getSuperclass().getDeclaredField("sequence");
        sequence.setAccessible(true);
        sequence.setLong(protection, value);
    }

    @Test
    void anApplicationWriteRotatesKeysBetweenFragmentsBeforeTheLimit() throws Exception {
        CipherSuite suite = CipherSuite.TLS_AES_128_GCM_SHA256;
        byte[] secret = new byte[32];
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        var config = new TlsClientConnection.Config(BrowserProfiles.chrome156(), TestCerts.CA.trustManager(), null,
                ClientSessionStore.NONE, Map.of(), CertificateDecompressor.ZLIB, new SecureRandom(),
                InstantSource.system(), 65536);
        TlsClientConnection connection = new TlsClientConnection(config, new ByteArrayInputStream(new byte[0]),
                wire, "tls.test", "tls.test", List.of(), null);
        field(connection, "handshakeDone", true);
        field(connection, "suite", suite);
        field(connection, "clientApplicationSecret", secret);
        records(connection).writeKeys(suite, secret);
        sequence(records(connection), "write", (1L << 23) - 2);
        byte[] data = new byte[3 * 16384 + 2];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        connection.write(data, 0, data.length);

        TlsRecordLayer peer = new TlsRecordLayer(new ByteArrayInputStream(wire.toByteArray()),
                new ByteArrayOutputStream());
        peer.readKeys(suite, secret);
        sequence(peer, "read", (1L << 23) - 2);
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        TlsRecordLayer.Record first = peer.read();
        assertEquals(TlsRecordLayer.APPLICATION_DATA, first.type());
        received.write(first.fragment());
        TlsRecordLayer.Record update = peer.read();
        assertEquals(TlsRecordLayer.HANDSHAKE, update.type());
        assertArrayEquals(new byte[] {24, 0, 0, 1, 0}, update.fragment());
        byte[] next = suite.hkdf().expandLabel(secret, "traffic upd", new byte[0], 32);
        peer.readKeys(suite, next);
        for (int i = 0; i < 3; i++) {
            TlsRecordLayer.Record record = peer.read();
            assertEquals(TlsRecordLayer.APPLICATION_DATA, record.type());
            received.write(record.fragment());
        }
        assertNull(peer.read());
        assertArrayEquals(data, received.toByteArray());
    }

    @Test
    void rejectingANewTrafficKeyClosesWritesWithoutSendingApplicationData() throws Exception {
        AtomicReference<byte[]> firstKey = new AtomicReference<>();
        AlgorithmConstraints constraints = new AlgorithmConstraints() {
            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters params) {
                return true;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
                if (!(key instanceof SecretKey)) return true;
                firstKey.compareAndSet(null, key.getEncoded());
                return Arrays.equals(firstKey.get(), key.getEncoded());
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters params) {
                return permits(primitives, key);
            }
        };
        CipherSuite suite = CipherSuite.TLS_AES_128_GCM_SHA256;
        byte[] secret = new byte[32];
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        var config = new TlsClientConnection.Config(BrowserProfiles.chrome156(), TestCerts.CA.trustManager(), null,
                ClientSessionStore.NONE, Map.of(), CertificateDecompressor.ZLIB, new SecureRandom(),
                InstantSource.system(), 65536);
        TlsClientConnection connection = new TlsClientConnection(config, new ByteArrayInputStream(new byte[0]),
                wire, "tls.test", "tls.test", List.of(), null);
        field(connection, "handshakeDone", true);
        field(connection, "suite", suite);
        field(connection, "clientApplicationSecret", secret);
        TlsRecordLayer records = records(connection);
        records.acceptance(new TlsAcceptancePolicy(null, constraints));
        records.writeKeys(suite, secret);
        sequence(records, "write", (1L << 23) - 1);
        assertThrows(IOException.class, () -> connection.write(new byte[] {1}, 0, 1));

        TlsRecordLayer peer = new TlsRecordLayer(new ByteArrayInputStream(wire.toByteArray()), new ByteArrayOutputStream());
        peer.readKeys(suite, secret);
        sequence(peer, "read", (1L << 23) - 1);
        TlsRecordLayer.Record update = peer.read();
        assertEquals(TlsRecordLayer.HANDSHAKE, update.type());
        assertArrayEquals(new byte[] {24, 0, 0, 1, 0}, update.fragment());
        assertNull(peer.read());
        int sent = wire.size();
        assertThrows(IOException.class, () -> connection.write(new byte[] {2}, 0, 1));
        assertEquals(sent, wire.size());
    }
}
