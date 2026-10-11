package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.Secrets;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * An in-memory connection layer: it moves each level's handshake bytes between a client and a
 * server session, cut into random fragments, collecting the secrets each side hands out.
 */
final class Handshakes {

    /** Rewrites the bytes one side sends at one level, to inject faults. */
    interface Tamper {
        byte[] apply(boolean fromServer, EncryptionLevel level, byte[] bytes);
    }

    static final Tamper NONE = (fromServer, level, bytes) -> bytes;

    static final byte[] CLIENT_PARAMS = {0x01, 0x02, 0x03};
    static final byte[] SERVER_PARAMS = {0x04, 0x05, 0x06, 0x07};

    final TlsSession client;
    final TlsSession server;
    final Map<EncryptionLevel, Secrets> clientSecrets = new EnumMap<>(EncryptionLevel.class);
    final Map<EncryptionLevel, Secrets> serverSecrets = new EnumMap<>(EncryptionLevel.class);
    private final Random random;
    private final Tamper tamper;

    Handshakes(TlsSession client, TlsSession server, Random random, Tamper tamper) {
        this.client = client;
        this.server = server;
        this.random = random;
        this.tamper = tamper;
    }

    static Handshakes run(TlsConfig clientConfig, TlsConfig serverConfig) throws QuicException {
        return run(clientConfig, serverConfig, new Random(1), NONE);
    }

    static Handshakes run(TlsConfig clientConfig, TlsConfig serverConfig, Random random, Tamper tamper)
            throws QuicException {
        Handshakes h = new Handshakes(TlsSession.client(clientConfig, CLIENT_PARAMS),
                TlsSession.server(serverConfig, SERVER_PARAMS), random, tamper);
        h.complete();
        return h;
    }

    /** Shuttles bytes until neither side has anything more to send. */
    void complete() throws QuicException {
        drain(client, clientSecrets);
        for (int round = 0; round < 8; round++) {
            boolean moved = deliver(client, server, false);
            drain(server, serverSecrets);
            moved |= deliver(server, client, true);
            drain(client, clientSecrets);
            if (!moved) return;
        }
        throw new AssertionError("handshake did not settle");
    }

    private static void drain(TlsSession session, Map<EncryptionLevel, Secrets> into) {
        for (Secrets s; (s = session.nextSecrets()) != null; ) {
            if (into.put(s.level(), s) != null) throw new AssertionError("secrets for " + s.level() + " twice");
        }
    }

    private boolean deliver(TlsSession from, TlsSession to, boolean fromServer) throws QuicException {
        boolean moved = false;
        for (EncryptionLevel level : EncryptionLevel.values()) {
            byte[] bytes = from.writeHandshake(level);
            if (bytes.length == 0) continue;
            moved = true;
            feed(to, level, tamper.apply(fromServer, level, bytes), random);
        }
        return moved;
    }

    /** Feeds bytes in random fragments, sometimes one byte at a time, sometimes all at once. */
    static void feed(TlsSession to, EncryptionLevel level, byte[] bytes, Random random) throws QuicException {
        int mode = random.nextInt(3);
        int at = 0;
        while (at < bytes.length) {
            int n = switch (mode) {
                case 0 -> bytes.length - at;
                case 1 -> 1 + random.nextInt(Math.min(7, bytes.length - at));
                default -> 1 + random.nextInt(bytes.length - at);
            };
            ByteBuffer buffer = ByteBuffer.wrap(bytes, at, n);
            to.readHandshake(level, buffer);
            if (buffer.hasRemaining()) throw new AssertionError("readHandshake left bytes unread");
            at += n;
        }
    }

    /** Both sides finished with the same secrets at each level and agree on what was negotiated. */
    void assertAgreement() {
        assertTrue(client.isHandshakeComplete(), "client complete");
        assertTrue(server.isHandshakeComplete(), "server complete");
        assertEquals(List.of(EncryptionLevel.HANDSHAKE, EncryptionLevel.ONE_RTT), new ArrayList<>(clientSecrets.keySet()));
        assertEquals(clientSecrets.keySet(), serverSecrets.keySet());
        for (EncryptionLevel level : clientSecrets.keySet()) {
            Secrets c = clientSecrets.get(level);
            Secrets s = serverSecrets.get(level);
            assertEquals(c.suite(), s.suite());
            assertArrayEquals(c.client(), s.client(), level + " client secret");
            assertArrayEquals(c.server(), s.server(), level + " server secret");
            assertEquals(c.suite().hkdf().hashLength(), c.client().length);
            assertTrue(!Arrays.equals(c.client(), c.server()), "directions differ");
        }
        assertNotNull(client.cipherSuite());
        assertEquals(client.cipherSuite(), server.cipherSuite());
        assertEquals(client.negotiatedGroup(), server.negotiatedGroup());
        assertEquals(client.negotiatedAlpn(), server.negotiatedAlpn());
        assertEquals(client.usedHelloRetryRequest(), server.usedHelloRetryRequest());
        assertArrayEquals(SERVER_PARAMS, client.peerTransportParameters());
        assertArrayEquals(CLIENT_PARAMS, server.peerTransportParameters());
        assertArrayEquals(client.exportKeyingMaterial("EXPORTER-test", new byte[] {1}, 32),
                server.exportKeyingMaterial("EXPORTER-test", new byte[] {1}, 32));
    }

    /** Splits a flight into its handshake messages. */
    static List<byte[]> messages(byte[] flight) {
        List<byte[]> out = new ArrayList<>();
        int at = 0;
        while (at < flight.length) {
            int len = ((flight[at + 1] & 0xff) << 16) | ((flight[at + 2] & 0xff) << 8) | (flight[at + 3] & 0xff);
            out.add(Arrays.copyOfRange(flight, at, at + 4 + len));
            at += 4 + len;
        }
        return out;
    }

    static byte[] join(List<byte[]> messages) {
        int total = 0;
        for (byte[] m : messages) total += m.length;
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] m : messages) {
            System.arraycopy(m, 0, out, at, m.length);
            at += m.length;
        }
        return out;
    }

    /** Rewrites the first message of a type in a flight. */
    static byte[] rewrite(byte[] flight, int type, java.util.function.UnaryOperator<byte[]> change) {
        List<byte[]> messages = messages(flight);
        for (int i = 0; i < messages.size(); i++) {
            if ((messages.get(i)[0] & 0xff) == type) {
                messages.set(i, change.apply(messages.get(i)));
                break;
            }
        }
        return join(messages);
    }

    static HandshakeMessage decode(byte[] message) {
        try {
            return HandshakeMessage.decode(message[0] & 0xff, Arrays.copyOfRange(message, 4, message.length));
        } catch (QuicException e) {
            throw new AssertionError(e);
        }
    }

    /** The alert in a CRYPTO_ERROR. */
    static int alert(QuicException e) {
        return TlsAlert.fromErrorCode(e.code());
    }
}
