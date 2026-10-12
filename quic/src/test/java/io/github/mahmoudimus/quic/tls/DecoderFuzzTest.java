package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Feeds mutated handshake messages and extension bodies, from a fixed seed, to the decoders, which
 * may only fail with a {@code decode_error} alert; and mutated flights to whole sessions, which may
 * only fail with a {@link QuicException} that is not an internal error.
 */
class DecoderFuzzTest {

    private static final long SEED = 0x7153_1e55_c0deL;
    private static final long DECODE_ERROR = QuicException.CRYPTO_ERROR + TlsAlert.DECODE_ERROR;

    /** Every message of a handshake with a retry and client authentication, plus post-handshake ones. */
    private static List<byte[]> corpus() throws Exception {
        List<byte[]> messages = new ArrayList<>();
        Handshakes.Tamper record = (fromServer, level, bytes) -> {
            messages.addAll(Handshakes.messages(bytes));
            return bytes;
        };
        Handshakes h = Handshakes.run(
                HandshakeTest.client().groups(NamedGroup.SECP256R1, NamedGroup.X25519)
                        .clientCertificate(TestCerts.CA.issue(KeyType.ED25519, "client.test")).build(),
                HandshakeTest.server().groups(NamedGroup.X25519).clientAuth(ClientAuth.REQUIRE)
                        .clientTrustManager(TestCerts.CA.trustManager()).build(),
                new Random(1), record);
        h.assertAgreement();
        messages.add(new HandshakeMessage.NewSessionTicket(7200, 5, new byte[] {1, 2}, new byte[] {3, 4, 5},
                List.of(new Extension(ExtensionType.EARLY_DATA, new byte[] {0, 0, 0x40, 0}))).encode());
        messages.add(new HandshakeMessage.KeyUpdate(1).encode());
        return messages;
    }

    private static byte[] mutate(byte[] input, Random random) {
        byte[] b = input.clone();
        int rounds = 1 + random.nextInt(4);
        for (int r = 0; r < rounds; r++) {
            switch (random.nextInt(7)) {
                case 0 -> {
                    if (b.length > 0) b[random.nextInt(b.length)] ^= (byte) (1 << random.nextInt(8));
                }
                case 1 -> {
                    if (b.length > 0) b[random.nextInt(b.length)] = (byte) random.nextInt(256);
                }
                case 2 -> b = Arrays.copyOf(b, b.length == 0 ? 0 : random.nextInt(b.length));
                case 3 -> {
                    byte[] extra = new byte[1 + random.nextInt(8)];
                    random.nextBytes(extra);
                    int at = random.nextInt(b.length + 1);
                    byte[] out = new byte[b.length + extra.length];
                    System.arraycopy(b, 0, out, 0, at);
                    System.arraycopy(extra, 0, out, at, extra.length);
                    System.arraycopy(b, at, out, at + extra.length, b.length - at);
                    b = out;
                }
                case 4 -> {
                    if (b.length > 0) b[random.nextInt(b.length)] = random.nextBoolean() ? 0 : (byte) 0xff;
                }
                case 5 -> {
                    if (b.length > 1) {
                        int from = random.nextInt(b.length);
                        int len = 1 + random.nextInt(Math.min(16, b.length - from));
                        int to = random.nextInt(b.length - len + 1);
                        System.arraycopy(b, from, b, to, len);
                    }
                }
                default -> {
                    byte[] noise = new byte[random.nextInt(48)];
                    random.nextBytes(noise);
                    b = noise;
                }
            }
        }
        return b;
    }

    private static void expectDecodeErrorOnly(ThrowingRunnable decode, String what) {
        try {
            decode.run();
        } catch (QuicException e) {
            assertEquals(DECODE_ERROR, e.code(), what + ": " + e.getMessage());
        } catch (Throwable t) {
            fail(what + " threw " + t, t);
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    @Test
    void handshakeMessageDecoders() throws Exception {
        List<byte[]> corpus = corpus();
        Random random = new Random(SEED);
        int decoded = 0;
        for (int i = 0; i < 30_000; i++) {
            byte[] message = corpus.get(random.nextInt(corpus.size()));
            int type = random.nextInt(10) == 0 ? random.nextInt(256) : message[0] & 0xff;
            byte[] body = mutate(Arrays.copyOfRange(message, 4, message.length), random);
            String what = "iteration " + i + " type " + type;
            try {
                HandshakeMessage m = HandshakeMessage.decode(type, body);
                decoded++;
                // What decodes re-encodes into something that decodes again.
                byte[] again = m.encode();
                HandshakeMessage.decode(again[0] & 0xff, Arrays.copyOfRange(again, 4, again.length));
            } catch (QuicException e) {
                assertEquals(DECODE_ERROR, e.code(), what + ": " + e.getMessage());
            } catch (Throwable t) {
                fail(what + " threw " + t, t);
            }
        }
        assertTrue(decoded > 1000, "some mutations still decode: " + decoded);
    }

    @Test
    void extensionDecoders() throws Exception {
        List<byte[]> bodies = new ArrayList<>();
        for (byte[] message : corpus()) {
            HandshakeMessage m = Handshakes.decode(message);
            List<Extension> extensions = switch (m) {
                case HandshakeMessage.ClientHello ch -> ch.extensions();
                case HandshakeMessage.ServerHello sh -> sh.extensions();
                case HandshakeMessage.EncryptedExtensions ee -> ee.extensions();
                case HandshakeMessage.CertificateRequest cr -> cr.extensions();
                default -> List.of();
            };
            for (Extension e : extensions) bodies.add(e.data());
        }
        Random random = new Random(SEED + 1);
        for (int i = 0; i < 30_000; i++) {
            byte[] body = mutate(bodies.get(random.nextInt(bodies.size())), random);
            String what = "iteration " + i;
            expectDecodeErrorOnly(() -> Extensions.decodeServerName(body), what + " server_name");
            expectDecodeErrorOnly(() -> Extensions.decodeU16List(body, "list"), what + " u16 list");
            expectDecodeErrorOnly(() -> Extensions.decodeAlpn(body), what + " alpn");
            expectDecodeErrorOnly(() -> Extensions.decodeSupportedVersionsClient(body), what + " versions");
            expectDecodeErrorOnly(() -> Extensions.decodeSupportedVersionServer(body), what + " version");
            expectDecodeErrorOnly(() -> Extensions.decodeKeyShareClient(body), what + " client shares");
            expectDecodeErrorOnly(() -> Extensions.decodeKeyShareServer(body), what + " server share");
            expectDecodeErrorOnly(() -> Extensions.decodeKeyShareRetry(body), what + " retry group");
            expectDecodeErrorOnly(() -> Extensions.decodeCookie(body), what + " cookie");
            expectDecodeErrorOnly(() -> Extensions.decodePskKeyExchangeModes(body), what + " psk modes");
            expectDecodeErrorOnly(() -> HandshakeMessage.Extension.decodeList(new Reader(body), true), what + " list");
        }
    }

    @Test
    void sessionsSurviveMutatedFlights() throws Exception {
        Random random = new Random(SEED + 2);
        int failures = 0;
        for (int i = 0; i < 600; i++) {
            boolean mutateServer = random.nextBoolean();
            EncryptionLevel target = random.nextBoolean() ? EncryptionLevel.INITIAL : EncryptionLevel.HANDSHAKE;
            boolean[] done = {false};
            Handshakes.Tamper tamper = (fromServer, level, bytes) -> {
                if (done[0] || fromServer != mutateServer || level != target) return bytes;
                done[0] = true;
                return mutate(bytes, random);
            };
            TlsConfig.Builder client = HandshakeTest.client();
            if (random.nextBoolean()) client.groups(NamedGroup.SECP256R1, NamedGroup.X25519);
            Handshakes h = new Handshakes(TlsSession.client(client.build(), Handshakes.CLIENT_PARAMS),
                    TlsSession.server(HandshakeTest.server().groups(NamedGroup.X25519).build(), Handshakes.SERVER_PARAMS),
                    new Random(i), tamper);
            try {
                h.complete();
            } catch (QuicException e) {
                failures++;
                assertNotEquals(QuicException.CRYPTO_ERROR + TlsAlert.INTERNAL_ERROR, e.code(),
                        "iteration " + i + ": " + e.getMessage());
                boolean expected = TlsAlert.fromErrorCode(e.code()) >= 0
                        || e.code() == QuicException.PROTOCOL_VIOLATION
                        || e.code() == QuicException.CRYPTO_BUFFER_EXCEEDED;
                assertTrue(expected, "iteration " + i + ": code " + e.code());
            } catch (Throwable t) {
                fail("iteration " + i + " threw " + t, t);
            }
        }
        assertTrue(failures > 300, "most mutations are caught: " + failures);
    }
}
