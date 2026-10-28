package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** The QUIC handshake with Chrome 156's QUIC ClientHello profile, against the module's TLS server. */
class QuicProfileHandshakeTest {

    private static final String HOST = "quic.test";

    private static TlsConfig.Builder chromeClient() {
        return TlsConfig.builder().serverName(HOST).alpnProtocols("h3").trustManager(TestCerts.CA.trustManager())
                .clientHelloProfile(BrowserProfiles.chrome156Quic())
                .applicationSettings(java.util.Map.of("h3", new byte[0]));
    }

    private static TlsConfig.Builder server() {
        return TlsConfig.builder().certificate(TestCerts.CA.issue(KeyType.P256, HOST)).alpnProtocols("h3");
    }

    private static ClientHello capture(byte[] message) throws Exception {
        return ClientHello.decode(new Reader(Arrays.copyOfRange(message, 4, message.length)));
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = QuicProfileHandshakeTest.class.getResourceAsStream("/fingerprints/chrome-156-quic/" + name)) {
            return in.readAllBytes();
        }
    }

    @Test
    void theHandshakeCompletesAndTheHelloIsChromes() throws Exception {
        AtomicReference<byte[]> sent = new AtomicReference<>();
        Handshakes h = Handshakes.run(chromeClient().build(), server().build(), new Random(3), (fromServer, level, bytes) -> {
            if (!fromServer && level == EncryptionLevel.INITIAL && sent.get() == null) sent.set(bytes);
            return bytes;
        });
        h.assertAgreement();
        assertEquals("h3", h.client.negotiatedAlpn());
        // the module's server prefers X25519, for which the hello carries a share
        assertEquals(NamedGroup.X25519, h.client.negotiatedGroup());

        ClientHello ours = capture(sent.get());
        ClientHello chrome = capture(fixture("quic-clienthello-0.bin"));
        assertArrayEquals(chrome.cipherSuites(), ours.cipherSuites());
        assertEquals(0, ours.sessionId().length);
        assertEquals(new HashSet<>(chrome.extensions().stream().map(Extension::type).toList()),
                new HashSet<>(ours.extensions().stream().map(Extension::type).toList()));
        assertTrue(ours.extensions().stream().noneMatch(e -> Grease.isGrease(e.type())), "no GREASE in QUIC");
        for (int type : List.of(10, 13, 43, 45, 27, ProfileExtensions.TRUST_ANCHORS, ProfileExtensions.APPLICATION_SETTINGS)) {
            assertArrayEquals(Extension.find(chrome.extensions(), type), Extension.find(ours.extensions(), type), "extension " + type);
        }
        assertArrayEquals(Handshakes.CLIENT_PARAMS, Extension.find(ours.extensions(), ProfileExtensions.QUIC_TRANSPORT_PARAMETERS));
        // a hybrid share and an X25519 one, as Chrome's
        byte[] shares = Extension.find(ours.extensions(), ExtensionType.KEY_SHARE);
        assertEquals(Extension.find(chrome.extensions(), ExtensionType.KEY_SHARE).length, shares.length);
    }

    @Test
    void aServerPreferringTheHybridGroupGetsIt() throws Exception {
        Handshakes h = Handshakes.run(chromeClient().build(),
                server().groups(NamedGroup.X25519_MLKEM768, NamedGroup.X25519).build());
        h.assertAgreement();
        assertEquals(NamedGroup.X25519_MLKEM768, h.client.negotiatedGroup());
    }

    @Test
    void aRetryForP256SendsOnlyThatShare() throws Exception {
        java.util.List<byte[]> hellos = new java.util.ArrayList<>();
        Handshakes h = Handshakes.run(chromeClient().build(), server().groups(NamedGroup.SECP256R1).build(), new Random(5),
                (fromServer, level, bytes) -> {
                    if (!fromServer && level == EncryptionLevel.INITIAL) hellos.add(bytes);
                    return bytes;
                });
        h.assertAgreement();
        assertEquals(NamedGroup.SECP256R1, h.client.negotiatedGroup());
        ClientHello second = capture(hellos.get(hellos.size() - 1));
        Reader r = new Reader(Extension.find(second.extensions(), ExtensionType.KEY_SHARE)).sub16("shares");
        int count = 0;
        while (r.hasRemaining()) {
            int group = r.u16("group");
            r.vector16(1, "share");
            count++;
            assertEquals(0x0017, group);
        }
        assertEquals(1, count);
    }
}
