package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The Firefox 159 profile's hellos against the ones a real Firefox 159.0 sent. */
class Firefox159ProfileTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static ClientHello ours(int pskLength) {
        HelloContext context = new HelloContext("localhost", List.of("h2", "http/1.1"),
                Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32], 0x0017, new byte[65]),
                Grease.random(RANDOM), RANDOM, Map.of(), pskLength);
        return BrowserProfiles.firefox159().clientHello(context);
    }

    private static List<Integer> types(List<Extension> extensions) {
        return extensions.stream().map(Extension::type).toList();
    }

    /** The groups of a key_share body, and the length of each share. */
    private static List<List<Integer>> shares(byte[] keyShare) {
        try {
            Reader list = new Reader(keyShare).sub16("shares");
            List<List<Integer>> out = new java.util.ArrayList<>();
            while (list.hasRemaining()) out.add(List.of(list.u16("group"), list.vector16(1, "share").length));
            return out;
        } catch (io.github.mahmoudimus.quic.QuicException e) {
            throw new AssertionError(e);
        }
    }

    /** Every extension but key_share and the GREASE ECH, whose bodies are random, has Firefox's exact body. */
    private static void assertSameBodies(ClientHello firefox, ClientHello ours) {
        assertEquals(types(firefox.extensions()), types(ours.extensions()));
        for (int i = 0; i < firefox.extensions().size(); i++) {
            Extension theirs = firefox.extensions().get(i);
            Extension mine = ours.extensions().get(i);
            switch (theirs.type()) {
                case ExtensionType.KEY_SHARE -> assertEquals(shares(theirs.data()), shares(mine.data()));
                case ProfileExtensions.ENCRYPTED_CLIENT_HELLO -> {
                    assertEquals(theirs.data().length, mine.data().length, "GREASE ECH length");
                    // outer, HKDF-SHA256; the AEAD is AES-128-GCM or ChaCha20-Poly1305 at random
                    assertEquals(0, mine.data()[0]);
                    assertEquals(1, ((mine.data()[1] & 0xff) << 8) | (mine.data()[2] & 0xff));
                    int aead = ((mine.data()[3] & 0xff) << 8) | (mine.data()[4] & 0xff);
                    assertTrue(aead == 1 || aead == 3, "aead " + aead);
                }
                default -> assertArrayEquals(theirs.data(), mine.data(), "extension " + theirs.type());
            }
        }
    }

    @Test
    void aNewConnectionsHelloIsFirefoxs() {
        ClientHello firefox = Firefox159Fixture.hello(Firefox159Fixture.FRESH);
        for (int i = 0; i < 20; i++) {
            ClientHello ours = ours(0);
            assertArrayEquals(firefox.cipherSuites(), ours.cipherSuites());
            assertEquals(firefox.sessionId().length, ours.sessionId().length);
            assertArrayEquals(firefox.compressionMethods(), ours.compressionMethods());
            assertSameBodies(firefox, ours);
            assertEquals(Firefox159Fixture.bytes(Firefox159Fixture.FRESH).length, ours.encode().length);
        }
    }

    @Test
    void aResumingHelloLeavesOutSessionTicketAndSizesItsGreaseEchWithThePsk() {
        ClientHello firefox = Firefox159Fixture.hello(Firefox159Fixture.RESUMED);
        byte[] psk = Extension.find(firefox.extensions(), ExtensionType.PRE_SHARED_KEY);
        ClientHello ours = ours(psk.length);
        // the client adds pre_shared_key after the profile's extensions
        List<Extension> withPsk = new java.util.ArrayList<>(ours.extensions());
        withPsk.add(new Extension(ExtensionType.PRE_SHARED_KEY, psk));
        assertSameBodies(firefox, ours.withExtensions(withPsk));
    }

    @Test
    void theGreaseEchAeadIsEitherOfNsssTwo() {
        Set<Integer> aeads = new HashSet<>();
        for (int i = 0; i < 64; i++) {
            byte[] ech = Extension.find(ours(0).extensions(), ProfileExtensions.ENCRYPTED_CLIENT_HELLO);
            aeads.add(((ech[3] & 0xff) << 8) | (ech[4] & 0xff));
        }
        assertEquals(Set.of(1, 3), aeads);
    }

    @Test
    void theGreaseEchPayloadFollowsTheServerNamesLength() {
        // NSS pads the name to 100 bytes, then the whole to 32: a longer name changes nothing until it passes 100
        HelloContext shortName = new HelloContext("a.test", List.of("h2"), Map.of(ProfileExtensions.X25519_MLKEM768,
                new byte[1216], 0x001d, new byte[32], 0x0017, new byte[65]), Grease.random(RANDOM), RANDOM);
        HelloContext longName = new HelloContext("a".repeat(120) + ".test", List.of("h2"), Map.of(ProfileExtensions.X25519_MLKEM768,
                new byte[1216], 0x001d, new byte[32], 0x0017, new byte[65]), Grease.random(RANDOM), RANDOM);
        int shortLength = payload(BrowserProfiles.firefox159().clientHello(shortName));
        int longLength = payload(BrowserProfiles.firefox159().clientHello(longName));
        assertEquals(0, (shortLength - 16) % 32);
        assertEquals(0, (longLength - 16) % 32);
        assertTrue(longLength > shortLength, shortLength + " " + longLength);
    }

    private static int payload(ClientHello hello) {
        try {
            Reader r = new Reader(Extension.find(hello.extensions(), ProfileExtensions.ENCRYPTED_CLIENT_HELLO));
            r.u8("type");
            r.u16("kdf");
            r.u16("aead");
            r.u8("config id");
            r.vector16(0, "enc");
            return r.vector16(1, "payload").length;
        } catch (io.github.mahmoudimus.quic.QuicException e) {
            throw new AssertionError(e);
        }
    }
}
