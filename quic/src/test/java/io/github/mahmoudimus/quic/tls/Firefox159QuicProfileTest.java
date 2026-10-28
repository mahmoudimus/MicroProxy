package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Firefox 159's QUIC ClientHello against the four a real Firefox 159.0 sent over HTTP/3. */
class Firefox159QuicProfileTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    static ClientHello captured(int n) {
        String path = "/fingerprints/firefox-159-quic/quic-clienthello-" + n + ".bin";
        try (InputStream in = Firefox159QuicProfileTest.class.getResourceAsStream(path)) {
            byte[] m = in.readAllBytes();
            return ClientHello.decode(new Reader(java.util.Arrays.copyOfRange(m, 4, m.length)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ClientHello ours(byte[] transportParameters) {
        HelloContext context = new HelloContext("quic.test", List.of("h3"),
                Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32], 0x0017, new byte[65]),
                Grease.random(RANDOM), RANDOM, Map.of(ProfileExtensions.QUIC_TRANSPORT_PARAMETERS, transportParameters));
        return BrowserProfiles.firefox159Quic().clientHello(context);
    }

    @Test
    void eachExtensionIsFirefoxs() {
        for (int n = 0; n < 4; n++) {
            ClientHello firefox = captured(n);
            byte[] tp = Extension.find(firefox.extensions(), ProfileExtensions.QUIC_TRANSPORT_PARAMETERS);
            ClientHello ours = ours(tp);
            assertArrayEquals(firefox.cipherSuites(), ours.cipherSuites());
            assertEquals(0, ours.sessionId().length);
            assertEquals(new HashSet<>(firefox.extensions().stream().map(Extension::type).toList()),
                    new HashSet<>(ours.extensions().stream().map(Extension::type).toList()));
            for (Extension theirs : firefox.extensions()) {
                byte[] mine = Extension.find(ours.extensions(), theirs.type());
                if (theirs.type() == ExtensionType.KEY_SHARE || theirs.type() == ProfileExtensions.ENCRYPTED_CLIENT_HELLO) {
                    // random: the same length (the GREASE ECH's payload sized as NSS sizes it)
                    assertEquals(theirs.data().length, mine.length, "extension " + theirs.type());
                } else {
                    assertArrayEquals(theirs.data(), mine, "extension " + theirs.type());
                }
            }
        }
    }

    @Test
    void theExtensionsAreShuffledButTheTransportParametersAndEchStayLast() {
        byte[] tp = Extension.find(captured(0).extensions(), ProfileExtensions.QUIC_TRANSPORT_PARAMETERS);
        Set<List<Integer>> orders = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            List<Integer> types = ours(tp).extensions().stream().map(Extension::type).toList();
            assertEquals(List.of(ProfileExtensions.QUIC_TRANSPORT_PARAMETERS, ProfileExtensions.ENCRYPTED_CLIENT_HELLO),
                    types.subList(types.size() - 2, types.size()));
            orders.add(types);
        }
        assertTrue(orders.size() > 40, orders.size() + " orders in 50 hellos");
        // as the captures were: each its own order, the same last two
        for (int n = 0; n < 4; n++) {
            List<Integer> types = captured(n).extensions().stream().map(Extension::type).toList();
            assertEquals(List.of(57, 0xfe0d), types.subList(types.size() - 2, types.size()));
        }
    }
}
