package io.github.mahmoudimus.quic.tls;

import static io.github.mahmoudimus.quic.tls.ProfileExtensions.GREASE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class ClientHelloProfileTest {

    private static final ClientHelloProfile SMALL = new ClientHelloProfile("small",
            new int[] {GREASE, 0x1301},
            List.of(ProfileExtensions.greaseFirst(), ProfileExtensions.serverName(),
                    ProfileExtensions.extendedMasterSecret(), ProfileExtensions.alpn(),
                    ProfileExtensions.supportedVersions(0x0304), ProfileExtensions.greaseLast()),
            true, 32);

    private static HelloContext context(long seed) {
        SplittableRandom rng = new SplittableRandom(seed);
        return new HelloContext("localhost", List.of("h2", "http/1.1"), Map.of(), Grease.random(rng), rng);
    }

    @Test
    void fixedFieldsAreChromes() {
        HelloContext c = context(1);
        ClientHello hello = SMALL.clientHello(c);
        assertEquals(0x0303, hello.legacyVersion());
        assertEquals(32, hello.random().length);
        assertEquals(32, hello.sessionId().length);
        assertArrayEquals(new byte[] {0}, hello.compressionMethods());
        assertArrayEquals(new int[] {c.grease().cipher(), 0x1301}, hello.cipherSuites());
    }

    @Test
    void encodeIsTheHandshakeMessage() throws Exception {
        byte[] message = SMALL.encode(context(2));
        assertEquals(HandshakeType.CLIENT_HELLO, message[0]);
        int length = ((message[1] & 0xff) << 16) | ((message[2] & 0xff) << 8) | (message[3] & 0xff);
        assertEquals(message.length - 4, length);
        ClientHello decoded = ClientHello.decode(new Reader(java.util.Arrays.copyOfRange(message, 4, message.length)));
        assertEquals(6, decoded.extensions().size());
    }

    @Test
    void anExtensionWhoseBodyIsNullIsLeftOut() {
        SplittableRandom rng = new SplittableRandom(3);
        HelloContext noSni = new HelloContext(null, List.of(), Map.of(), Grease.random(rng), rng);
        List<Integer> types = SMALL.clientHello(noSni).extensions().stream().map(Extension::type).toList();
        assertEquals(4, types.size());
        assertTrue(!types.contains(ExtensionType.SERVER_NAME) && !types.contains(ExtensionType.ALPN));
    }

    @Test
    void shufflingKeepsGreaseFirstAndLastAndMovesTheRest() {
        Set<List<Integer>> orders = new HashSet<>();
        for (long seed = 0; seed < 200; seed++) {
            HelloContext c = context(seed);
            List<Integer> types = new ArrayList<>(SMALL.clientHello(c).extensions().stream().map(Extension::type).toList());
            assertEquals(c.grease().extension1(), types.getFirst());
            assertEquals(c.grease().extension2(), types.getLast());
            orders.add(types.subList(1, types.size() - 1));
        }
        // 4 movable extensions: 24 orders; 200 hellos see all of them
        assertEquals(24, orders.size());
    }

    @Test
    void preSharedKeyStaysLast() {
        ClientHelloProfile withPsk = new ClientHelloProfile("psk", new int[] {0x1301},
                List.of(ProfileExtensions.serverName(), ProfileExtensions.extendedMasterSecret(),
                        ProfileExtensions.alpn(), new ExtensionSpec(ExtensionType.PRE_SHARED_KEY, c -> new byte[0])),
                true, 0);
        for (long seed = 0; seed < 50; seed++) {
            assertEquals(ExtensionType.PRE_SHARED_KEY, withPsk.clientHello(context(seed)).extensions().getLast().type());
        }
    }

    @Test
    void unshuffledProfilesKeepTheirOrder() {
        ClientHelloProfile fixed = new ClientHelloProfile("fixed", new int[] {0x1301},
                List.of(ProfileExtensions.serverName(), ProfileExtensions.extendedMasterSecret(), ProfileExtensions.alpn()),
                false, 0);
        for (long seed = 0; seed < 20; seed++) {
            assertEquals(List.of(0, 23, 16),
                    fixed.clientHello(context(seed)).extensions().stream().map(Extension::type).toList());
        }
    }
}
