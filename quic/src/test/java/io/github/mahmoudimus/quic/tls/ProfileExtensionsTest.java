package io.github.mahmoudimus.quic.tls;

import static io.github.mahmoudimus.quic.tls.ProfileExtensions.GREASE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

class ProfileExtensionsTest {

    private static final HelloContext CONTEXT = new HelloContext("localhost", List.of("h2", "http/1.1"),
            Map.of(ProfileExtensions.X25519_MLKEM768, new byte[1216], 0x001d, new byte[32]),
            Chrome156Fixture.GREASE_0, new SplittableRandom(7));

    private static void assertMatchesCapture(ExtensionSpec spec) {
        int type = spec.resolvedType(CONTEXT.grease());
        assertArrayEquals(Chrome156Fixture.extension(0, type), spec.body().encode(CONTEXT),
                "extension " + type);
    }

    @Test
    void deterministicBodiesMatchChrome156ByteForByte() {
        assertMatchesCapture(ProfileExtensions.greaseFirst());
        assertMatchesCapture(ProfileExtensions.greaseLast());
        assertMatchesCapture(ProfileExtensions.serverName());
        assertMatchesCapture(ProfileExtensions.extendedMasterSecret());
        assertMatchesCapture(ProfileExtensions.renegotiationInfo());
        assertMatchesCapture(ProfileExtensions.supportedGroups(GREASE, 0x11ec, 0x001d, 0x0017, 0x0018));
        assertMatchesCapture(ProfileExtensions.ecPointFormats());
        assertMatchesCapture(ProfileExtensions.sessionTicket());
        assertMatchesCapture(ProfileExtensions.alpn());
        assertMatchesCapture(ProfileExtensions.statusRequest());
        assertMatchesCapture(ProfileExtensions.signatureAlgorithms(GREASE, 0x0904, 0x0905, 0x0906, 0x0403,
                0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601));
        assertMatchesCapture(ProfileExtensions.signedCertificateTimestamp());
        assertMatchesCapture(ProfileExtensions.pskKeyExchangeModes());
        assertMatchesCapture(ProfileExtensions.supportedVersions(GREASE, 0x0304, 0x0303));
        assertMatchesCapture(ProfileExtensions.compressCertificate(ProfileExtensions.BROTLI));
        assertMatchesCapture(ProfileExtensions.applicationSettings("h2"));
        assertMatchesCapture(ProfileExtensions.trustAnchors(BrowserProfiles.CHROME_156_TRUST_ANCHORS));
    }

    @Test
    void keyShareHasChromesLayout() throws Exception {
        byte[] ours = ProfileExtensions.keyShare(GREASE, 0x11ec, 0x001d).body().encode(CONTEXT);
        byte[] chrome = Chrome156Fixture.extension(0, 51);
        assertEquals(chrome.length, ours.length);
        // the GREASE share is one zero byte; the real shares differ, being keys
        assertArrayEquals(java.util.Arrays.copyOf(chrome, 7), java.util.Arrays.copyOf(ours, 7));
        Reader r = new Reader(ours);
        Reader list = r.sub16("client_shares");
        assertEquals(0x0a0a, list.u16("group"));
        assertEquals(1, list.vector16(0, "share").length);
        assertEquals(0x11ec, list.u16("group"));
        assertEquals(1216, list.vector16(0, "share").length);
        assertEquals(0x001d, list.u16("group"));
        assertEquals(32, list.vector16(0, "share").length);
    }

    @Test
    void keyShareWithoutAKeyIsAnError() {
        HelloContext none = new HelloContext("localhost", List.of(), Map.of(), Chrome156Fixture.GREASE_0,
                new SplittableRandom(1));
        assertThrows(IllegalArgumentException.class,
                () -> ProfileExtensions.keyShare(0x001d).body().encode(none));
    }

    @Test
    void greaseEchHasBoringSslsLayoutAndPayloadSizes() throws Exception {
        // Chrome's: outer, HKDF-SHA256, AES-128-GCM, a random config id, a 32-byte enc and a
        // payload of 144, 176, 208 or 240 bytes
        for (int n : new int[] {0, 1}) {
            byte[] chrome = Chrome156Fixture.extension(n, ProfileExtensions.ENCRYPTED_CLIENT_HELLO);
            assertArrayEquals(new byte[] {0, 0, 1, 0, 1}, java.util.Arrays.copyOf(chrome, 5));
        }
        assertEquals(218, Chrome156Fixture.extension(0, ProfileExtensions.ENCRYPTED_CLIENT_HELLO).length);
        assertEquals(282, Chrome156Fixture.extension(1, ProfileExtensions.ENCRYPTED_CLIENT_HELLO).length);
        java.util.Set<Integer> payloads = new java.util.HashSet<>();
        for (int i = 0; i < 200; i++) {
            byte[] ours = ProfileExtensions.greaseEch(144, 176, 208, 240).body().encode(CONTEXT);
            assertArrayEquals(new byte[] {0, 0, 1, 0, 1}, java.util.Arrays.copyOf(ours, 5));
            Reader r = new Reader(ours);
            r.u8("type");
            r.u16("kdf");
            r.u16("aead");
            r.u8("config_id");
            assertEquals(32, r.vector16(0, "enc").length);
            payloads.add(r.vector16(0, "payload").length);
            r.expectEnd("ech");
        }
        assertEquals(java.util.Set.of(144, 176, 208, 240), payloads);
    }

    @Test
    void absentServerNameOrAlpnLeavesTheExtensionOut() {
        HelloContext bare = new HelloContext(null, List.of(), Map.of(), Chrome156Fixture.GREASE_0,
                new SplittableRandom(1));
        assertNull(ProfileExtensions.serverName().body().encode(bare));
        assertNull(ProfileExtensions.alpn().body().encode(bare));
    }

    @Test
    void onlyGreaseAndPreSharedKeyKeepTheirPlace() {
        assertTrue(ProfileExtensions.greaseFirst().fixedPosition());
        assertTrue(ProfileExtensions.greaseLast().fixedPosition());
        assertTrue(new ExtensionSpec(41, c -> new byte[0]).fixedPosition());
        assertEquals(false, ProfileExtensions.serverName().fixedPosition());
    }
}
