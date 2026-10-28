package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The ECH hellos made from the Chrome profile, opened and decoded as a client-facing server
 * would (RFC 9849 sections 5.1 and 7.1): the outer hello is the profile's for the public name, and
 * the inner one decompresses from it exactly.
 */
class EchClientTest {

    private static final String INNER = "secret.example";
    private static final String PUBLIC = "public.example";

    private final SecureRandom random = new SecureRandom();
    private final byte[] skR = new byte[32];
    private final EchConfig.Selected selected;

    EchClientTest() throws Exception {
        random.nextBytes(skR);
        byte[] config = EchConfigTest.config(EchConfig.VERSION, 0x33, Hpke.KEM_X25519_HKDF_SHA256,
                Hpke.x25519PublicKey(skR), new int[][] {{1, 1}}, 64, PUBLIC);
        selected = EchConfig.select(EchConfigTest.list(config));
    }

    private ClientHello profileHello() {
        ClientHelloProfile profile = BrowserProfiles.chrome156();
        Map<Integer, byte[]> keys = new LinkedHashMap<>();
        for (int code : profile.keyShareGroups()) keys.put(code, KeyExchange.generate(NamedGroup.forCode(code), random).publicKey());
        return profile.clientHello(new HelloContext(PUBLIC, List.of("h2", "http/1.1"), keys, Grease.random(random), random));
    }

    private static List<Integer> types(ClientHello h) {
        return h.extensions().stream().map(Extension::type).toList();
    }

    /** The server's view: the outer ECH extension's fields. */
    record OuterEch(int kdf, int aead, int configId, byte[] enc, byte[] payload) {
        static OuterEch of(ClientHello outer) throws QuicException {
            Reader r = new Reader(Extension.find(outer.extensions(), ProfileExtensions.ENCRYPTED_CLIENT_HELLO));
            assertEquals(0, r.u8("type"));
            OuterEch e = new OuterEch(r.u16("kdf"), r.u16("aead"), r.u8("config_id"), r.vector16(0, "enc"), r.vector16(1, "payload"));
            r.expectEnd("ech");
            return e;
        }
    }

    /** Decrypts and decodes the inner hello as RFC 9849 section 7.1 has a server do. */
    private static byte[] open(Hpke.Context context, ClientHello outer) throws Exception {
        OuterEch ech = OuterEch.of(outer);
        byte[] message = outer.encode();
        byte[] aadHello = outer.withExtensions(replaceEch(outer.extensions(), ech, new byte[ech.payload().length])).encode();
        byte[] encoded = context.open(Arrays.copyOfRange(aadHello, 4, aadHello.length), ech.payload());
        assertEquals(0, encoded.length % 32, "padded to a multiple of 32");
        Reader r = new Reader(encoded);
        ClientHello e = ClientHello.decode(r);
        for (byte b : r.rest()) assertEquals(0, b, "padding is zeros");
        assertEquals(0, e.sessionId().length);
        List<Extension> extensions = new ArrayList<>();
        int at = 0;
        for (Extension x : e.extensions()) {
            if (x.type() != EchClient.ECH_OUTER_EXTENSIONS) {
                extensions.add(x);
                continue;
            }
            Reader refs = new Reader(x.data()).sub8("ech_outer_extensions");
            while (refs.hasRemaining()) {
                int type = refs.u16("type");
                assertTrue(type != ProfileExtensions.ENCRYPTED_CLIENT_HELLO);
                while (outer.extensions().get(at).type() != type) at++; // in the outer hello's order
                extensions.add(outer.extensions().get(at++));
            }
        }
        assertNotNull(message);
        return new ClientHello(e.legacyVersion(), e.random(), outer.sessionId(), e.cipherSuites(), e.compressionMethods(),
                extensions).encode();
    }

    private static List<Extension> replaceEch(List<Extension> extensions, OuterEch ech, byte[] payload) {
        Writer w = new Writer();
        w.u8(0).u16(ech.kdf()).u16(ech.aead()).u8(ech.configId()).vector16(ech.enc()).vector16(payload);
        List<Extension> out = new ArrayList<>(extensions);
        for (int i = 0; i < out.size(); i++) {
            if (out.get(i).type() == ProfileExtensions.ENCRYPTED_CLIENT_HELLO) out.set(i, new Extension(out.get(i).type(), w.toByteArray()));
        }
        return out;
    }

    private Hpke.Context receiver(byte[] enc) throws GeneralSecurityException {
        byte[] raw = selected.config().raw();
        byte[] info = new byte[8 + raw.length];
        System.arraycopy("tls ech\0".getBytes(StandardCharsets.US_ASCII), 0, info, 0, 8);
        System.arraycopy(raw, 0, info, 8, raw.length);
        return Hpke.setupBaseR(enc, skR, info, selected.aead());
    }

    @Test
    void theOuterHelloIsTheProfilesWithTheRealEch() throws Exception {
        ClientHello template = profileHello();
        EchClient ech = new EchClient(selected, INNER, random);
        EchClient.Inner inner = ech.inner(template);
        ClientHello outer = ech.outer(template, inner, inner.hello().encode(), true);

        assertEquals(types(template), types(outer), "same extensions, same order");
        for (int i = 0; i < template.extensions().size(); i++) {
            Extension t = template.extensions().get(i);
            if (t.type() == ProfileExtensions.ENCRYPTED_CLIENT_HELLO) continue;
            assertArrayEquals(t.data(), outer.extensions().get(i).data(), ExtensionType.name(t.type()));
        }
        assertArrayEquals(template.random(), outer.random());
        assertArrayEquals(template.sessionId(), outer.sessionId());
        assertArrayEquals(template.cipherSuites(), outer.cipherSuites());
        assertArrayEquals(Extensions.encodeServerName(PUBLIC), Extension.find(outer.extensions(), ExtensionType.SERVER_NAME));

        OuterEch e = OuterEch.of(outer);
        assertEquals(1, e.kdf());
        assertEquals(1, e.aead());
        assertEquals(0x33, e.configId());
        assertEquals(32, e.enc().length);
        // like BoringSSL's GREASE ECH lengths: 32n + 16
        assertEquals(16, e.payload().length % 32);
    }

    @Test
    void theInnerHelloOffersTls13OnlyAndDecompressesExactly() throws Exception {
        ClientHello template = profileHello();
        EchClient ech = new EchClient(selected, INNER, random);
        EchClient.Inner inner = ech.inner(template);
        ClientHello h = inner.hello();
        byte[] innerMessage = h.encode();
        ClientHello outer = ech.outer(template, inner, innerMessage, true);

        assertArrayEquals(Extensions.encodeServerName(INNER), Extension.find(h.extensions(), ExtensionType.SERVER_NAME));
        assertArrayEquals(new byte[] {1}, Extension.find(h.extensions(), ProfileExtensions.ENCRYPTED_CLIENT_HELLO));
        for (int tls12Only : new int[] {23, 0xff01, 35, 11}) assertNull(Extension.find(h.extensions(), tls12Only));
        byte[] sv = Extension.find(h.extensions(), ExtensionType.SUPPORTED_VERSIONS);
        assertEquals(5, sv.length, "GREASE and TLS 1.3");
        assertTrue(Grease.isGrease(((sv[1] & 0xff) << 8) | (sv[2] & 0xff)));
        assertEquals(0x0304, ((sv[3] & 0xff) << 8) | (sv[4] & 0xff));
        for (int s : h.cipherSuites()) assertTrue(Grease.isGrease(s) || CipherSuite.forCode(s) != null);
        assertEquals(4, h.cipherSuites().length, "GREASE and the three TLS 1.3 suites");
        assertArrayEquals(Extension.find(template.extensions(), ExtensionType.KEY_SHARE),
                Extension.find(h.extensions(), ExtensionType.KEY_SHARE), "the outer hello's key shares");
        assertArrayEquals(template.sessionId(), h.sessionId());
        assertFalse(Arrays.equals(template.random(), h.random()));
        assertArrayEquals(ech.innerRandom(), h.random());

        OuterEch e = OuterEch.of(outer);
        assertArrayEquals(innerMessage, open(receiver(e.enc()), outer));
        // the encrypted form is compressed: much shorter than the inner hello with its ML-KEM share
        assertTrue(e.payload().length < innerMessage.length / 2, e.payload().length + " vs " + innerMessage.length);
    }

    @Test
    void theSecondHellosContinueTheHpkeContext() throws Exception {
        ClientHello template = profileHello();
        EchClient ech = new EchClient(selected, INNER, random);
        EchClient.Inner inner = ech.inner(template);
        ClientHello outer = ech.outer(template, inner, inner.hello().encode(), true);
        Hpke.Context server = receiver(OuterEch.of(outer).enc());
        open(server, outer);

        // a HelloRetryRequest for P-256 with a cookie: new key_share, cookie before the last GREASE
        KeyExchange p256 = KeyExchange.generate(NamedGroup.forCode(0x0017), random);
        List<Extension> extensions = new ArrayList<>(outer.extensions());
        for (int i = 0; i < extensions.size(); i++) {
            if (extensions.get(i).type() == ExtensionType.KEY_SHARE) {
                extensions.set(i, new Extension(ExtensionType.KEY_SHARE,
                        Extensions.encodeKeyShareClient(List.of(new Extensions.KeyShare(0x0017, p256.publicKey())))));
            }
        }
        extensions.add(extensions.size() - 1, new Extension(ExtensionType.COOKIE, Extensions.encodeCookie(new byte[] {9, 9})));
        ClientHello template2 = outer.withExtensions(extensions);
        EchClient.Inner inner2 = ech.inner(template2);
        byte[] inner2Message = inner2.hello().encode();
        ClientHello outer2 = ech.outer(template2, inner2, inner2Message, false);

        OuterEch e2 = OuterEch.of(outer2);
        assertEquals(0, e2.enc().length, "no enc in the second outer hello");
        assertEquals(OuterEch.of(outer).configId(), e2.configId());
        assertArrayEquals(inner.hello().random(), inner2.hello().random());
        assertArrayEquals(inner2Message, open(server, outer2));
        assertArrayEquals(Extension.find(outer2.extensions(), ExtensionType.KEY_SHARE),
                Extension.find(inner2.hello().extensions(), ExtensionType.KEY_SHARE));
        assertNotNull(Extension.find(inner2.hello().extensions(), ExtensionType.COOKIE));
    }

    @Test
    void paddingFollowsTheMaximumNameLength() throws Exception {
        ClientHello template = profileHello();
        EchClient longName = new EchClient(selected, "a-much-longer-secret-name.example", random);
        EchClient shortName = new EchClient(selected, INNER, random);
        EchClient.Inner a = longName.inner(template);
        EchClient.Inner b = shortName.inner(template);
        // both names are under the 64 the config allows, so both pad to the same length
        assertEquals(longName.encodeInner(a, a.hello().encode()).length, shortName.encodeInner(b, b.hello().encode()).length);
        EchClient noName = new EchClient(selected, null, random);
        EchClient.Inner c = noName.inner(template);
        assertNull(Extension.find(c.hello().extensions(), ExtensionType.SERVER_NAME));
        assertEquals(0, noName.encodeInner(c, c.hello().encode()).length % 32);
    }

    @Test
    void confirmationsDependOnTheInnerRandomAndTheTranscript() throws Exception {
        EchClient ech = new EchClient(selected, INNER, random);
        byte[] hash = new byte[32];
        byte[] a = ech.confirmation(CipherSuite.TLS_AES_128_GCM_SHA256, EchClient.ACCEPT_LABEL, hash);
        assertEquals(8, a.length);
        assertFalse(Arrays.equals(a, ech.confirmation(CipherSuite.TLS_AES_128_GCM_SHA256, EchClient.HRR_ACCEPT_LABEL, hash)));
        hash[0] = 1;
        assertFalse(Arrays.equals(a, ech.confirmation(CipherSuite.TLS_AES_128_GCM_SHA256, EchClient.ACCEPT_LABEL, hash)));
        assertFalse(Arrays.equals(a, new EchClient(selected, INNER, random)
                .confirmation(CipherSuite.TLS_AES_128_GCM_SHA256, EchClient.ACCEPT_LABEL, new byte[32])));

        byte[] serverHello = new byte[4 + 2 + 32 + 10];
        Arrays.fill(serverHello, (byte) 0x55);
        byte[] zeroed = EchClient.zeroConfirmation(serverHello);
        for (int i = 0; i < serverHello.length; i++) assertEquals(i >= 30 && i < 38 ? 0 : 0x55, zeroed[i] & 0xff, "byte " + i);
    }
}
