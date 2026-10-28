package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/** HPKE against the base-mode test vectors of RFC 9180 appendix A.1.1 and A.2.1. */
class HpkeTest {

    private static final HexFormat HEX = HexFormat.of();

    /** One vector: the setup values, its encryptions and its exports. */
    record Vector(String name, Map<String, String> values, List<String[]> encryptions, List<String[]> exports) {
        byte[] get(String key) {
            String v = values.get(key);
            assertNotNull(v, name + " has no " + key);
            return HEX.parseHex(v);
        }

        @Override
        public String toString() {
            return name;
        }
    }

    static Stream<Vector> vectors() throws IOException {
        List<Vector> out = new ArrayList<>();
        try (InputStream in = HpkeTest.class.getResourceAsStream("/hpke/rfc9180-base.txt")) {
            assertNotNull(in, "hpke/rfc9180-base.txt");
            Vector current = null;
            for (String line : new String(in.readAllBytes(), StandardCharsets.US_ASCII).split("\n")) {
                if (line.isBlank() || line.startsWith("#")) continue;
                if (line.startsWith("[")) {
                    current = new Vector(line.substring(1, line.length() - 1), new LinkedHashMap<>(), new ArrayList<>(),
                            new ArrayList<>());
                    out.add(current);
                    continue;
                }
                int eq = line.indexOf('=');
                String key = line.substring(0, eq);
                String value = line.substring(eq + 1);
                switch (key) {
                    case "encryption" -> current.encryptions().add(value.split(" "));
                    case "export" -> current.exports().add(value.split(" "));
                    default -> current.values().put(key, value);
                }
            }
        }
        return out.stream();
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void derivesTheKeyPairsOfTheVector(Vector v) throws GeneralSecurityException {
        assertArrayEquals(v.get("skEm"), Hpke.deriveX25519PrivateKey(v.get("ikmE")));
        assertArrayEquals(v.get("skRm"), Hpke.deriveX25519PrivateKey(v.get("ikmR")));
        assertArrayEquals(v.get("pkEm"), Hpke.x25519PublicKey(v.get("skEm")));
        assertArrayEquals(v.get("pkRm"), Hpke.x25519PublicKey(v.get("skRm")));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void senderSealsTheVectorsCiphertexts(Vector v) throws GeneralSecurityException {
        assertEquals(0, Integer.parseInt(v.values().get("mode")));
        assertTrue(Hpke.supports(Integer.parseInt(v.values().get("kem_id")), Integer.parseInt(v.values().get("kdf_id")),
                Integer.parseInt(v.values().get("aead_id"))));
        Hpke.Aead aead = Hpke.Aead.forId(Integer.parseInt(v.values().get("aead_id")));
        Hpke.Sender sender = Hpke.setupBaseS(v.get("pkRm"), v.get("info"), aead, v.get("ikmE"));
        assertArrayEquals(v.get("enc"), sender.enc());
        assertArrayEquals(v.get("base_nonce"), sender.context().nonce());
        assertEquals(6, v.encryptions().size());
        for (String[] e : v.encryptions()) {
            sender.context().sequence(Long.parseLong(e[0]));
            assertArrayEquals(HEX.parseHex(e[3]), sender.context().nonce(), v + " nonce " + e[0]);
            assertArrayEquals(HEX.parseHex(e[4]), sender.context().seal(HEX.parseHex(e[2]), HEX.parseHex(e[1])),
                    v + " ciphertext " + e[0]);
            assertEquals(Long.parseLong(e[0]) + 1, sender.context().sequence());
        }
        assertEquals(3, v.exports().size());
        for (String[] x : v.exports()) {
            byte[] context = x[0].equals("-") ? new byte[0] : HEX.parseHex(x[0]);
            assertArrayEquals(HEX.parseHex(x[2]), sender.context().export(context, Integer.parseInt(x[1])));
        }
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void receiverOpensTheVectorsCiphertexts(Vector v) throws GeneralSecurityException {
        Hpke.Aead aead = Hpke.Aead.forId(Integer.parseInt(v.values().get("aead_id")));
        Hpke.Context receiver = Hpke.setupBaseR(v.get("enc"), v.get("skRm"), v.get("info"), aead);
        for (String[] e : v.encryptions()) {
            receiver.sequence(Long.parseLong(e[0]));
            assertArrayEquals(HEX.parseHex(e[1]), receiver.open(HEX.parseHex(e[2]), HEX.parseHex(e[4])));
        }
        byte[] ct = HEX.parseHex(v.encryptions().get(0)[4]);
        ct[0] ^= 1;
        receiver.sequence(0);
        byte[] tampered = ct;
        assertThrows(AEADBadTagException.class, () -> receiver.open(HEX.parseHex(v.encryptions().get(0)[2]), tampered));
    }

    /** AES-256-GCM has no X25519 vector in RFC 9180, so it is checked as a round trip. */
    @ParameterizedTest
    @EnumSource(Hpke.Aead.class)
    void sealedMessagesOpenInSequence(Hpke.Aead aead) throws GeneralSecurityException {
        SecureRandom random = new SecureRandom();
        byte[] skR = new byte[32];
        random.nextBytes(skR);
        byte[] info = "tls ech\0config".getBytes(StandardCharsets.US_ASCII);
        Hpke.Sender sender = Hpke.setupBaseS(Hpke.x25519PublicKey(skR), info, aead, random);
        Hpke.Context receiver = Hpke.setupBaseR(sender.enc(), skR, info, aead);
        for (int i = 0; i < 3; i++) {
            byte[] pt = ("message " + i).getBytes(StandardCharsets.US_ASCII);
            byte[] aad = new byte[] {(byte) i};
            byte[] ct = sender.context().seal(aad, pt);
            assertEquals(pt.length + Hpke.Aead.TAG_LENGTH, ct.length);
            assertArrayEquals(pt, receiver.open(aad, ct));
        }
        // another info gives another key
        Hpke.Context other = Hpke.setupBaseR(sender.enc(), skR, new byte[0], aead);
        byte[] ct = sender.context().seal(new byte[0], new byte[] {1});
        assertThrows(AEADBadTagException.class, () -> other.open(new byte[0], ct));
    }

    @ParameterizedTest
    @EnumSource(Hpke.Aead.class)
    void suiteIds(Hpke.Aead aead) {
        assertEquals(aead, Hpke.Aead.forId(aead.id()));
        assertTrue(Hpke.supports(0x0020, 0x0001, aead.id()));
        assertFalse(Hpke.supports(0x0010, 0x0001, aead.id()));
        assertFalse(Hpke.supports(0x0020, 0x0002, aead.id()));
    }

    @ParameterizedTest
    @EnumSource(Hpke.Aead.class)
    void aSmallOrderPublicKeyIsRefused(Hpke.Aead aead) {
        byte[] zero = new byte[32];
        assertThrows(GeneralSecurityException.class, () -> Hpke.setupBaseS(zero, new byte[0], aead, new SecureRandom()));
        assertThrows(GeneralSecurityException.class, () -> Hpke.setupBaseS(new byte[31], new byte[0], aead, new SecureRandom()));
    }
}
