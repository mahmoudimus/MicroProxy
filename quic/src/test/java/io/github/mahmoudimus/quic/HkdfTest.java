package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class HkdfTest {

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    /** RFC 5869 appendix A.1. */
    @Test
    void rfc5869BasicCase() {
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Hkdf.SHA256.extract(salt, ikm);
        assertArrayEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);
        assertArrayEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                + "34007208d5b887185865"), Hkdf.SHA256.expand(prk, info, 42));
    }

    /** RFC 9001 appendix A.1: the client's Initial secrets for DCID 0x8394c8f03e515708. */
    @Test
    void rfc9001InitialSecrets() {
        byte[] salt = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        byte[] initial = Hkdf.SHA256.extract(salt, hex("8394c8f03e515708"));
        assertArrayEquals(hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"), initial);
        byte[] client = Hkdf.SHA256.expandLabel(initial, "client in", new byte[0], 32);
        assertArrayEquals(hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), client);
        assertArrayEquals(hex("1f369613dd76d5467730efcbe3b1a22d"),
                Hkdf.SHA256.expandLabel(client, "quic key", new byte[0], 16));
        assertArrayEquals(hex("fa044b2f42a3fd3b46fb255c"),
                Hkdf.SHA256.expandLabel(client, "quic iv", new byte[0], 12));
        assertArrayEquals(hex("9f50449e04a0e810283a1e9933adedd2"),
                Hkdf.SHA256.expandLabel(client, "quic hp", new byte[0], 16));
    }

    @Test
    void rejectsOverlongOutput() {
        assertThrows(IllegalArgumentException.class, () -> Hkdf.SHA256.expand(new byte[32], new byte[0], 255 * 32 + 1));
    }

    @Test
    void rejectsLabelsThatAsciiEncodingWouldSilentlyAlias() {
        for (String label : new String[] {"caf\u00e9", "caf?\uD800", "traffic upd\uD83D\uDD10"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Hkdf.SHA256.expandLabel(new byte[32], label, new byte[0], 16), label);
        }
    }
}
