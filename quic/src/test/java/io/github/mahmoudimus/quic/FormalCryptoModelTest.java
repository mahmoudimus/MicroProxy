package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class FormalCryptoModelTest {
    @Test
    void observesTheLengthDelimitedLabelEncodingUsedByExpandLabel() throws Exception {
        byte[] golden = HexFormat.of().parseHex("001009746c733133206b657900");
        assertArrayEquals(golden, Hkdf.labelInfo("key", new byte[0], 16));
        for (Hkdf hkdf : new Hkdf[] {Hkdf.SHA256, Hkdf.SHA384}) {
            byte[] secret = new byte[hkdf.hashLength()];
            assertArrayEquals(hkdf.expand(secret, golden, 16),
                    hkdf.expandLabel(secret, "key", new byte[0], 16));
        }
        assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo("x".repeat(250), new byte[0], 16));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo("key", new byte[256], 16));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo("key", new byte[0], 65536));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.labelInfo("key", new byte[0], -1));
        List<String> observations = new ArrayList<>();
        Random inputs = new Random(20261028);
        for (String label : new String[] {"", "key", "iv", "traffic upd", "quic key", "quicv2 key",
                "\0\u007f", "x".repeat(249)}) {
            for (int contextLength : new int[] {0, 1, 32, 255}) {
                byte[] context = new byte[contextLength];
                inputs.nextBytes(context);
                for (int length : new int[] {0, 16, 256, 65535}) {
                    byte[] encoded = Hkdf.labelInfo(label, context, length);
                    observations.add("{\"kind\":\"label\",\"length\":" + length + ",\"label\":"
                            + bytes(label.getBytes(StandardCharsets.US_ASCII)) + ",\"context\":" + bytes(context)
                            + ",\"encoded\":" + bytes(encoded) + "}");
                }
            }
        }
        export("crypto-label.jsonl", observations);
    }

    private static String bytes(byte[] bytes) {
        List<String> values = new ArrayList<>();
        for (byte value : bytes) values.add(Integer.toString(value & 0xff));
        return "[" + String.join(",", values) + "]";
    }

    private static void export(String filename, List<String> observations) throws Exception {
        String directory = System.getProperty("microproxy.formal.output");
        if (directory != null) {
            Path destination = Path.of(directory).resolve(filename);
            Files.createDirectories(destination.getParent());
            Files.write(destination, observations);
        }
    }
}
