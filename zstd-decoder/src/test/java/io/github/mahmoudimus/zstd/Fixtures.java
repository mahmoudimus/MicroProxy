package io.github.mahmoudimus.zstd;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** The fixtures in src/test/resources/zstd, described by its MANIFEST. */
final class Fixtures {

    record Fixture(String name, int size, String sha256, String dictionary) {
        byte[] compressed() {
            return resource(name + ".zst");
        }

        ZstdDecompressor decompressor() {
            if (dictionary == null) return ZstdDecompressor.create();
            try {
                return ZstdDecompressor.builder().dictionary(ZstdDictionary.of(resource(dictionary))).build();
            } catch (ZstdException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private Fixtures() {}

    static List<Fixture> all() {
        List<Fixture> out = new ArrayList<>();
        for (String line : new String(resource("MANIFEST"), StandardCharsets.UTF_8).split("\n")) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] f = line.split(" ");
            out.add(new Fixture(f[0], Integer.parseInt(f[1]), f[2], f[3].equals("-") ? null : f[3]));
        }
        return out;
    }

    static Fixture named(String name) {
        return all().stream().filter(f -> f.name().equals(name)).findFirst().orElseThrow();
    }

    static byte[] resource(String name) {
        try (InputStream in = Fixtures.class.getResourceAsStream("/zstd/" + name)) {
            if (in == null) throw new IllegalArgumentException("no fixture " + name);
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
