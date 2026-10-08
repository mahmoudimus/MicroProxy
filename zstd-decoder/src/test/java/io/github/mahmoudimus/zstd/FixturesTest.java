package io.github.mahmoudimus.zstd;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Decodes output of the reference encoder; see src/test/fixtures/generate.py for what each covers. */
class FixturesTest {

    static List<Fixtures.Fixture> fixtures() {
        return Fixtures.all();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fixtures")
    void decodesInOneCall(Fixtures.Fixture f) throws IOException {
        byte[] out = f.decompressor().decompress(f.compressed());
        assertEquals(f.size(), out.length);
        assertEquals(f.sha256(), Fixtures.sha256(out));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fixtures")
    void decodesAsAStreamFromTrickleInput(Fixtures.Fixture f) throws IOException {
        Random random = new Random(f.name().hashCode());
        // The source hands out a few bytes at a time and the reader asks for odd amounts.
        ByteArrayInputStream source = new ByteArrayInputStream(f.compressed());
        InputStream trickle = new InputStream() {
            @Override
            public int read() {
                return source.read();
            }

            @Override
            public int read(byte[] b, int off, int len) {
                return source.read(b, off, Math.min(len, 1 + random.nextInt(7)));
            }
        };
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZstdInputStream in = f.decompressor().inputStream(trickle)) {
            byte[] buf = new byte[1 + random.nextInt(5000)];
            int n;
            while ((n = in.read(buf, 0, 1 + random.nextInt(buf.length))) > 0) {
                out.write(buf, 0, n);
            }
        }
        assertEquals(f.sha256(), Fixtures.sha256(out.toByteArray()));
    }
}
