package io.github.mahmoudimus.zstd;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Damaged input must be rejected with a {@link ZstdException} from an explicit check: never an
 * internal error, a hang or unbounded memory.
 */
class CorruptionTest {

    @Test
    void mutatedFixturesFailCleanly() {
        List<Fixtures.Fixture> fixtures = Fixtures.all().stream().filter(f -> f.dictionary() == null).toList();
        ZstdDecompressor decoder = ZstdDecompressor.builder().maxWindowSize(1 << 24).build();
        Random random = new Random(8878);
        long deadline = System.nanoTime() + 60_000_000_000L;
        int rejected = 0;
        for (int i = 0; i < 4000; i++) {
            Fixtures.Fixture f = fixtures.get(random.nextInt(fixtures.size()));
            byte[] data = mutate(f.compressed(), random);
            try {
                decoder.decompress(data, 32 << 20);
            } catch (ZstdException e) {
                assertFalse(e.getMessage().contains("internal"), () -> f + " mutation " + Arrays.toString(e.getStackTrace()));
                rejected++;
            }
            if (System.nanoTime() > deadline) fail("decoding mutated input is too slow");
        }
        assertTrue(rejected > 3000, "most mutations should be detected, got " + rejected);
    }

    private static byte[] mutate(byte[] original, Random random) {
        byte[] m = original.clone();
        int count = 1 + random.nextInt(4);
        for (int k = 0; k < count && m.length > 0; k++) {
            switch (random.nextInt(4)) {
                case 0 -> m[random.nextInt(m.length)] ^= (byte) (1 << random.nextInt(8));
                case 1 -> m[random.nextInt(m.length)] = (byte) random.nextInt(256);
                case 2 -> m = Arrays.copyOf(m, random.nextInt(m.length));
                default -> m[random.nextInt(Math.min(m.length, 32))] = (byte) random.nextInt(256);
            }
        }
        return m;
    }
}
