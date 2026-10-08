package io.github.mahmoudimus.zstd;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * Compresses random inputs with the {@code zstd} command (when it is installed) using random
 * settings, and checks that they decode to the original.
 */
class ReferenceEncoderTest {

    private static final String[] LEVELS = {"-1", "-3", "-6", "-12", "-19", "--fast=4", "--ultra -22"};

    static boolean zstdInstalled() {
        try {
            return new ProcessBuilder("zstd", "--version").redirectErrorStream(true).start().waitFor() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @Test
    void randomInputsAndSettings() throws Exception {
        assumeTrue(zstdInstalled(), "zstd is not installed");
        Random random = new Random(Long.getLong("zstd.seed", 9659));
        for (int i = 0; i < 60; i++) {
            byte[] input = input(random, random.nextInt(4) == 0 ? random.nextInt(2_000_000) : random.nextInt(300_000));
            List<String> command = new ArrayList<>(List.of("zstd", "-q", "-c"));
            command.addAll(List.of(LEVELS[random.nextInt(LEVELS.length)].split(" ")));
            if (random.nextBoolean()) command.add("--no-check");
            if (random.nextInt(4) == 0) command.add("--zstd=wlog=" + (10 + random.nextInt(14)));
            if (random.nextInt(5) == 0) command.add("--long=" + (20 + random.nextInt(5)));
            byte[] compressed = run(command, input);
            assertArrayEquals(input, ZstdDecompressor.create().decompress(compressed), String.join(" ", command));
        }
    }

    private static byte[] run(List<String> command, byte[] input) throws Exception {
        Process p = new ProcessBuilder(command).start();
        CompletableFuture<byte[]> out = CompletableFuture.supplyAsync(() -> {
            try {
                return p.getInputStream().readAllBytes();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        try (var stdin = p.getOutputStream()) {
            stdin.write(input);
        }
        byte[] result = out.get();
        if (p.waitFor() != 0) throw new IllegalStateException(command + " failed");
        return result;
    }

    /** A mix of text-like runs, random bytes, byte runs and copies of earlier data. */
    private static byte[] input(Random random, int size) {
        byte[] out = new byte[size];
        String[] words = {"zstd ", "frame ", "block ", "literal ", "match ", "offset ", "huffman\n", "window "};
        int n = 0;
        while (n < size) {
            int kind = random.nextInt(10);
            int len = Math.min(size - n, 1 + random.nextInt(kind < 5 ? 4000 : 20000));
            if (kind < 4) {
                for (int i = 0; i < len; ) {
                    byte[] w = words[random.nextInt(words.length)].getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                    for (int j = 0; j < w.length && i < len; j++, i++) out[n + i] = w[j];
                }
            } else if (kind < 6) {
                for (int i = 0; i < len; i++) out[n + i] = (byte) random.nextInt(256);
            } else if (kind < 8) {
                java.util.Arrays.fill(out, n, n + len, (byte) random.nextInt(256));
            } else if (n > 0) {
                int from = random.nextInt(n);
                for (int i = 0; i < len; i++) out[n + i] = out[from + (i % (n - from))];
            }
            n += len;
        }
        return out;
    }
}
