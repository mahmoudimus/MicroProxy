package io.github.mahmoudimus.http2;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Random and mutated input to the frame reader and the HPACK decoder may only fail with an
 * {@link Http2Exception} or an {@link EOFException}: never another exception, a hang or an
 * allocation beyond the configured limits.
 */
class FuzzTest {

    private static final long TIME_LIMIT_NANOS = 60_000_000_000L;

    @Test
    void mutatedConnectionsFailCleanly() throws IOException {
        Random random = new Random(9113);
        List<byte[]> corpus = new ArrayList<>();
        for (int i = 0; i < 40; i++) corpus.add(connection(random));
        // -Dhttp2.fuzz.runs=N runs a longer campaign.
        int runs = Integer.getInteger("http2.fuzz.runs", 15_000);
        long deadline = System.nanoTime() + TIME_LIMIT_NANOS * Math.max(1, runs / 15_000);
        int failures = 0;
        for (int i = 0; i < runs; i++) {
            byte[] input = mutate(corpus.get(random.nextInt(corpus.size())), random);
            if (consume(input)) failures++;
            if (System.nanoTime() > deadline) fail("fuzzing is too slow");
        }
        assertTrue(failures > runs / 2, "most mutations should be detected, got " + failures);
        // The unmutated corpus reads cleanly.
        for (byte[] c : corpus) assertTrue(!consume(c), "corpus must be valid");
    }

    @Test
    void randomBytesFailCleanly() {
        Random random = new Random(7541);
        long deadline = System.nanoTime() + TIME_LIMIT_NANOS;
        for (int i = 0; i < 20_000; i++) {
            byte[] input = new byte[random.nextInt(200)];
            random.nextBytes(input);
            if (random.nextBoolean() && input.length >= 9) {
                // Plausible frame headers get further into the parsers.
                input[0] = 0;
                input[1] = 0;
                input[2] = (byte) random.nextInt(input.length - 8);
                input[3] = (byte) random.nextInt(12);
            }
            consume(input);
            decodeHpack(input);
            if (System.nanoTime() > deadline) fail("fuzzing is too slow");
        }
    }

    @Test
    void mutatedHpackBlocksFailCleanly() {
        Random random = new Random(1);
        HpackEncoder encoder = new HpackEncoder();
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 0; i < 50; i++) blocks.add(encoder.encode(randomFields(random)));
        for (int i = 0; i < 20_000; i++) {
            decodeHpack(mutate(blocks.get(random.nextInt(blocks.size())), random));
        }
    }

    /** Reads everything; true if the input was rejected. */
    private static boolean consume(byte[] input) {
        FrameReader reader = new FrameReader(new ByteArrayInputStream(input));
        reader.setMaxHeaderBlockSize(4096);
        reader.setMaxContinuationFrames(16);
        HpackDecoder hpack = new HpackDecoder();
        hpack.setMaxHeaderListSize(8192);
        hpack.setMaxStringLength(2048);
        boolean rejected = false;
        while (true) {
            try {
                Frame f = reader.readFrame();
                if (f == null) return rejected;
                switch (f) {
                    case Frame.Headers h -> {
                        List<HeaderField> fields = hpack.decode(h.streamId(), h.fieldBlock());
                        try {
                            Http2Headers.toRequest(h.streamId(), fields);
                        } catch (Http2Exception e) {
                            checkScope(e);
                        }
                        try {
                            Http2Headers.toResponse(h.streamId(), fields);
                        } catch (Http2Exception e) {
                            checkScope(e);
                        }
                    }
                    case Frame.PushPromise p -> hpack.decode(p.streamId(), p.fieldBlock());
                    case Frame.Settings s -> Http2Settings.DEFAULT.apply(s);
                    default -> {}
                }
            } catch (Http2Exception e) {
                checkScope(e);
                rejected = true;
                if (e.isConnectionError()) return true;
            } catch (EOFException e) {
                return true;
            } catch (Throwable t) {
                throw new AssertionError("unexpected " + t + " for input " + TestBytes.hex(input), t);
            }
        }
    }

    private static void decodeHpack(byte[] block) {
        HpackDecoder d = new HpackDecoder();
        d.setMaxHeaderListSize(4096);
        d.setMaxStringLength(1024);
        try {
            d.decode(1, block);
            d.decode(1, block); // again, against whatever the first pass left in the table
        } catch (Http2Exception e) {
            checkScope(e);
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for block " + TestBytes.hex(block), t);
        }
    }

    private static void checkScope(Http2Exception e) {
        if (e.isConnectionError() == (e.streamId() != 0)) throw new AssertionError("inconsistent scope: " + e.getMessage());
    }

    /** A plausible connection's worth of frames. */
    private static byte[] connection(Random random) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter w = new FrameWriter(out);
        HpackEncoder hpack = new HpackEncoder();
        w.writeSettings(Http2Settings.builder().enablePush(false).maxConcurrentStreams(100).build());
        w.writeSettingsAck();
        int stream = 1;
        for (int i = 0, n = 3 + random.nextInt(8); i < n; i++) {
            switch (random.nextInt(8)) {
                case 0, 1, 2 -> {
                    byte[] block = hpack.encode(request(random));
                    if (random.nextBoolean() && block.length > 4) {
                        int cut = 1 + random.nextInt(block.length - 1);
                        w.writeFrame(new Frame.Headers(stream, Arrays.copyOf(block, cut), false, false,
                                random.nextBoolean() ? new Frame.PrioritySpec(0, false, 16) : null, random.nextInt(3) * 7));
                        w.writeFrame(new Frame.Continuation(stream, Arrays.copyOfRange(block, cut, block.length), true));
                    } else {
                        w.writeHeaders(stream, block, false);
                    }
                    byte[] data = new byte[random.nextInt(300)];
                    random.nextBytes(data);
                    w.writeFrame(new Frame.Data(stream, data, true, random.nextInt(4) * 5));
                    stream += 2;
                }
                case 3 -> w.writePing(random.nextBoolean(), random.nextLong());
                case 4 -> w.writeWindowUpdate(random.nextInt(4), 1 + random.nextInt(100_000));
                case 5 -> w.writeRstStream(1 + random.nextInt(9), ErrorCode.CANCEL);
                case 6 -> w.writeFrame(new Frame.Priority(1 + random.nextInt(9), new Frame.PrioritySpec(0, false, 16)));
                default -> w.writePushPromise(1, 2, hpack.encode(request(random)));
            }
        }
        w.writeGoAway(stream, ErrorCode.NO_ERROR, "bye".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    private static List<HeaderField> request(Random random) {
        List<HeaderField> fields = new ArrayList<>(Http2Headers.fromHttp1Request("GET", "https", "example.com", "/p/" + random.nextInt(50),
                List.of(Map.entry("accept", "*/*"), Map.entry("cookie", "a=" + random.nextInt(9) + "; b=2"))));
        fields.addAll(randomFields(random));
        return fields;
    }

    private static List<HeaderField> randomFields(Random random) {
        List<HeaderField> fields = new ArrayList<>();
        for (int i = random.nextInt(6); i > 0; i--) {
            char[] v = new char[random.nextInt(60)];
            for (int j = 0; j < v.length; j++) v[j] = (char) ('a' + random.nextInt(26));
            fields.add(new HeaderField("x-f" + random.nextInt(10), new String(v), random.nextInt(8) == 0));
        }
        return fields;
    }

    private static byte[] mutate(byte[] original, Random random) {
        byte[] m = original.clone();
        int count = 1 + random.nextInt(4);
        for (int k = 0; k < count && m.length > 0; k++) {
            switch (random.nextInt(6)) {
                case 0 -> m[random.nextInt(m.length)] ^= (byte) (1 << random.nextInt(8));
                case 1 -> m[random.nextInt(m.length)] = (byte) random.nextInt(256);
                case 2 -> m = Arrays.copyOf(m, random.nextInt(m.length));
                case 3 -> {
                    // Duplicate or drop a slice.
                    int a = random.nextInt(m.length);
                    int b = a + random.nextInt(Math.min(64, m.length - a) + 1);
                    byte[] slice = Arrays.copyOfRange(m, a, b);
                    m = random.nextBoolean()
                            ? TestBytes.concat(Arrays.copyOf(m, b), slice, Arrays.copyOfRange(m, b, m.length))
                            : TestBytes.concat(Arrays.copyOf(m, a), Arrays.copyOfRange(m, b, m.length));
                }
                case 4 -> m[random.nextInt(Math.min(m.length, 48))] = (byte) random.nextInt(256); // headers live early
                default -> m[random.nextInt(m.length)] = (byte) (random.nextBoolean() ? 0xff : 0x00);
            }
        }
        return m;
    }
}
