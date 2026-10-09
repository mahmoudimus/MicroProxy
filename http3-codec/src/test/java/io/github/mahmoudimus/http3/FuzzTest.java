package io.github.mahmoudimus.http3;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.mahmoudimus.http3.Http3StreamValidator.Role;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Random and mutated input to the frame reader, the stream validator and both QPACK directions
 * may only fail with an {@link Http3Exception}: never another exception, a hang or an allocation
 * beyond the configured limits. Fixed seeds; pass {@code -Dhttp3.fuzz.runs=N} for a longer run.
 */
class FuzzTest {

    private static final long TIME_LIMIT_NANOS = 60_000_000_000L;
    private static final int RUNS = Integer.getInteger("http3.fuzz.runs", 10_000);

    /** One endpoint's view of a request: the peer's encoder stream, then its request stream. */
    record Exchange(byte[] encoderStream, byte[] requestStream) {}

    @Test
    void mutatedRequestStreamsFailCleanly() throws IOException {
        Random random = new Random(9114);
        List<Exchange> corpus = new ArrayList<>();
        for (int i = 0; i < 40; i++) corpus.add(exchange(random));
        for (Exchange e : corpus) assertTrue(!consumeRequest(e.encoderStream(), e.requestStream()), "corpus must be valid");
        long deadline = System.nanoTime() + TIME_LIMIT_NANOS * Math.max(1, RUNS / 10_000);
        int rejected = 0;
        for (int i = 0; i < RUNS; i++) {
            Exchange e = corpus.get(random.nextInt(corpus.size()));
            boolean mutateEncoder = random.nextInt(3) == 0 && e.encoderStream().length > 0;
            byte[] enc = mutateEncoder ? mutate(e.encoderStream(), random) : e.encoderStream();
            byte[] req = mutateEncoder ? e.requestStream() : mutate(e.requestStream(), random);
            if (consumeRequest(enc, req)) rejected++;
            if (System.nanoTime() > deadline) fail("fuzzing is too slow");
        }
        assertTrue(rejected > RUNS / 3, "most mutations should be detected, got " + rejected);
    }

    @Test
    void mutatedControlStreamsFailCleanly() throws IOException {
        Random random = new Random(9204);
        List<byte[]> corpus = new ArrayList<>();
        for (int i = 0; i < 30; i++) corpus.add(controlStream(random));
        for (byte[] c : corpus) assertTrue(!consumeControl(c), "corpus must be valid");
        for (int i = 0; i < RUNS; i++) consumeControl(mutate(corpus.get(random.nextInt(corpus.size())), random));
    }

    @Test
    void randomBytesFailCleanly() {
        Random random = new Random(9000);
        long deadline = System.nanoTime() + TIME_LIMIT_NANOS;
        for (int i = 0; i < RUNS * 2; i++) {
            byte[] input = new byte[random.nextInt(120)];
            random.nextBytes(input);
            if (random.nextBoolean() && input.length >= 2) {
                // Plausible frame headers get further into the parsers.
                input[0] = (byte) new int[] {0, 1, 3, 4, 5, 7, 0x0d, 0x21}[random.nextInt(8)];
                input[1] = (byte) random.nextInt(Math.min(64, input.length - 1));
            }
            consumeRequest(new byte[0], input);
            consumeControl(input);
            decodeSection(input);
            encoderStream(input);
            decoderStream(input);
            parseBuffer(input);
            if (System.nanoTime() > deadline) fail("fuzzing is too slow");
        }
    }

    @Test
    void mutatedQpackInputFailsCleanly() throws Http3Exception {
        Random random = new Random(7541);
        QpackEncoder enc = new QpackEncoder(1024);
        enc.setPeerSettings(1024, 8);
        List<byte[]> sections = new ArrayList<>();
        ByteArrayOutputStream encoderStream = new ByteArrayOutputStream();
        for (int i = 0; i < 40; i++) {
            sections.add(enc.encode(4L * i, QpackTest.randomFields(random)));
            encoderStream.writeBytes(enc.encoderStreamBytes());
        }
        byte[] instructions = encoderStream.toByteArray();
        for (int i = 0; i < RUNS; i++) {
            byte[] section = mutate(sections.get(random.nextInt(sections.size())), random);
            QpackDecoder dec = new QpackDecoder(1024, 8);
            dec.setMaxFieldSectionSize(4096);
            try {
                dec.onEncoderStream(random.nextBoolean() ? instructions : mutate(instructions, random));
                if (dec.decode(0, section) == null) {
                    for (long ready : dec.onEncoderStream(new byte[0])) dec.resume(ready);
                }
                dec.cancelStream(0);
                dec.decoderStreamBytes();
            } catch (Http3Exception e) {
                checkScope(e);
            } catch (Throwable t) {
                throw new AssertionError("unexpected " + t + " for section " + TestBytes.hex(section), t);
            }
        }
    }

    // --- consumers -----------------------------------------------------------------------------

    /** Reads a request stream as a server would; true if the input was rejected. */
    private static boolean consumeRequest(byte[] encoderInput, byte[] requestInput) {
        long streamId = 0;
        Http3FrameReader reader = new Http3FrameReader(new ByteArrayInputStream(requestInput));
        reader.setMaxFramePayloadSize(4096);
        Http3StreamValidator validator = Http3StreamValidator.forRequestStream(streamId, Role.SERVER);
        QpackDecoder qpack = new QpackDecoder(1024, 4);
        qpack.setMaxFieldSectionSize(8192);
        boolean rejected = false;
        try {
            qpack.onEncoderStream(encoderInput);
            Http3Frame f;
            while ((f = reader.readFrame()) != null) {
                validator.onFrame(f);
                if (f instanceof Http3Frame.Headers h && !qpack.isBlocked(streamId)) {
                    try {
                        List<HeaderField> fields = qpack.decode(streamId, h.fieldSection());
                        if (fields != null) {
                            if (validator.trailersReceived()) {
                                Http3Headers.validateTrailers(streamId, fields);
                            } else {
                                Http3Headers.toRequest(streamId, fields);
                            }
                        }
                    } catch (Http3Exception e) {
                        checkScope(e);
                        if (e.isConnectionError()) throw e;
                        rejected = true;
                    }
                }
            }
            validator.onEndOfStream();
            qpack.decoderStreamBytes();
            return rejected || qpack.isBlocked(streamId);
        } catch (Http3Exception e) {
            checkScope(e);
            return true;
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for input " + TestBytes.hex(requestInput), t);
        }
    }

    /** Reads a control stream as a client would; true if the input was rejected. */
    private static boolean consumeControl(byte[] input) {
        Http3FrameReader reader = new Http3FrameReader(new ByteArrayInputStream(input));
        reader.setMaxFramePayloadSize(1024);
        Http3StreamValidator validator = Http3StreamValidator.forControlStream(Role.CLIENT);
        Http3StreamValidator.UnidirectionalStreams streams = new Http3StreamValidator.UnidirectionalStreams(Role.CLIENT);
        try {
            long type = reader.readStreamType();
            if (type < 0 || !streams.onStream(type) || type != Http3StreamType.CONTROL) return true;
            Http3Frame f;
            while ((f = reader.readFrame()) != null) {
                validator.onFrame(f);
                if (f instanceof Http3Frame.Settings s) {
                    Http3Settings settings = Http3Settings.fromFrame(s);
                    new QpackEncoder(4096).applyPeerSettings(settings);
                    Http3FrameWriter.encode(settings.toFrame());
                }
            }
            return false;
        } catch (Http3Exception e) {
            checkScope(e);
            return true;
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for input " + TestBytes.hex(input), t);
        }
    }

    private static void decodeSection(byte[] section) {
        QpackDecoder dec = new QpackDecoder(512, 2);
        dec.setMaxFieldSectionSize(2048);
        try {
            dec.decode(0, section);
            dec.decode(4, section);
        } catch (Http3Exception e) {
            checkScope(e);
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for section " + TestBytes.hex(section), t);
        }
    }

    private static void encoderStream(byte[] input) {
        QpackDecoder dec = new QpackDecoder(512, 2);
        try {
            int split = input.length / 2;
            dec.onEncoderStream(input, 0, split);
            dec.onEncoderStream(input, split, input.length - split);
            dec.decoderStreamBytes();
        } catch (Http3Exception e) {
            checkScope(e);
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for encoder stream " + TestBytes.hex(input), t);
        }
    }

    private static void decoderStream(byte[] input) {
        QpackEncoder enc = new QpackEncoder(512);
        enc.setPeerSettings(512, 2);
        try {
            enc.encode(0, List.of(new HeaderField("x-a", "1"), new HeaderField("x-b", "2")));
            enc.onDecoderStream(input);
        } catch (Http3Exception e) {
            checkScope(e);
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for decoder stream " + TestBytes.hex(input), t);
        }
    }

    private static void parseBuffer(byte[] input) {
        ByteBuffer buf = ByteBuffer.wrap(input);
        try {
            while (Http3FrameReader.parse(buf, 1024) != null) {
                // keep parsing
            }
        } catch (Http3Exception e) {
            checkScope(e);
        } catch (Throwable t) {
            throw new AssertionError("unexpected " + t + " for buffer " + TestBytes.hex(input), t);
        }
    }

    private static void checkScope(Http3Exception e) {
        if (e.isConnectionError() == (e.streamId() >= 0)) throw new AssertionError("inconsistent scope: " + e.getMessage());
    }

    // --- corpus --------------------------------------------------------------------------------

    /** A plausible request: dynamic QPACK, DATA, grease and trailers. */
    private static Exchange exchange(Random random) throws IOException {
        QpackEncoder qpack = new QpackEncoder(1024).setHuffman(random.nextBoolean());
        qpack.setPeerSettings(1024, 4);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(out);
        List<HeaderField> request = new ArrayList<>(List.of(
                new HeaderField(":method", random.nextBoolean() ? "GET" : "POST"), new HeaderField(":scheme", "https"),
                new HeaderField(":authority", "example.com"), new HeaderField(":path", "/p/" + random.nextInt(50))));
        for (HeaderField f : QpackTest.randomFields(random)) {
            if (!f.name().startsWith(":")) request.add(f);
        }
        if (random.nextBoolean()) w.writeFrame(new Http3Frame.Unknown(Http3FrameType.reserved(random.nextInt(100)), new byte[random.nextInt(8)]));
        w.writeHeaders(qpack.encode(0, sanitize(request)));
        for (int i = random.nextInt(4); i > 0; i--) {
            byte[] data = new byte[random.nextInt(300)];
            random.nextBytes(data);
            w.writeData(data);
            if (random.nextInt(4) == 0) w.writeFrame(new Http3Frame.Unknown(0x21, new byte[] {1}));
        }
        if (random.nextBoolean()) w.writeHeaders(qpack.encode(0, List.of(new HeaderField("x-trailer", "t" + random.nextInt(9)))));
        return new Exchange(qpack.encoderStreamBytes(), out.toByteArray());
    }

    /** Drops fields a valid request may not carry. */
    private static List<HeaderField> sanitize(List<HeaderField> fields) {
        List<HeaderField> out = new ArrayList<>();
        for (HeaderField f : fields) {
            String v = f.value();
            boolean ok = !Http3Headers.CONNECTION_SPECIFIC.contains(f.name()) && !f.name().equals("te") && !f.name().equals("host")
                    && !f.name().equals("content-length") && v.chars().noneMatch(c -> c == 0 || c == '\r' || c == '\n')
                    && (v.isEmpty() || (v.charAt(0) != ' ' && v.charAt(0) != '\t' && v.charAt(v.length() - 1) != ' '
                            && v.charAt(v.length() - 1) != '\t'));
            if (ok) out.add(f);
        }
        return out;
    }

    /** A plausible server control stream. */
    private static byte[] controlStream(Random random) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Http3FrameWriter w = new Http3FrameWriter(out);
        w.writeStreamType(Http3StreamType.CONTROL);
        w.writeSettings(Http3Settings.builder()
                .qpackMaxTableCapacity(random.nextInt(8192))
                .qpackBlockedStreams(random.nextInt(100))
                .maxFieldSectionSize(1 + random.nextInt(1 << 20))
                .enableConnectProtocol(random.nextBoolean())
                .h3Datagram(random.nextBoolean())
                .grease(random.nextInt(1000), random.nextInt(1000))
                .build());
        long goAway = 4L * random.nextInt(1000);
        for (int i = random.nextInt(5); i > 0; i--) {
            switch (random.nextInt(3)) {
                case 0 -> w.writeCancelPush(random.nextInt(100));
                case 1 -> {
                    w.writeGoAway(goAway);
                    goAway = Math.max(0, goAway - 4L * random.nextInt(10));
                }
                default -> w.writeFrame(new Http3Frame.Unknown(Http3FrameType.reserved(random.nextInt(50)), new byte[random.nextInt(10)]));
            }
        }
        return out.toByteArray();
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
                case 4 -> m[random.nextInt(Math.min(m.length, 24))] = (byte) random.nextInt(256); // prefixes live early
                default -> m[random.nextInt(m.length)] = (byte) (random.nextBoolean() ? 0xff : 0x00);
            }
        }
        return m;
    }
}
