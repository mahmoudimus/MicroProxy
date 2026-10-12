package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.quic.MessageFramer;

/**
 * {@link MessageAssembler} with each built-in framer: messages split across reads at every byte,
 * several in one read, the size limit, and bytes a framer cannot read.
 */
class MessageAssemblerTest {

    private static final List<String> PAYLOADS = List.of("", "a", "hello", "x".repeat(300), "y".repeat(70_000));

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** The payloads framed one after another, as a peer would send them. */
    private static byte[] stream(MessageFramer framer, List<String> payloads) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String p : payloads) out.writeBytes(framer.frame(utf8(p)));
        return out.toByteArray();
    }

    /** Feeds the stream in pieces of the given sizes, and returns the payloads of the messages. */
    private static List<String> feed(MessageAssembler a, MessageFramer framer, byte[] stream, int... pieces) {
        List<String> out = new ArrayList<>();
        int at = 0;
        int i = 0;
        while (at < stream.length) {
            int n = Math.min(pieces[i++ % pieces.length], stream.length - at);
            for (byte[] m : a.add(stream, at, n)) out.add(new String(framer.payload(m), StandardCharsets.UTF_8));
            at += n;
        }
        return out;
    }

    @ParameterizedTest
    @ValueSource(strings = {"u16", "u32", "varint", "lf", "crlf"})
    void splitAndCoalescedMessages(String name) {
        MessageFramer framer = MessageFramer.named(name);
        List<String> payloads = name.equals("u16") ? PAYLOADS.subList(0, 4) : PAYLOADS;
        byte[] stream = stream(framer, payloads);
        // All at once: coalesced.
        assertEquals(payloads, feed(new MessageAssembler(framer, 1 << 20), framer, stream, stream.length));
        // A byte at a time: every prefix and delimiter split.
        assertEquals(payloads, feed(new MessageAssembler(framer, 1 << 20), framer, stream, 1));
        // Odd pieces that cut messages anywhere, and join the end of one to the start of the next.
        assertEquals(payloads, feed(new MessageAssembler(framer, 1 << 20), framer, stream, 3, 7, 2, 1000, 5));
        Random random = new Random(name.hashCode());
        for (int round = 0; round < 20; round++) {
            MessageAssembler a = new MessageAssembler(framer, 1 << 20);
            List<String> out = new ArrayList<>();
            int at = 0;
            while (at < stream.length) {
                int n = Math.min(1 + random.nextInt(20_000), stream.length - at);
                for (byte[] m : a.add(stream, at, n)) out.add(new String(framer.payload(m), StandardCharsets.UTF_8));
                at += n;
            }
            assertEquals(payloads, out);
            assertEquals(0, a.kept());
        }
    }

    @Test
    void lengthPrefixesAndDelimiters() {
        assertArrayEquals(new byte[] {0, 2, 'h', 'i'}, MessageFramer.u16().frame(utf8("hi")));
        assertArrayEquals(new byte[] {0, 0, 0, 2, 'h', 'i'}, MessageFramer.u32().frame(utf8("hi")));
        assertArrayEquals(new byte[] {2, 'h', 'i'}, MessageFramer.varint().frame(utf8("hi")));
        assertArrayEquals(new byte[] {0x41, 0x2c}, java.util.Arrays.copyOf(MessageFramer.varint().frame(new byte[300]), 2));
        assertArrayEquals(new byte[] {(byte) 0x80, 0, 0x40, 0},
                java.util.Arrays.copyOf(MessageFramer.varint().frame(new byte[16384]), 4));
        assertArrayEquals(utf8("hi\n"), MessageFramer.lines().frame(utf8("hi")));
        assertArrayEquals(utf8("hi\r\n"), MessageFramer.crlfLines().frame(utf8("hi")));
        // A non-minimal varint prefix is read too: 0x4002 is 2.
        assertEquals(4, MessageFramer.varint().frameLength(new byte[] {0x40, 2, 'h', 'i'}, 0, 4));
        // The length is known from the prefix alone.
        assertEquals(1002, MessageFramer.u16().frameLength(new byte[] {3, (byte) 0xe8}, 0, 2));
        assertEquals(MessageFramer.NEED_MORE, MessageFramer.u32().frameLength(new byte[] {0, 0, 0}, 0, 3));
        // A line feed alone does not end a CRLF line; a carriage return stays in an LF line.
        assertEquals(MessageFramer.NEED_MORE, MessageFramer.crlfLines().frameLength(utf8("a\nb"), 0, 3));
        assertEquals("a\r", new String(MessageFramer.lines().payload(utf8("a\r\n")), StandardCharsets.UTF_8));
        try {
            MessageFramer.u16().frame(new byte[65536]);
            throw new AssertionError("framed a payload too long for two bytes");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("u16"));
        }
    }

    @Test
    void tooLarge() {
        MessageFramer u16 = MessageFramer.u16();
        // Known from the prefix: refused before the rest arrives.
        MessageAssembler a = new MessageAssembler(u16, 100);
        assertEquals(List.of(), a.add(new byte[] {0, (byte) 200}, 0, 2));
        assertNotNull(a.failure());
        assertTrue(a.failure().contains("202 bytes"), a.failure());
        assertEquals(List.of(), a.add(new byte[] {1}, 0, 1), "nothing more once failed");
        // Exactly the limit, prefix included, is allowed.
        MessageAssembler exact = new MessageAssembler(u16, 100);
        byte[] hundred = u16.frame(new byte[98]);
        assertEquals(1, exact.add(hundred, 0, hundred.length).size());
        assertNull(exact.failure());
        // A delimiter that does not come within the limit.
        MessageAssembler lines = new MessageAssembler(MessageFramer.lines(), 10);
        assertEquals(List.of(), lines.add(utf8("012345678"), 0, 9));
        assertNull(lines.failure());
        lines.add(utf8("9"), 0, 1);
        assertNotNull(lines.failure());
        // Messages before the one too large are still given.
        MessageAssembler before = new MessageAssembler(MessageFramer.lines(), 10);
        assertEquals(2, before.add(utf8("ok\nfine\nmuch too long"), 0, 21).size());
        assertNotNull(before.failure());
        // varint lengths beyond 2^31.
        MessageAssembler huge = new MessageAssembler(MessageFramer.varint(), 1 << 20);
        huge.add(new byte[] {(byte) 0xff, -1, -1, -1, -1, -1, -1, -1}, 0, 8);
        assertTrue(huge.failure().contains("more than"), huge.failure());
    }

    @Test
    void malformedPrefixes() {
        MessageFramer picky = (data, offset, length) -> {
            if (data[offset] != 'M') throw new IllegalArgumentException("not an M");
            return length >= 2 ? 2 + (data[offset + 1] & 0xff) : MessageFramer.NEED_MORE;
        };
        MessageAssembler a = new MessageAssembler(picky, 1000);
        assertEquals(1, a.add(new byte[] {'M', 1, 'x', 'Q'}, 0, 4).size());
        assertTrue(a.failure().contains("not an M"), a.failure());
        MessageAssembler zero = new MessageAssembler((data, offset, length) -> 0, 1000);
        zero.add(new byte[] {1}, 0, 1);
        assertTrue(zero.failure().contains("a length of 0"), zero.failure());
    }

    @Test
    void restIsWhatIsLeftWhenTheStreamEnds() {
        MessageAssembler a = new MessageAssembler(MessageFramer.u16(), 1000);
        assertEquals(1, a.add(new byte[] {0, 1, 'a', 0, 5, 'b'}, 0, 6).size());
        assertEquals(3, a.kept());
        assertArrayEquals(new byte[] {0, 5, 'b'}, a.rest());
        assertEquals(0, a.kept());
    }
}
