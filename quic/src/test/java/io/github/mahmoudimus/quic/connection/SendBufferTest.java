/*
 * Ported from quinn-proto src/connection/send_buffer.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class SendBufferTest {

    private static ByteBuffer b(String s) {
        return ByteBuffer.wrap(s.getBytes(StandardCharsets.US_ASCII));
    }

    private static SendBuffer.Transmit t(long start, long end, boolean encodeLength) {
        return new SendBuffer.Transmit(start, end, encodeLength);
    }

    private static String get(SendBuffer buf, long start, long end) {
        ByteBuffer v = buf.get(start, end);
        byte[] out = new byte[v.remaining()];
        v.get(out);
        return new String(out, StandardCharsets.US_ASCII);
    }

    @Test
    void fragmentWithLength() {
        SendBuffer buf = new SendBuffer();
        String msg = "Hello, world!";
        buf.write(b(msg));
        // offset 0 needs no Offset field: 19 bytes left, too few for 13 bytes, so 11 with a length
        assertEquals(t(0, 11, true), buf.pollTransmit(19));
        assertEquals(t(11, msg.length(), true), buf.pollTransmit(msg.length() + 16 - 11));
        assertEquals(t(msg.length(), msg.length(), true), buf.pollTransmit(58));
    }

    @Test
    void fragmentWithoutLength() {
        SendBuffer buf = new SendBuffer();
        String msg = "Hello, world with some extra data!";
        buf.write(b(msg));
        assertEquals(t(0, 19, false), buf.pollTransmit(19));
        assertEquals(t(19, msg.length(), false), buf.pollTransmit(msg.length() - 19 + 1));
        assertEquals(t(msg.length(), msg.length(), true), buf.pollTransmit(58));
    }

    @Test
    void reservesEncodedOffset() {
        SendBuffer buf = new SendBuffer();
        // Pretend there is more than 1 GiB of data in the buffer
        ByteBuffer chunk = ByteBuffer.allocate(1024 * 1024);
        for (int i = 0; i < 1025; i++) {
            buf.write(chunk);
        }
        long size1 = 64;
        long size2 = 16 * 1024;
        long size3 = 1024 * 1024 * 1024;

        // Offset 0 requires no space
        assertEquals(t(0, 16, false), buf.pollTransmit(16));
        buf.retransmit(0, 16);
        assertEquals(t(0, 16, false), buf.pollTransmit(16));
        long transmitted = 16;

        // Offset 16 requires 1 byte
        assertEquals(t(transmitted, size1, false), buf.pollTransmit((int) (size1 - transmitted + 1)));
        buf.retransmit(transmitted, size1);
        assertEquals(t(transmitted, size1, false), buf.pollTransmit((int) (size1 - transmitted + 1)));
        transmitted = size1;

        // Offset 64 requires 2 bytes
        assertEquals(t(transmitted, size2, false), buf.pollTransmit((int) (size2 - transmitted + 2)));
        buf.retransmit(transmitted, size2);
        assertEquals(t(transmitted, size2, false), buf.pollTransmit((int) (size2 - transmitted + 2)));
        transmitted = size2;

        // Offset 16384 requires 4 bytes
        assertEquals(t(transmitted, size3, false), buf.pollTransmit((int) (size3 - transmitted + 4)));
        buf.retransmit(transmitted, size3);
        assertEquals(t(transmitted, size3, false), buf.pollTransmit((int) (size3 - transmitted + 4)));
        transmitted = size3;

        // Offset 1 GiB requires 8 bytes
        int len = chunk.remaining();
        assertEquals(t(transmitted, transmitted + len, false), buf.pollTransmit(len + 8));
        buf.retransmit(transmitted, transmitted + len);
        assertEquals(t(transmitted, transmitted + len, false), buf.pollTransmit(len + 8));
    }

    @Test
    void multipleSegments() {
        SendBuffer buf = new SendBuffer();
        String msg = "Hello, world!";
        long msgLen = msg.length();
        for (String seg : new String[] {"He", "llo,", " w", "o", "rld!"}) {
            buf.write(b(seg));
        }
        assertEquals(msg, new String(buf.unackedBytes(), StandardCharsets.US_ASCII));

        assertEquals(t(0, 8, true), buf.pollTransmit(16));
        assertEquals("He", get(buf, 0, 5));
        assertEquals("llo,", get(buf, 2, 8));
        assertEquals(" w", get(buf, 6, 8));

        assertEquals(t(8, msgLen, true), buf.pollTransmit(16));
        assertEquals("o", get(buf, 8, msgLen));
        assertEquals("rld!", get(buf, 9, msgLen));

        assertEquals(t(msgLen, msgLen, true), buf.pollTransmit(42));

        // Now drain the segments
        buf.ack(0, 1);
        assertEquals(msg.substring(1), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        buf.ack(0, 3);
        assertEquals(msg.substring(3), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        buf.ack(3, 5);
        assertEquals(msg.substring(5), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        buf.ack(7, 9);
        assertEquals(msg.substring(5), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        buf.ack(4, 7);
        assertEquals(msg.substring(9), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        buf.ack(0, msgLen);
        assertEquals(0, buf.unackedBytes().length);
        assertTrue(buf.isFullyAcked());
    }

    @Test
    void retransmit() {
        SendBuffer buf = new SendBuffer();
        String msg = "Hello, world with extra data!";
        buf.write(b(msg));
        // Transmit two frames
        assertEquals(t(0, 16, false), buf.pollTransmit(16));
        assertEquals(t(16, 23, true), buf.pollTransmit(16));
        // Lose the first, but not the second
        buf.retransmit(0, 16);
        // Only the lost frame is retransmitted, then fresh data continues
        assertEquals(t(0, 16, false), buf.pollTransmit(16));
        assertEquals(t(23, msg.length(), true), buf.pollTransmit(16));
        // Lose the second frame
        buf.retransmit(16, 23);
        assertEquals(t(16, 23, true), buf.pollTransmit(16));
    }

    @Test
    void ack() {
        SendBuffer buf = new SendBuffer();
        String msg = "Hello, world!";
        buf.write(b(msg));
        assertEquals(t(0, 8, true), buf.pollTransmit(16));
        buf.ack(0, 8);
        assertEquals(msg.substring(8), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
    }

    @Test
    void reorderedAck() {
        SendBuffer buf = new SendBuffer();
        String msg = "Hello, world with extra data!";
        buf.write(b(msg));
        assertEquals(t(0, 16, false), buf.pollTransmit(16));
        assertEquals(t(16, 23, true), buf.pollTransmit(16));
        buf.ack(16, 23);
        assertEquals(msg, new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        buf.ack(0, 16);
        assertEquals(msg.substring(23), new String(buf.unackedBytes(), StandardCharsets.US_ASCII));
        assertTrue(buf.acksEmpty());
    }

    @Test
    void discardKeepsFinalOffset() {
        SendBuffer buf = new SendBuffer();
        buf.write(b("abcdef"));
        buf.pollTransmit(16);
        buf.discard();
        assertEquals(6, buf.offset());
        assertTrue(buf.isFullyAcked());
        assertFalse(buf.hasUnsentData());
        assertEquals(0, buf.buffered());
    }

    @Test
    void partialAckRetainsAllocationUntilSegmentReleased() {
        SendBuffer buf = new SendBuffer();
        buf.write(ByteBuffer.wrap(new byte[24]));
        buf.pollTransmit(40);
        buf.ack(0, 16);
        assertEquals(24, buf.buffered(), "a trimmed segment still holds its whole allocation");
        buf.ack(16, 24);
        assertEquals(0, buf.buffered());
    }

    @Test
    void cannotLoseUnsentData() {
        SendBuffer buf = new SendBuffer();
        buf.write(b("abc"));
        assertThrows(IllegalArgumentException.class, () -> buf.retransmit(0, 3));
    }

    @Test
    void writeDoesNotMoveTheCallersBuffer() {
        SendBuffer buf = new SendBuffer();
        byte[] data = "xyz".getBytes(StandardCharsets.US_ASCII);
        ByteBuffer bb = ByteBuffer.wrap(data);
        buf.write(bb);
        assertEquals(0, bb.position());
        assertArrayEquals(data, Arrays.copyOf(buf.unackedBytes(), 3));
    }
}
