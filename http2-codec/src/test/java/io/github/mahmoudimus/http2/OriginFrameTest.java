package io.github.mahmoudimus.http2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The ORIGIN frame (RFC 8336): its payload, and the reader delivering it on its own. */
class OriginFrameTest {

    private static byte[] ping() {
        return TestBytes.frame(FrameType.PING, 0, 0, new byte[8]);
    }

    @Test
    void theWireFormatIsLengthPrefixedAsciiOrigins() {
        byte[] payload = OriginFrame.encode(List.of("https://a.example", "https://b.example:8443"));
        assertArrayEquals(TestBytes.concat(new byte[] {0, 17}, "https://a.example".getBytes(),
                new byte[] {0, 22}, "https://b.example:8443".getBytes()), payload);
        assertEquals(List.of("https://a.example", "https://b.example:8443"), OriginFrame.decode(payload));
        assertEquals(List.of(), OriginFrame.decode(new byte[0]));
        // An empty entry is kept: what it means is the receiver's business.
        assertEquals(List.of(""), OriginFrame.decode(new byte[] {0, 0}));
    }

    @Test
    void malformedPayloadsAreRejected() {
        // A length that runs past the payload, a length cut in half, non-ASCII octets.
        assertThrows(IllegalArgumentException.class, () -> OriginFrame.decode(new byte[] {0, 5, 'a', 'b'}));
        assertThrows(IllegalArgumentException.class, () -> OriginFrame.decode(TestBytes.concat(
                OriginFrame.encode(List.of("https://a.example")), new byte[] {0})));
        assertThrows(IllegalArgumentException.class, () -> OriginFrame.decode(new byte[] {0, 1, (byte) 0xc3}));
        assertThrows(IllegalArgumentException.class, () -> OriginFrame.encode(List.of("https://é.example")));
        assertThrows(IllegalArgumentException.class, () -> OriginFrame.encode(List.of("x".repeat(70_000))));
        assertThrows(IllegalArgumentException.class,
                () -> OriginFrame.origins(new Frame.Unknown(0xd, 0, 0, new byte[0])));
    }

    @Test
    void onlyOriginFramesOnStreamZeroAreActedOn() {
        assertTrue(OriginFrame.isOrigin(OriginFrame.frame(List.of("https://a.example"))));
        // On another stream it must be ignored (RFC 8336 section 2.1).
        assertFalse(OriginFrame.isOrigin(new Frame.Unknown(FrameType.ORIGIN, 0, 1, new byte[0])));
        assertFalse(OriginFrame.isOrigin(new Frame.Unknown(0xd, 0, 0, new byte[0])));
        assertFalse(OriginFrame.isOrigin(new Frame.Ping(false, 1)));
        assertEquals("ORIGIN", FrameType.name(FrameType.ORIGIN));
    }

    @Test
    void theReaderDeliversOriginFramesAndStillSkipsOtherExtensions() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter writer = new FrameWriter(out);
        writer.writeFrame(new Frame.Unknown(0xfa, 0, 0, new byte[] {1, 2, 3}));
        writer.writeFrame(OriginFrame.frame(List.of("https://a.example", "https://b.example")));
        out.writeBytes(ping());
        byte[] wire = out.toByteArray();

        // By default ORIGIN is an extension frame like any other: skipped.
        FrameReader skipping = new FrameReader(new ByteArrayInputStream(wire));
        assertInstanceOf(Frame.Ping.class, skipping.readFrame());
        assertNull(skipping.readFrame());

        FrameReader reader = new FrameReader(new ByteArrayInputStream(wire));
        reader.setDeliverOriginFrames(true);
        Frame.Unknown origin = assertInstanceOf(Frame.Unknown.class, reader.readFrame());
        assertTrue(OriginFrame.isOrigin(origin));
        assertEquals(List.of("https://a.example", "https://b.example"), OriginFrame.origins(origin));
        assertInstanceOf(Frame.Ping.class, reader.readFrame());
        assertNull(reader.readFrame());
    }
}
