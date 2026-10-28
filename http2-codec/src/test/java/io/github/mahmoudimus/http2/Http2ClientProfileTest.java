package io.github.mahmoudimus.http2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Http2ClientProfileTest {

    @Test
    void chromesAkamaiFingerprint() {
        assertEquals("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", Http2ClientProfile.chrome156().akamai());
    }

    @Test
    void localSettingsAreTheAdvertisedOnes() {
        Http2Settings s = Http2ClientProfile.chrome156().localSettings();
        assertEquals(65_536, s.headerTableSize());
        assertEquals(6_291_456, s.initialWindowSize());
        assertEquals(262_144, s.maxHeaderListSize());
        assertEquals(false, s.enablePush());
    }

    @Test
    void pseudoHeadersAreReorderedAndTheRestKept() {
        List<HeaderField> fields = List.of(new HeaderField(":method", "GET"), new HeaderField(":scheme", "https"),
                new HeaderField(":authority", "a.test"), new HeaderField(":path", "/"),
                new HeaderField("user-agent", "x"), new HeaderField("accept", "*/*"));
        assertEquals(List.of(":method", ":authority", ":scheme", ":path", "user-agent", "accept"),
                Http2ClientProfile.chrome156().order(fields).stream().map(HeaderField::name).toList());
    }

    @Test
    void aConnectHasNoSchemeOrPathToPlace() {
        List<HeaderField> fields = List.of(new HeaderField(":method", "CONNECT"), new HeaderField(":authority", "a.test:443"));
        assertEquals(List.of(":method", ":authority"),
                Http2ClientProfile.chrome156().order(fields).stream().map(HeaderField::name).toList());
    }

    @Test
    void headersWithPriorityAreWrittenAsChromesAre() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameWriter writer = new FrameWriter(out);
        writer.writeHeaders(1, new byte[] {(byte) 0x82}, true, new Frame.PrioritySpec(0, true, 256));
        writer.flush();
        // Chrome 156's first HEADERS: flags END_STREAM | END_HEADERS | PRIORITY (37), exclusive
        // dependency on 0, weight 256 (255 on the wire), then the block
        assertArrayEquals(new byte[] {0, 0, 6, 1, 37, 0, 0, 0, 1, (byte) 0x80, 0, 0, 0, (byte) 255, (byte) 0x82},
                out.toByteArray());
        Frame frame = new FrameReader(new ByteArrayInputStream(out.toByteArray())).readFrame();
        Frame.Headers headers = assertInstanceOf(Frame.Headers.class, frame);
        assertEquals(new Frame.PrioritySpec(0, true, 256), headers.priority());
    }

    @Test
    void aProfileMustNameEachPseudoHeader() {
        assertThrows(IllegalArgumentException.class,
                () -> new Http2ClientProfile("bad", Map.of(), 0, null, List.of(":method", ":path")));
    }
}
