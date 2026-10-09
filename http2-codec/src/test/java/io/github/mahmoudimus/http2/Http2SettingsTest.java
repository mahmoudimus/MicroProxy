package io.github.mahmoudimus.http2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Http2SettingsTest {

    @Test
    void defaultsAreTheProtocolsInitialValues() {
        Http2Settings d = Http2Settings.DEFAULT;
        assertEquals(4096, d.headerTableSize());
        assertTrue(d.enablePush());
        assertEquals(Http2Settings.UNLIMITED, d.maxConcurrentStreams());
        assertEquals(65_535, d.initialWindowSize());
        assertEquals(16_384, d.maxFrameSize());
        assertEquals(Http2Settings.UNLIMITED, d.maxHeaderListSize());
        assertTrue(d.changedValues().isEmpty());
        assertEquals(d, Http2Settings.builder().build());
    }

    @Test
    void builderAndChangedValues() {
        Http2Settings s = Http2Settings.builder()
                .enablePush(false)
                .maxConcurrentStreams(100)
                .initialWindowSize(1 << 20)
                .maxFrameSize(1 << 15)
                .maxHeaderListSize(65_536)
                .headerTableSize(8192)
                .build();
        Map<Integer, Long> expected = new LinkedHashMap<>();
        expected.put(Http2Settings.HEADER_TABLE_SIZE, 8192L);
        expected.put(Http2Settings.ENABLE_PUSH, 0L);
        expected.put(Http2Settings.MAX_CONCURRENT_STREAMS, 100L);
        expected.put(Http2Settings.INITIAL_WINDOW_SIZE, 1L << 20);
        expected.put(Http2Settings.MAX_FRAME_SIZE, 1L << 15);
        expected.put(Http2Settings.MAX_HEADER_LIST_SIZE, 65_536L);
        assertEquals(expected, s.changedValues());
        assertEquals(expected, s.toFrame().values());
        assertEquals(s, s.toBuilder().build());
    }

    @Test
    void invalidValuesAreRejectedByTheBuilder() {
        assertThrows(IllegalArgumentException.class, () -> Http2Settings.builder().maxFrameSize(16_383).build());
        assertThrows(IllegalArgumentException.class, () -> Http2Settings.builder().maxFrameSize(1 << 24).build());
        assertThrows(IllegalArgumentException.class, () -> Http2Settings.builder().initialWindowSize(-1).build());
        assertThrows(IllegalArgumentException.class, () -> Http2Settings.builder().headerTableSize(1L << 32).build());
        assertThrows(IllegalArgumentException.class, () -> Http2Settings.builder().maxConcurrentStreams(-5).build());
        assertThrows(IllegalArgumentException.class, () -> Http2Settings.builder().maxHeaderListSize(1L << 40).build());
    }

    @Test
    void applyingAPeersSettings() throws Http2Exception {
        Map<Integer, Long> values = new LinkedHashMap<>();
        values.put(Http2Settings.ENABLE_PUSH, 0L);
        values.put(Http2Settings.INITIAL_WINDOW_SIZE, (long) Integer.MAX_VALUE);
        values.put(Http2Settings.MAX_FRAME_SIZE, (long) Http2Settings.MAX_MAX_FRAME_SIZE);
        values.put(Http2Settings.HEADER_TABLE_SIZE, 0xffffffffL);
        values.put(0x99, 7L); // unknown, ignored
        Http2Settings s = Http2Settings.DEFAULT.apply(new Frame.Settings(false, values));
        assertFalse(s.enablePush());
        assertEquals(Integer.MAX_VALUE, s.initialWindowSize());
        assertEquals(Http2Settings.MAX_MAX_FRAME_SIZE, s.maxFrameSize());
        assertEquals(0xffffffffL, s.headerTableSize());
        assertSame(s, s.apply(Frame.Settings.acknowledgement()));
    }

    @Test
    void applyingInvalidSettingsIsAConnectionError() {
        assertSettingError(Http2Settings.ENABLE_PUSH, 2, ErrorCode.PROTOCOL_ERROR);
        assertSettingError(Http2Settings.INITIAL_WINDOW_SIZE, 1L << 31, ErrorCode.FLOW_CONTROL_ERROR);
        assertSettingError(Http2Settings.MAX_FRAME_SIZE, 16_383, ErrorCode.PROTOCOL_ERROR);
        assertSettingError(Http2Settings.MAX_FRAME_SIZE, 1 << 24, ErrorCode.PROTOCOL_ERROR);
    }

    private static void assertSettingError(int id, long value, ErrorCode code) {
        Http2Exception e = assertThrows(Http2Exception.class,
                () -> Http2Settings.DEFAULT.apply(new Frame.Settings(false, Map.of(id, value))));
        assertEquals(code, e.errorCode());
        assertTrue(e.isConnectionError());
    }

    @Test
    void extendedConnectSettingIsBooleanAndCannotBeDisabled() throws Exception {
        assertSettingError(8, 2, ErrorCode.PROTOCOL_ERROR);
        Http2Settings enabled = Http2Settings.DEFAULT.apply(new Frame.Settings(false, Map.of(8, 1L)));
        Http2Exception e = assertThrows(Http2Exception.class,
                () -> enabled.apply(new Frame.Settings(false, Map.of(8, 0L))));
        assertEquals(ErrorCode.PROTOCOL_ERROR, e.errorCode());
    }

    @Test
    void errorCodes() {
        for (ErrorCode c : ErrorCode.values()) assertSame(c, ErrorCode.forCode(c.code()));
        assertSame(ErrorCode.INTERNAL_ERROR, ErrorCode.forCode(0xe));
        assertSame(ErrorCode.INTERNAL_ERROR, ErrorCode.forCode(-1));
        assertEquals(0xd, ErrorCode.HTTP_1_1_REQUIRED.code());
    }
}
