package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertConnectionError;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Http3SettingsTest {

    @Test
    void defaults() {
        Http3Settings d = Http3Settings.DEFAULT;
        assertEquals(0, d.qpackMaxTableCapacity());
        assertEquals(Http3Settings.UNLIMITED, d.maxFieldSectionSize());
        assertEquals(0, d.qpackBlockedStreams());
        assertFalse(d.enableConnectProtocol());
        assertFalse(d.h3Datagram());
        assertTrue(d.values().isEmpty());
    }

    @Test
    void framesCarryTheChangedValuesThenTheExtensions() throws Http3Exception {
        Http3Settings s = Http3Settings.builder()
                .extension(0x1234, 5)
                .h3Datagram(true)
                .qpackBlockedStreams(100)
                .maxFieldSectionSize(16384)
                .qpackMaxTableCapacity(4096)
                .enableConnectProtocol(true)
                .grease(0, 77)
                .build();
        assertEquals(List.of(0x01L, 0x06L, 0x07L, 0x08L, 0x33L, 0x1234L, 0x21L), List.copyOf(s.values().keySet()));
        assertEquals(s, Http3Settings.fromFrame(s.toFrame()));
    }

    @Test
    void fromFrameValidatesAndKeepsUnknownSettings() throws Http3Exception {
        Map<Long, Long> v = new LinkedHashMap<>();
        v.put(0x21L, 1L);
        v.put(Http3Settings.MAX_FIELD_SECTION_SIZE, 100L);
        v.put(0xffffL, QuicVarInt.MAX_VALUE);
        Http3Settings s = Http3Settings.fromFrame(new Http3Frame.Settings(v));
        assertEquals(100, s.maxFieldSectionSize());
        assertEquals(Map.of(0x21L, 1L, 0xffffL, QuicVarInt.MAX_VALUE), s.extensions());

        for (long id : new long[] {0, 2, 3, 4, 5}) {
            assertConnectionError(Http3ErrorCode.H3_SETTINGS_ERROR, () -> Http3Settings.fromFrame(new Http3Frame.Settings(Map.of(id, 1L))));
        }
        assertConnectionError(Http3ErrorCode.H3_SETTINGS_ERROR,
                () -> Http3Settings.fromFrame(new Http3Frame.Settings(Map.of(Http3Settings.ENABLE_CONNECT_PROTOCOL, 5L))));
        assertConnectionError(Http3ErrorCode.H3_SETTINGS_ERROR,
                () -> Http3Settings.fromFrame(new Http3Frame.Settings(Map.of(Http3Settings.H3_DATAGRAM, 2L))));
    }

    @Test
    void constructorRejectsImpossibleValues() {
        assertThrows(IllegalArgumentException.class, () -> Http3Settings.builder().qpackMaxTableCapacity(-1).build());
        assertThrows(IllegalArgumentException.class, () -> Http3Settings.builder().qpackBlockedStreams(1L << 62).build());
        assertThrows(IllegalArgumentException.class, () -> Http3Settings.builder().maxFieldSectionSize(-2).build());
        assertThrows(IllegalArgumentException.class, () -> Http3Settings.builder().extension(Http3Settings.H3_DATAGRAM, 1).build());
        assertThrows(IllegalArgumentException.class, () -> Http3Settings.builder().extension(0x02, 1).build());
    }

    @Test
    void identifierClasses() {
        assertTrue(Http3Settings.isHttp2Reserved(0x04));
        assertFalse(Http3Settings.isHttp2Reserved(Http3Settings.QPACK_MAX_TABLE_CAPACITY));
        assertFalse(Http3Settings.isHttp2Reserved(Http3Settings.MAX_FIELD_SECTION_SIZE));
        assertTrue(Http3Settings.isDefined(Http3Settings.H3_DATAGRAM));
        assertFalse(Http3Settings.isDefined(0x21));
    }
}
