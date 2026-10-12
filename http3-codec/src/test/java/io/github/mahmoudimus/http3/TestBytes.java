package io.github.mahmoudimus.http3;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.RecordComponent;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.function.Executable;

/** Helpers for building raw frames and comparing frames. */
final class TestBytes {

    private TestBytes() {}

    static byte[] hex(String hex) {
        return HexFormat.of().parseHex(hex.replace(" ", ""));
    }

    static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    static byte[] varint(long v) {
        return QuicVarInt.encode(v);
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }

    /** A raw frame with an explicit length, whatever its payload. */
    static byte[] frame(long type, long length, byte[] payload) {
        return concat(varint(type), varint(length), payload);
    }

    /** A raw frame whose length matches its payload. */
    static byte[] frame(long type, byte... payload) {
        return frame(type, payload.length, payload);
    }

    /** A SETTINGS payload from identifier, value pairs. */
    static byte[] settingsPayload(long... pairs) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (long v : pairs) out.writeBytes(varint(v));
        return out.toByteArray();
    }

    static Http3FrameReader reader(byte[]... parts) {
        return new Http3FrameReader(new ByteArrayInputStream(concat(parts)));
    }

    /** Reading the input to its end fails with this connection error. */
    static Http3Exception assertConnectionError(Http3ErrorCode code, Http3FrameReader reader) {
        return assertConnectionError(code, () -> {
            while (reader.readFrame() != null) {
                // keep reading until the failure
            }
        });
    }

    static Http3Exception assertConnectionError(Http3ErrorCode code, Executable action) {
        Http3Exception e = assertThrows(Http3Exception.class, action);
        assertEquals(code, e.errorCode(), e.getMessage());
        assertTrue(e.isConnectionError(), e.getMessage());
        return e;
    }

    static Http3Exception assertStreamError(long streamId, Http3ErrorCode code, Executable action) {
        Http3Exception e = assertThrows(Http3Exception.class, action);
        assertEquals(code, e.errorCode(), e.getMessage());
        assertEquals(streamId, e.streamId(), e.getMessage());
        return e;
    }

    /** Records compared component by component, with byte arrays compared by content. */
    static void assertFrameEquals(Http3Frame expected, Http3Frame actual) {
        assertEquals(expected.getClass(), actual.getClass());
        for (RecordComponent c : expected.getClass().getRecordComponents()) {
            try {
                Object a = c.getAccessor().invoke(expected);
                Object b = c.getAccessor().invoke(actual);
                if (a instanceof byte[] x) {
                    assertArrayEquals(x, (byte[]) b, c.getName());
                } else if (a instanceof Map<?, ?> m) {
                    assertEquals(m, b, c.getName());
                    assertEquals(m.keySet().stream().toList(), ((Map<?, ?>) b).keySet().stream().toList(), "order of " + c.getName());
                } else {
                    assertEquals(a, b, c.getName());
                }
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        }
    }

    static void assertContains(String haystack, String needle) {
        assertTrue(haystack.contains(needle), () -> "expected '" + needle + "' in: " + haystack);
    }
}
