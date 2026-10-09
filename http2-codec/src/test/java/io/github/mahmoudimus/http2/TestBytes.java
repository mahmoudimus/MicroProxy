package io.github.mahmoudimus.http2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.RecordComponent;
import java.util.HexFormat;
import java.util.function.Consumer;

/** Helpers for building raw frames and comparing frames. */
final class TestBytes {

    private TestBytes() {}

    static byte[] hex(String hex) {
        return HexFormat.of().parseHex(hex.replace(" ", ""));
    }

    static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    /** A raw frame with an explicit header, whatever its payload. */
    static byte[] frame(int length, int type, int flags, int streamId, byte... payload) {
        byte[] f = new byte[9 + payload.length];
        f[0] = (byte) (length >>> 16);
        f[1] = (byte) (length >>> 8);
        f[2] = (byte) length;
        f[3] = (byte) type;
        f[4] = (byte) flags;
        f[5] = (byte) (streamId >>> 24);
        f[6] = (byte) (streamId >>> 16);
        f[7] = (byte) (streamId >>> 8);
        f[8] = (byte) streamId;
        System.arraycopy(payload, 0, f, 9, payload.length);
        return f;
    }

    /** A raw frame whose header length matches its payload. */
    static byte[] frame(int type, int flags, int streamId, byte... payload) {
        return frame(payload.length, type, flags, streamId, payload);
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }

    static FrameReader reader(byte[]... parts) {
        return new FrameReader(new ByteArrayInputStream(concat(parts)));
    }

    static FrameReader reader(Consumer<FrameReader> setup, byte[]... parts) {
        FrameReader r = reader(parts);
        setup.accept(r);
        return r;
    }

    /** Reading the input fails with this error code and scope. */
    static Http2Exception assertError(ErrorCode code, boolean connection, FrameReader reader) {
        Http2Exception e = assertThrows(Http2Exception.class, () -> {
            while (reader.readFrame() != null) {
                // keep reading until the failure
            }
        });
        assertEquals(code, e.errorCode(), e.getMessage());
        assertEquals(connection, e.isConnectionError(), e.getMessage());
        return e;
    }

    /** Records compared component by component, with byte arrays compared by content. */
    static void assertFrameEquals(Frame expected, Frame actual) {
        assertEquals(expected.getClass(), actual.getClass());
        for (RecordComponent c : expected.getClass().getRecordComponents()) {
            try {
                Object a = c.getAccessor().invoke(expected);
                Object b = c.getAccessor().invoke(actual);
                if (a instanceof byte[] x) {
                    assertArrayEquals(x, (byte[]) b, c.getName());
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
