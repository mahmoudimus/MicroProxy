package org.microproxy.contentviews;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.contentviews.ProtobufTest.bytes;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaders;

class GrpcTest {

    // mitmproxy_rs's gRPC vectors (view_grpc.rs).
    static final String TEST_YAML = "1: 150  # !sint: 75\n\n---\n\n1: 150  # !sint: 75\n";
    static final byte[] TEST_GRPC = bytes(0, 0, 0, 0, 3, 8, 150, 1, 0, 0, 0, 0, 3, 8, 150, 1);
    static final byte[] TEST_GZIP = bytes(1, 0, 0, 0, 23, 31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 227, 152, 198, 8, 0, 160,
            149, 78, 161, 3, 0, 0, 0);
    static final byte[] TEST_DEFLATE = bytes(1, 0, 0, 0, 5, 227, 152, 198, 8, 0);

    private static final ContentView VIEW = ContentViews.defaults().get("grpc").orElseThrow();

    static ContentView.Metadata grpc(String encoding) {
        HttpHeaders h = new HttpHeaders().set("content-type", "application/grpc");
        if (encoding != null) h.set("grpc-encoding", encoding);
        return new ContentView.Metadata("application/grpc", h, null, "/pkg.Service/Method", false);
    }

    @Test
    void emptyBody() throws DecodeException {
        assertEquals("", VIEW.render(new byte[0], grpc(null)));
        assertEquals(List.of(), Grpc.split(new byte[0]));
    }

    @Test
    void twoMessages() throws DecodeException {
        assertEquals(TEST_YAML, VIEW.render(TEST_GRPC, grpc(null)));
        List<byte[]> messages = Grpc.messages(TEST_GRPC, null);
        assertEquals(2, messages.size());
        assertArrayEquals(bytes(8, 150, 1), messages.get(1));
        assertArrayEquals(TEST_GRPC, Grpc.join(messages));
    }

    @Test
    void gzipCompressedMessage() throws DecodeException {
        assertEquals("# gzip-compressed, 23 bytes\n1: 150  # !sint: 75\n", VIEW.render(TEST_GZIP, grpc("gzip")));
        assertArrayEquals(bytes(8, 150, 1), Grpc.messages(TEST_GZIP, "gzip").getFirst());
    }

    @Test
    void deflateCompressedMessage() throws DecodeException {
        assertEquals("# deflate-compressed, 5 bytes\n1: 150  # !sint: 75\n", VIEW.render(TEST_DEFLATE, grpc("deflate")));
    }

    @Test
    void compressionRoundTrips() throws DecodeException {
        List<byte[]> messages = List.of("one".getBytes(StandardCharsets.UTF_8), new byte[0], bytes(8, 1));
        for (String encoding : List.of("gzip", "deflate")) {
            byte[] body = Grpc.join(messages, encoding);
            List<Grpc.Frame> frames = Grpc.split(body);
            assertTrue(frames.stream().allMatch(Grpc.Frame::compressed));
            List<byte[]> back = Grpc.messages(body, encoding);
            for (int i = 0; i < messages.size(); i++) assertArrayEquals(messages.get(i), back.get(i));
        }
        assertArrayEquals(Grpc.join(messages), Grpc.join(messages, "identity"));
        assertThrows(IllegalArgumentException.class, () -> Grpc.join(messages, "snappy"));
    }

    @Test
    void framingErrors() {
        // A flag other than 0 or 1.
        assertThrows(DecodeException.class, () -> Grpc.split(bytes(2, 0, 0, 0, 0)));
        // The body ends inside a message, or inside a header.
        assertThrows(DecodeException.class, () -> Grpc.split(bytes(0, 0, 0, 0, 5, 1)));
        assertThrows(DecodeException.class, () -> Grpc.split(bytes(0, 0, 0)));
        // A compressed message needs grpc-encoding, and one the proxy knows.
        assertThrows(DecodeException.class, () -> Grpc.messages(TEST_GZIP, null));
        assertThrows(DecodeException.class, () -> Grpc.messages(TEST_GZIP, "snappy"));
        assertThrows(DecodeException.class, () -> Grpc.messages(bytes(1, 0, 0, 0, 2, 1, 2), "gzip"));
    }

    @Test
    void aBodyCutShortShowsTheCompleteMessages() throws DecodeException {
        assertEquals("1: 150  # !sint: 75\n\n---\n\n# incomplete message: 2 of 3 bytes\n",
                VIEW.render(Arrays.copyOf(TEST_GRPC, 15), grpc(null)));
        assertEquals("1: 150  # !sint: 75\n\n---\n\n# 2 bytes of an incomplete message header\n",
                VIEW.render(Arrays.copyOf(TEST_GRPC, 10), grpc(null)));
    }

    @Test
    void statusDetails() throws DecodeException {
        Map<Object, Object> violation = new LinkedHashMap<>();
        violation.put(1, "name");
        violation.put(2, "must not be empty");
        Map<Object, Object> badRequest = Map.of(1, violation);
        Grpc.Status status = new Grpc.Status(3, "invalid name",
                List.of(new Grpc.Detail("type.googleapis.com/google.rpc.BadRequest", Protobuf.encode(badRequest))));
        String trailer = status.toTrailer();
        assertEquals(status, Grpc.statusFromTrailer(trailer));
        assertEquals("INVALID_ARGUMENT", status.codeName());
        assertEquals(null, Grpc.codeName(99));

        HttpHeaders trailers = new HttpHeaders().add("grpc-status", "3").add("grpc-message", "invalid%20name")
                .add("grpc-status-details-bin", trailer);
        assertEquals("""
                1: 150  # !sint: 75

                ---

                # trailers
                grpc-status: '3'  # INVALID_ARGUMENT
                grpc-message: invalid name  # percent-decoded
                grpc-status-details-bin:
                  code: 3
                  message: invalid name
                  details:
                  - type_url: type.googleapis.com/google.rpc.BadRequest
                    value:
                      field_violations:
                      - field: name
                        description: must not be empty
                """, VIEW.render(bytes(0, 0, 0, 0, 3, 8, 150, 1), grpc(null).withTrailers(trailers)));

        ContentViews views = ContentViews.defaults();
        assertEquals("INVALID_ARGUMENT", views.describeHeader("grpc-status", "3"));
        assertEquals("invalid name", views.describeHeader("grpc-message", "invalid%20name"));
        assertEquals(null, views.describeHeader("grpc-message", "plain"));
        assertTrue(views.describeHeader("grpc-status-details-bin", trailer).startsWith("code: 3\nmessage: invalid name\n"));
        assertEquals(null, views.describeHeader("content-type", "application/grpc"));
        assertEquals(null, views.describeHeader("grpc-status-details-bin", "!!!"));
    }

    @Test
    void grpcWebTrailersFrameAndTextEncoding() throws DecodeException {
        byte[] trailers = "grpc-status: 0\r\ngrpc-message: done\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] body = new byte[8 + 5 + trailers.length];
        System.arraycopy(bytes(0, 0, 0, 0, 3, 8, 150, 1), 0, body, 0, 8);
        body[8] = (byte) 0x80;
        body[12] = (byte) trailers.length;
        System.arraycopy(trailers, 0, body, 13, trailers.length);
        String expected = "1: 150  # !sint: 75\n\n---\n\n# trailers\ngrpc-status: '0'  # OK\ngrpc-message: done\n";
        assertEquals(expected, VIEW.render(body, ContentView.Metadata.of("application/grpc-web+proto")));
        byte[] text = Base64.getEncoder().encode(body);
        assertEquals(expected, VIEW.render(text, ContentView.Metadata.of("application/grpc-web-text")));
        // Plain gRPC has no trailers frames.
        assertThrows(DecodeException.class, () -> Grpc.split(body));
    }
}
