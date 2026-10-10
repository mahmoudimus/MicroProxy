package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertConnectionError;
import static io.github.mahmoudimus.http3.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

/** The Huffman code shared with HPACK, with the RFC 7541 Appendix C strings. */
class HuffmanTest {

    private static final Http3ErrorCode ERROR = Http3ErrorCode.QPACK_DECOMPRESSION_FAILED;

    private static String encode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Huffman.encode(s, out);
        return hex(out.toByteArray());
    }

    private static String decode(String hex) throws Http3Exception {
        byte[] b = hex(hex);
        return Huffman.decode(b, 0, b.length, Long.MAX_VALUE, ERROR);
    }

    @Test
    void rfc7541Strings() throws Http3Exception {
        String[][] cases = {
            {"www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"},
            {"no-cache", "a8eb10649cbf"},
            {"custom-key", "25a849e95ba97d7f"},
            {"custom-value", "25a849e95bb8e8b4bf"},
            {"302", "6402"},
            {"private", "aec3771a4b"},
            {"Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"},
            {"https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"},
        };
        for (String[] c : cases) {
            assertEquals(c[1], encode(c[0]), c[0]);
            assertEquals(c[0], decode(c[1]), c[1]);
            assertEquals(c[1].length() / 2, Huffman.encodedLength(c[0]));
        }
    }

    @Test
    void everyOctetRoundTrips() throws Http3Exception {
        StringBuilder all = new StringBuilder();
        for (int i = 0; i < 256; i++) {
            String one = String.valueOf((char) i);
            assertEquals(one, decode(encode(one)));
            all.append((char) i);
        }
        assertEquals(all.toString(), decode(encode(all.toString())));
        assertEquals("", decode(""));
    }

    @Test
    void invalidPaddingAndEos() {
        assertConnectionError(ERROR, () -> decode("ffffffff")); // EOS (30 ones), then more
        assertConnectionError(ERROR, () -> decode("f1e3c2e5f23a6ba0ab90f4ffff")); // 8+ bits of padding
        assertConnectionError(ERROR, () -> decode("00")); // '0' (00000) then 000 padding, not ones
    }

    @Test
    void outputLimit() {
        byte[] b = hex("f1e3c2e5f23a6ba0ab90f4ff");
        assertConnectionError(Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR,
                () -> Huffman.decode(b, 0, b.length, 10, Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR));
    }
}
