package io.github.mahmoudimus.http2;

import static io.github.mahmoudimus.http2.TestBytes.assertContains;
import static io.github.mahmoudimus.http2.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.util.Random;
import org.junit.jupiter.api.Test;

class HuffmanTest {

    private static String encode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Huffman.encode(s, out);
        assertEquals(Huffman.encodedLength(s), out.size());
        return hex(out.toByteArray());
    }

    private static String decode(String hex) throws Http2Exception {
        byte[] b = hex(hex);
        return Huffman.decode(b, 0, b.length, 1 << 16);
    }

    private static void assertRejected(String hex, ErrorCode code, String message) {
        Http2Exception e = assertThrows(Http2Exception.class, () -> decode(hex));
        assertEquals(code, e.errorCode());
        assertContains(e.getMessage(), message);
    }

    @Test
    void rfcStrings() throws Http2Exception {
        // From RFC 7541 C.4 and C.6.
        String[][] cases = {
            {"www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"},
            {"no-cache", "a8eb10649cbf"},
            {"custom-key", "25a849e95ba97d7f"},
            {"custom-value", "25a849e95bb8e8b4bf"},
            {"302", "6402"},
            {"private", "aec3771a4b"},
            {"Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"},
            {"https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"},
            {"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"},
        };
        for (String[] c : cases) {
            assertEquals(c[1], encode(c[0]), c[0]);
            assertEquals(c[0], decode(c[1]), c[1]);
        }
    }

    @Test
    void everyOctetRoundTrips() throws Http2Exception {
        StringBuilder all = new StringBuilder();
        for (int i = 0; i < 256; i++) all.append((char) i);
        String s = all.toString();
        assertEquals(s, decode(encode(s)));
        Random random = new Random(7541);
        for (int i = 0; i < 2000; i++) {
            char[] cs = new char[random.nextInt(40)];
            for (int j = 0; j < cs.length; j++) cs[j] = (char) random.nextInt(256);
            String t = new String(cs);
            assertEquals(t, decode(encode(t)));
        }
    }

    @Test
    void emptyString() throws Http2Exception {
        assertEquals("", encode(""));
        assertEquals("", decode(""));
    }

    @Test
    void validPaddingIsUpToSevenOnes() throws Http2Exception {
        // 'a' is 00011; padded with 111.
        assertEquals("a", decode("1f"));
        // '0' is 00000 then '0' again = 10 bits, padded with 6 ones.
        assertEquals("00", decode("003f"));
    }

    @Test
    void eosIsRejected() {
        // 30 ones decode to EOS.
        assertRejected("fffffffc", ErrorCode.COMPRESSION_ERROR, "EOS");
        assertRejected("ffffffff", ErrorCode.COMPRESSION_ERROR, "EOS");
        // After a symbol, too.
        assertRejected("1fffffffff", ErrorCode.COMPRESSION_ERROR, "EOS");
    }

    @Test
    void paddingLongerThanSevenBitsIsRejected() {
        assertRejected("ff", ErrorCode.COMPRESSION_ERROR, "longer than 7 bits");
        assertRejected("1fff", ErrorCode.COMPRESSION_ERROR, "longer than 7 bits"); // 'a' + 11 ones
        assertRejected("ffff", ErrorCode.COMPRESSION_ERROR, "longer than 7 bits");
    }

    @Test
    void paddingThatIsNotAllOnesIsRejected() {
        assertRejected("18", ErrorCode.COMPRESSION_ERROR, "not a prefix of EOS"); // 'a' + 000
        assertRejected("1e", ErrorCode.COMPRESSION_ERROR, "not a prefix of EOS"); // 'a' + 110
        assertRejected("00", ErrorCode.COMPRESSION_ERROR, "not a prefix of EOS"); // '0' + 000
    }

    @Test
    void decodedLengthIsCapped() {
        byte[] b = hex(encode("aaaaaaaaaa"));
        Http2Exception e = assertThrows(Http2Exception.class, () -> Huffman.decode(b, 0, b.length, 9));
        assertEquals(ErrorCode.ENHANCE_YOUR_CALM, e.errorCode());
    }
}
