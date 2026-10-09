package io.github.mahmoudimus.http2;

import static io.github.mahmoudimus.http2.TestBytes.assertContains;
import static io.github.mahmoudimus.http2.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** HPACK limits, malformed input and encoder choices. */
class HpackTest {

    private static Http2Exception assertCompressionError(HpackDecoder d, String hex, String message) {
        Http2Exception e = assertThrows(Http2Exception.class, () -> d.decode(1, hex(hex)));
        assertEquals(ErrorCode.COMPRESSION_ERROR, e.errorCode(), e.getMessage());
        assertTrue(e.isConnectionError());
        assertContains(e.getMessage(), message);
        return e;
    }

    private static byte[] literalWithIndexing(String name, String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x40);
        HpackEncoder.writeInt(out, 0, 7, name.length());
        out.writeBytes(name.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        HpackEncoder.writeInt(out, 0, 7, value.length());
        out.writeBytes(value.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        return out.toByteArray();
    }

    // --- malformed input -----------------------------------------------------------------------

    @Test
    void indexZeroAndIndexBeyondTheTables() {
        assertCompressionError(new HpackDecoder(), "80", "index 0");
        assertCompressionError(new HpackDecoder(), "be", "index 62");
        assertCompressionError(new HpackDecoder(), "7e 00", "index 62"); // literal with a missing indexed name
    }

    @Test
    void integerOverflowInPrefixIntegers() {
        // 127 + 0x7f + (0x7f << 7) + ... + (0x0f << 28) is far beyond 2^31-1.
        assertCompressionError(new HpackDecoder(), "ff ff ff ff ff 0f", "integer overflow");
        // Exactly 2^31: 127 + 2147483521.
        assertCompressionError(new HpackDecoder(), "ff 81 ff ff ff 07", "integer overflow");
        // Endless zero continuation bytes.
        assertCompressionError(new HpackDecoder(), "ff 80 80 80 80 80 80 80 80 01", "integer overflow");
        assertCompressionError(new HpackDecoder(), "ff 80", "truncated integer");
        // A string length of 2^31-1 is a valid integer but runs past the block.
        assertCompressionError(new HpackDecoder(), "40 7f 80 ff ff ff 07", "runs past");
    }

    @Test
    void truncatedLiterals() {
        assertCompressionError(new HpackDecoder(), "40 0a 61", "runs past");
        assertCompressionError(new HpackDecoder(), "40 01 61", "truncated field"); // value missing
        assertCompressionError(new HpackDecoder(), "04", "truncated field");
    }

    @Test
    void badHuffmanInAString() {
        assertCompressionError(new HpackDecoder(), "04 81 ff", "longer than 7 bits");
        assertCompressionError(new HpackDecoder(), "04 84 ff ff ff ff", "EOS");
    }

    // --- dynamic table size updates ------------------------------------------------------------

    @Test
    void sizeUpdateAboveTheSettingIsRejected() throws Http2Exception {
        HpackDecoder d = new HpackDecoder();
        d.decode(1, hex("3fe11f 82")); // 4096 is fine
        assertCompressionError(d, "3fe21f 82", "exceeds the limit 4096"); // 4097
    }

    @Test
    void sizeUpdateMustComeFirst() throws Http2Exception {
        assertCompressionError(new HpackDecoder(), "82 20", "after a field");
        // Several at the start are fine (§4.2: the smallest, then the final size).
        HpackDecoder d = new HpackDecoder();
        assertEquals(List.of(new HeaderField(":method", "GET")), d.decode(1, hex("20 3fe11f 82")));
        assertEquals(4096, d.dynamicTableCapacity());
    }

    @Test
    void sizeUpdateIsRequiredAfterTheSettingShrinks() throws Http2Exception {
        HpackDecoder d = new HpackDecoder();
        d.decode(1, literalWithIndexing("x-a", "1"));
        assertEquals(1, d.dynamicTableLength());
        d.setMaxHeaderTableSize(64);
        assertCompressionError(d, "82", "must start with a dynamic table size update");

        HpackDecoder d2 = new HpackDecoder();
        d2.setMaxHeaderTableSize(64);
        assertCompressionError(d2, "", "must start with a dynamic table size update");
        assertCompressionError(d2, "3fe11f 82", "exceeds the limit 64");

        HpackDecoder d3 = new HpackDecoder();
        d3.decode(1, literalWithIndexing("x-a", "1"));
        d3.setMaxHeaderTableSize(64);
        d3.decode(1, hex("3f21 82")); // update to 64, then a field
        assertEquals(64, d3.dynamicTableCapacity());
        assertEquals(36, d3.dynamicTableSize(), "the entry still fits");
        d3.decode(1, hex("82")); // no longer required
        // Growing the setting requires nothing.
        d3.setMaxHeaderTableSize(8192);
        d3.decode(1, hex("82"));
    }

    @Test
    void sizeUpdateToZeroEvictsEverything() throws Http2Exception {
        HpackDecoder d = new HpackDecoder();
        d.decode(1, literalWithIndexing("x-a", "1"));
        d.decode(1, hex("20"));
        assertEquals(0, d.dynamicTableLength());
        assertEquals(0, d.dynamicTableSize());
        assertCompressionError(d, "be", "index 62");
    }

    // --- limits --------------------------------------------------------------------------------

    @Test
    void headerListSizeIsAStreamErrorThatKeepsTheTableInStep() throws Http2Exception {
        HpackDecoder d = new HpackDecoder();
        d.setMaxHeaderListSize(100);
        // Three new fields of 32 + 3 + 30 = 65 octets: the list is 195, the table takes all three.
        String v = "v".repeat(30);
        byte[] block = TestBytes.concat(literalWithIndexing("x-a", v), literalWithIndexing("x-b", v), literalWithIndexing("x-c", v));
        HeaderListSizeException e = assertThrows(HeaderListSizeException.class, () -> d.decode(5, block));
        assertFalse(e.isConnectionError());
        assertEquals(5, e.streamId());
        assertEquals(195, e.size());
        assertEquals(100, e.limit());
        assertEquals(3, d.dynamicTableLength());
        // The next block can refer to all three.
        assertEquals(List.of(new HeaderField("x-a", v)), d.decode(7, hex("c0")));
    }

    @Test
    void hpackBombIsStoppedByTheHeaderListSize() {
        // One 4000-octet entry referenced 3000 times would decode to 12 MB.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(literalWithIndexing("x-bomb", "b".repeat(4000)));
        for (int i = 0; i < 3000; i++) out.write(0xbe);
        HpackDecoder d = new HpackDecoder();
        HeaderListSizeException e = assertThrows(HeaderListSizeException.class, () -> d.decode(1, out.toByteArray()));
        assertEquals(3001L * (4000 + 6 + 32), e.size());
        assertEquals(HpackDecoder.DEFAULT_MAX_HEADER_LIST_SIZE, e.limit());
    }

    @Test
    void stringLengthLimit() throws Http2Exception {
        HpackDecoder d = new HpackDecoder();
        d.setMaxStringLength(4);
        d.decode(1, hex("40 04 61626364 04 61626364"));
        Http2Exception raw = assertThrows(Http2Exception.class, () -> d.decode(1, hex("40 05 6162636465 00")));
        assertEquals(ErrorCode.ENHANCE_YOUR_CALM, raw.errorCode());
        assertTrue(raw.isConnectionError());
        // Huffman: 4 octets that decode to 6 characters ("aaaaaa" is 30 bits).
        Http2Exception huff = assertThrows(Http2Exception.class, () -> d.decode(1, hex("04 84 18c6 318c")));
        assertEquals(ErrorCode.ENHANCE_YOUR_CALM, huff.errorCode());
    }

    // --- encoder -------------------------------------------------------------------------------

    @Test
    void sensitiveNamesAreNeverIndexed() throws Http2Exception {
        HpackEncoder e = new HpackEncoder().setHuffman(false);
        byte[] block = e.encode(List.of(
                new HeaderField("authorization", "Bearer abc"),
                new HeaderField("cookie", "a=1"),
                new HeaderField("x-secret", "s", true),
                new HeaderField("x-plain", "p")));
        assertEquals(1, e.dynamicTableLength(), "only x-plain is indexed");
        // authorization is static index 23: never-indexed with a 4-bit prefix is 1f 08.
        assertEquals("1f08", hex(block).substring(0, 4));
        HpackDecoder d = new HpackDecoder();
        List<HeaderField> fields = d.decode(1, block);
        assertTrue(fields.get(0).sensitive());
        assertTrue(fields.get(1).sensitive());
        assertTrue(fields.get(2).sensitive());
        assertFalse(fields.get(3).sensitive());
        assertEquals(1, d.dynamicTableLength());
        // Encoding the same sensitive field again still sends it literally.
        byte[] again = e.encode(List.of(new HeaderField("authorization", "Bearer abc")));
        assertEquals(hex(block).substring(0, 2 * again.length), hex(again));

        HpackEncoder lax = new HpackEncoder().setNeverIndexSensitiveNames(false);
        lax.encode(List.of(new HeaderField("authorization", "Bearer abc")));
        assertEquals(1, lax.dynamicTableLength());
    }

    @Test
    void fieldsLargerThanTheTableAreNotIndexed() throws Http2Exception {
        HpackEncoder e = new HpackEncoder(100).setHuffman(false);
        e.encode(List.of(new HeaderField("x-small", "1")));
        byte[] block = e.encode(List.of(new HeaderField("x-large", "v".repeat(100))));
        assertEquals(0x00, block[0] & 0xf0, "literal without indexing");
        assertEquals(1, e.dynamicTableLength(), "the table was not flushed");
    }

    @Test
    void encoderSignalsTableSizeChanges() throws Http2Exception {
        HpackEncoder e = new HpackEncoder();
        HpackDecoder d = new HpackDecoder();
        d.decode(1, e.encode(List.of(new HeaderField("x-a", "1"))));
        d.decode(1, e.encode(List.of(new HeaderField("x-a", "1")))); // now indexed

        e.setMaxHeaderTableSize(0);
        e.setMaxHeaderTableSize(2048);
        byte[] block = e.encode(List.of(new HeaderField(":method", "GET")));
        // 0, then 2048 (31 + 2017 = 31, e1 0f), then the field.
        assertEquals("20" + "3fe10f" + "82", hex(block));
        d.setMaxHeaderTableSize(2048);
        d.decode(1, block);
        assertEquals(2048, d.dynamicTableCapacity());

        // A peer allowing more than the encoder's own limit does not grow the table.
        e.setMaxHeaderTableSize(1 << 20);
        assertEquals(4096, e.dynamicTableCapacity());
        assertEquals("3fe11f82", hex(e.encode(List.of(new HeaderField(":method", "GET")))));
        // No change, no update.
        e.setMaxHeaderTableSize(1 << 21);
        assertEquals("82", hex(e.encode(List.of(new HeaderField(":method", "GET")))));
    }

    @Test
    void encoderRejectsCharsThatAreNotOctets() {
        assertThrows(IllegalArgumentException.class, () -> new HpackEncoder().encode(List.of(new HeaderField("x", "€"))));
    }

    @Test
    void randomSectionsStayInStep() throws Http2Exception {
        Random random = new Random(42);
        String[] names = {"x-a", "x-b", "accept", "content-type", "cookie", ":path", "user-agent", "x-long"};
        HpackEncoder e = new HpackEncoder();
        HpackDecoder d = new HpackDecoder();
        for (int round = 0; round < 500; round++) {
            if (random.nextInt(20) == 0) {
                int size = random.nextInt(5000);
                e.setMaxHeaderTableSize(size);
                d.setMaxHeaderTableSize(size);
            }
            e.setHuffman(random.nextBoolean());
            List<HeaderField> fields = new ArrayList<>();
            for (int i = random.nextInt(12); i > 0; i--) {
                String name = names[random.nextInt(names.length)];
                String value = name.equals("x-long") ? "z".repeat(random.nextInt(3000)) : Integer.toString(random.nextInt(30));
                fields.add(new HeaderField(name, value, random.nextInt(10) == 0));
            }
            List<HeaderField> decoded = d.decode(1, e.encode(fields));
            assertEquals(fields.size(), decoded.size());
            for (int i = 0; i < fields.size(); i++) {
                assertEquals(fields.get(i).name(), decoded.get(i).name());
                assertEquals(fields.get(i).value(), decoded.get(i).value());
                if (fields.get(i).sensitive()) assertTrue(decoded.get(i).sensitive());
            }
            assertEquals(e.dynamicTableSize(), d.dynamicTableSize());
            assertEquals(e.dynamicTableLength(), d.dynamicTableLength());
        }
    }
}
