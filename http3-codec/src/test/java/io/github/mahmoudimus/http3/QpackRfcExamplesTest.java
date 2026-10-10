package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The examples of RFC 9204 Appendix B, encoded and decoded byte for byte, with both dynamic tables
 * (absolute index, reference count, size) checked after each step as the RFC shows them. The
 * examples use no Huffman coding, a SETTINGS_QPACK_MAX_TABLE_CAPACITY of 220, and need one blocked
 * stream.
 */
class QpackRfcExamplesTest {

    // B.1: the encoder has not yet received the decoder's settings, so it is static-only.
    static final String B1_SECTION = "0000 510b 2f69 6e64 6578 2e68 746d 6c";
    // B.2
    static final String B2_ENCODER = "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468";
    static final String B2_SECTION = "0381 10 11";
    static final String B2_DECODER = "84";
    // B.3
    static final String B3_ENCODER = "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565";
    static final String B3_DECODER = "01";
    // B.4
    static final String B4_ENCODER = "02";
    static final String B4_SECTION = "0500 80 c1 81";
    static final String B4_DECODER = "48";
    // B.5
    static final String B5_ENCODER = "810d 6375 7374 6f6d 2d76 616c 7565 32";

    static HeaderField f(String name, String value) {
        return new HeaderField(name, value);
    }

    static final List<HeaderField> B1_FIELDS = List.of(f(":path", "/index.html"));
    static final List<HeaderField> B2_FIELDS = List.of(f(":authority", "www.example.com"), f(":path", "/sample/path"));
    static final List<HeaderField> B4_FIELDS =
            List.of(f(":authority", "www.example.com"), f(":path", "/"), f("custom-key", "custom-value"));

    static String compact(String spaced) {
        return spaced.replace(" ", "");
    }

    @Test
    void encoderProducesTheRfcBytes() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096).setHuffman(false);

        // B.1 Literal Field Line with Name Reference
        assertEquals(compact(B1_SECTION), hex(enc.encode(0, B1_FIELDS)));
        assertEquals("", hex(enc.encoderStreamBytes()));
        assertEquals(0, enc.dynamicTableSize());

        // B.2 Dynamic Table
        enc.setPeerSettings(220, 1);
        assertEquals(compact(B2_SECTION), hex(enc.encode(4, B2_FIELDS)));
        assertEquals(compact(B2_ENCODER), hex(enc.encoderStreamBytes()));
        assertTable(enc, 106, 0, f(":authority", "www.example.com"), f(":path", "/sample/path"));
        assertRefs(enc, 1, 1);
        assertEquals(0, enc.knownReceivedCount());
        enc.onDecoderStream(hex(B2_DECODER));
        assertRefs(enc, 0, 0);
        assertEquals(2, enc.knownReceivedCount());

        // B.3 Speculative Insert
        assertEquals(2, enc.insert("custom-key", "custom-value"));
        assertEquals(compact(B3_ENCODER), hex(enc.encoderStreamBytes()));
        assertTable(enc, 160, 0, f(":authority", "www.example.com"), f(":path", "/sample/path"), f("custom-key", "custom-value"));
        enc.onDecoderStream(hex(B3_DECODER));
        assertEquals(3, enc.knownReceivedCount());

        // B.4 Duplicate Instruction, Stream Cancellation
        assertEquals(3, enc.duplicate(0));
        assertEquals(compact(B4_ENCODER), hex(enc.encoderStreamBytes()));
        assertEquals(compact(B4_SECTION), hex(enc.encode(8, B4_FIELDS)));
        assertEquals("", hex(enc.encoderStreamBytes()));
        assertTable(enc, 217, 0, f(":authority", "www.example.com"), f(":path", "/sample/path"),
                f("custom-key", "custom-value"), f(":authority", "www.example.com"));
        assertRefs(enc, 0, 0, 1, 1);
        assertEquals(1, enc.blockedStreams());
        enc.onDecoderStream(hex(B4_DECODER));
        assertRefs(enc, 0, 0, 0, 0);
        assertEquals(0, enc.blockedStreams());
        assertEquals(3, enc.knownReceivedCount());

        // B.5 Dynamic Table Insert, Eviction
        assertEquals(4, enc.insert("custom-key", "custom-value2"));
        assertEquals(compact(B5_ENCODER), hex(enc.encoderStreamBytes()));
        assertTable(enc, 215, 1, f(":path", "/sample/path"), f("custom-key", "custom-value"),
                f(":authority", "www.example.com"), f("custom-key", "custom-value2"));
    }

    @Test
    void decoderDecodesTheRfcBytesAndAnswersAsTheRfcDoes() throws Http3Exception {
        QpackDecoder dec = new QpackDecoder(220, 1);

        // B.1
        assertEquals(B1_FIELDS, dec.decode(0, hex(B1_SECTION)));
        assertEquals("", hex(dec.decoderStreamBytes()));

        // B.2
        assertEquals(List.of(), dec.onEncoderStream(hex(B2_ENCODER)));
        assertEquals(220, dec.dynamicTableCapacity());
        assertEquals(B2_FIELDS, dec.decode(4, hex(B2_SECTION)));
        assertEquals(B2_DECODER, hex(dec.decoderStreamBytes()));
        assertTable(dec, 106, 0, f(":authority", "www.example.com"), f(":path", "/sample/path"));

        // B.3
        dec.onEncoderStream(hex(B3_ENCODER));
        assertEquals(B3_DECODER, hex(dec.decoderStreamBytes()));
        assertTable(dec, 160, 0, f(":authority", "www.example.com"), f(":path", "/sample/path"), f("custom-key", "custom-value"));

        // B.4: the encoder stream data is delayed, so the section arrives first and blocks; then
        // the decoder cancels the stream.
        assertNull(dec.decode(8, hex(B4_SECTION)));
        assertTrue(dec.isBlocked(8));
        assertEquals(1, dec.blockedStreams());
        dec.cancelStream(8);
        assertFalse(dec.isBlocked(8));
        assertEquals(B4_DECODER, hex(dec.decoderStreamBytes()));
        assertEquals(List.of(), dec.onEncoderStream(hex(B4_ENCODER)));
        assertTable(dec, 217, 0, f(":authority", "www.example.com"), f(":path", "/sample/path"),
                f("custom-key", "custom-value"), f(":authority", "www.example.com"));

        // B.5
        dec.onEncoderStream(hex(B5_ENCODER));
        assertTable(dec, 215, 1, f(":path", "/sample/path"), f("custom-key", "custom-value"),
                f(":authority", "www.example.com"), f("custom-key", "custom-value2"));
        // The two inserts not otherwise acknowledged.
        assertEquals("02", hex(dec.decoderStreamBytes()));
    }

    @Test
    void blockedSectionOfB4ResumesWhenTheDuplicateArrives() throws Http3Exception {
        QpackDecoder dec = decoderAfterB3();
        assertNull(dec.decode(8, hex(B4_SECTION)));
        assertEquals(List.of(8L), dec.onEncoderStream(hex(B4_ENCODER)));
        assertEquals(B4_FIELDS, dec.resume(8));
        assertFalse(dec.isBlocked(8));
        assertEquals("88", hex(dec.decoderStreamBytes())); // Section Acknowledgment (stream=8)
    }

    @Test
    void sectionOfB4DecodesAtOnceWhenTheDuplicateArrivesFirst() throws Http3Exception {
        QpackDecoder dec = decoderAfterB3();
        dec.onEncoderStream(hex(B4_ENCODER));
        assertEquals(B4_FIELDS, dec.decode(8, hex(B4_SECTION)));
        assertEquals("88", hex(dec.decoderStreamBytes()));
    }

    @Test
    void encoderAndDecoderTogetherThroughEveryStep() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096).setHuffman(false);
        QpackDecoder dec = new QpackDecoder(220, 1);
        assertEquals(B1_FIELDS, dec.decode(0, enc.encode(0, B1_FIELDS)));
        enc.setPeerSettings(220, 1);
        byte[] section = enc.encode(4, B2_FIELDS);
        dec.onEncoderStream(enc.encoderStreamBytes());
        assertEquals(B2_FIELDS, dec.decode(4, section));
        enc.onDecoderStream(dec.decoderStreamBytes());
        enc.insert("custom-key", "custom-value");
        dec.onEncoderStream(enc.encoderStreamBytes());
        enc.onDecoderStream(dec.decoderStreamBytes());
        enc.duplicate(0);
        section = enc.encode(8, B4_FIELDS);
        dec.onEncoderStream(enc.encoderStreamBytes());
        assertEquals(B4_FIELDS, dec.decode(8, section));
        enc.onDecoderStream(dec.decoderStreamBytes());
        assertEquals(4, enc.knownReceivedCount());
        assertRefs(enc, 0, 0, 0, 0);
    }

    private static QpackDecoder decoderAfterB3() throws Http3Exception {
        QpackDecoder dec = new QpackDecoder(220, 1);
        dec.onEncoderStream(hex(B2_ENCODER));
        dec.decode(4, hex(B2_SECTION));
        dec.onEncoderStream(hex(B3_ENCODER));
        dec.decoderStreamBytes();
        return dec;
    }

    private static void assertTable(QpackEncoder enc, long size, long first, HeaderField... entries) {
        assertEquals(size, enc.dynamicTableSize(), "size");
        assertEquals(220, enc.dynamicTableCapacity(), "capacity");
        assertEquals(entries.length, enc.dynamicTableLength(), "entries");
        for (int i = 0; i < entries.length; i++) assertEquals(entries[i], enc.dynamicTableEntry(first + i), "entry " + (first + i));
        assertNull(enc.dynamicTableEntry(first + entries.length));
    }

    private static void assertTable(QpackDecoder dec, long size, long first, HeaderField... entries) {
        assertEquals(size, dec.dynamicTableSize(), "size");
        assertEquals(entries.length, dec.dynamicTableLength(), "entries");
        for (int i = 0; i < entries.length; i++) assertEquals(entries[i], dec.dynamicTableEntry(first + i), "entry " + (first + i));
        if (first > 0) assertNull(dec.dynamicTableEntry(first - 1));
    }

    private static void assertRefs(QpackEncoder enc, int... refs) {
        for (int i = 0; i < refs.length; i++) assertEquals(refs[i], enc.referenceCount(i), "Ref of entry " + i);
    }
}
