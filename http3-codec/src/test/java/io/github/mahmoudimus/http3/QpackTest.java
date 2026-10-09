package io.github.mahmoudimus.http3;

import static io.github.mahmoudimus.http3.TestBytes.assertConnectionError;
import static io.github.mahmoudimus.http3.TestBytes.concat;
import static io.github.mahmoudimus.http3.TestBytes.hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** The QPACK encoder and decoder: dynamic table, blocking, acknowledgments, limits and errors. */
class QpackTest {

    private static final Http3ErrorCode DECOMPRESSION = Http3ErrorCode.QPACK_DECOMPRESSION_FAILED;
    private static final Http3ErrorCode ENCODER_STREAM = Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR;
    private static final Http3ErrorCode DECODER_STREAM = Http3ErrorCode.QPACK_DECODER_STREAM_ERROR;

    static HeaderField f(String name, String value) {
        return new HeaderField(name, value);
    }

    static final List<HeaderField> REQUEST = List.of(
            f(":method", "GET"), f(":scheme", "https"), f(":authority", "example.com"), f(":path", "/a/b?c=d"),
            f("user-agent", "test/1.0"), f("accept", "*/*"), f("x-request-id", "abc123"));

    // --- static-only mode ----------------------------------------------------------------------

    @Test
    void staticOnlyEncoderNeverUsesTheDynamicTable() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder();
        enc.setPeerSettings(4096, 100); // the peer allows a table, but this encoder wants none
        QpackDecoder dec = new QpackDecoder();
        for (int i = 0; i < 3; i++) {
            byte[] section = enc.encode(4L * i, REQUEST);
            assertEquals("0000", hex(Arrays.copyOf(section, 2)));
            assertEquals(REQUEST, dec.decode(4L * i, section));
        }
        assertEquals(0, enc.encoderStreamBytes().length);
        assertEquals(0, enc.dynamicTableLength());
        assertEquals(0, dec.decoderStreamBytes().length);
        assertEquals(-1, enc.insert("a", "b"));
    }

    @Test
    void staticOnlyDecoderRejectsDynamicReferences() {
        QpackDecoder dec = new QpackDecoder();
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0200 80"))); // Required Insert Count 1
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0000 80"))); // dynamic index, RIC 0
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0000 10"))); // post-base, RIC 0
        assertConnectionError(ENCODER_STREAM, () -> dec.onEncoderStream(hex("21"))); // capacity 1 > 0
    }

    @Test
    void everyStaticEntryRoundTrips() throws Http3Exception {
        List<HeaderField> all = Arrays.asList(QpackStaticTable.ENTRIES);
        byte[] section = new QpackEncoder().setNeverIndexSensitiveNames(false).encode(0, all);
        assertEquals(2 + 63 + 2 * 36, section.length); // one octet below index 63, two from there
        assertEquals(all, new QpackDecoder().decode(0, section));
    }

    // --- representations -----------------------------------------------------------------------

    @Test
    void decoderHandlesEveryFieldLineRepresentation() throws Http3Exception {
        QpackDecoder dec = new QpackDecoder(4096, 0);
        // Capacity 4096, then insert a=1, b=2, c=3 (literal names, no Huffman).
        dec.onEncoderStream(hex("3fe11f 4161 0131 4162 0132 4163 0133"));
        // RIC 3 (encoded 3 % 256 + 1 = 4), Base 1 (sign 1, delta 1): a is relative 0, b and c post-base 0 and 1.
        byte[] section = hex(String.join(" ",
                "04 81",
                "80", // indexed, dynamic relative 0: a=1
                "10", // indexed, post-base 0: b=2
                "11", // indexed, post-base 1: c=3
                "d1", // indexed, static 17: :method GET
                "5f0e 0378797a", // literal, static name 29 (accept), xyz
                "7f0e 0378797a", // the same, never indexed
                "40 0378797a", // literal, dynamic name relative 0 (a)
                "60 0378797a", // the same, never indexed
                "01 0378797a", // literal, post-base name 1 (c)
                "09 0378797a", // the same, never indexed
                "23 6e616d 0376616c", // literal name "nam" = val
                "33 6e616d 0376616c")); // the same, never indexed
        List<HeaderField> fields = dec.decode(0, section);
        assertEquals(List.of(f("a", "1"), f("b", "2"), f("c", "3"), f(":method", "GET"),
                f("accept", "xyz"), new HeaderField("accept", "xyz", true),
                f("a", "xyz"), new HeaderField("a", "xyz", true),
                f("c", "xyz"), new HeaderField("c", "xyz", true),
                f("nam", "val"), new HeaderField("nam", "val", true)), fields);
        assertEquals("80", hex(dec.decoderStreamBytes()));
    }

    @Test
    void sensitiveFieldsAreSentNeverIndexedAndStayOutOfTheTable() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096);
        enc.setPeerSettings(4096, 10);
        QpackDecoder dec = new QpackDecoder(4096, 10);
        List<HeaderField> fields = List.of(
                f("authorization", "Bearer secret"), // static name, sensitive by name
                f("cookie", "id=1"),
                new HeaderField("x-token", "t0ps3cret", true), // literal name, marked
                new HeaderField(":method", "GET", true), // static exact match, but marked: still a literal
                f("x-plain", "v"));
        byte[] section = enc.encode(0, fields);
        dec.onEncoderStream(enc.encoderStreamBytes());
        List<HeaderField> decoded = dec.decode(0, section);
        assertTrue(decoded.get(0).sensitive());
        assertTrue(decoded.get(1).sensitive());
        assertTrue(decoded.get(2).sensitive());
        assertTrue(decoded.get(3).sensitive());
        assertFalse(decoded.get(4).sensitive());
        assertEquals(1, enc.dynamicTableLength()); // only x-plain was inserted
        assertEquals(f("x-plain", "v"), enc.dynamicTableEntry(0));
        // Forwarding the decoded fields keeps the bit.
        QpackDecoder dec2 = new QpackDecoder();
        assertEquals(decoded, dec2.decode(0, new QpackEncoder().encode(0, decoded)));
        // Unless the encoder is told names alone do not make a field sensitive.
        List<HeaderField> plain = new QpackDecoder().decode(0,
                new QpackEncoder().setNeverIndexSensitiveNames(false).encode(0, List.of(f("cookie", "id=1"))));
        assertFalse(plain.get(0).sensitive());
    }

    @Test
    void huffmanIsUsedWhenItIsShorter() throws Http3Exception {
        byte[] withHuffman = new QpackEncoder().encode(0, List.of(f("x-long-name", "www.example.com")));
        byte[] without = new QpackEncoder().setHuffman(false).encode(0, List.of(f("x-long-name", "www.example.com")));
        assertTrue(withHuffman.length < without.length);
        assertEquals(new QpackDecoder().decode(0, withHuffman), new QpackDecoder().decode(0, without));
    }

    // --- dynamic table -------------------------------------------------------------------------

    @Test
    void repeatedFieldsAreIndexedOnceAcknowledged() throws Http3Exception {
        Pair p = new Pair(4096, 0); // no blocked streams: only acknowledged entries may be referenced
        byte[] first = p.enc.encode(0, REQUEST);
        assertEquals("0000", hex(Arrays.copyOf(first, 2))); // inserted, but not referenced
        p.deliverEncoderStream();
        assertEquals(REQUEST, p.dec.decode(0, first));
        p.deliverDecoderStream(); // Insert Count Increment
        byte[] second = p.enc.encode(4, REQUEST);
        assertTrue(second.length < first.length / 2, second.length + " vs " + first.length);
        assertEquals(REQUEST, p.dec.decode(4, second));
        p.deliverDecoderStream(); // Section Acknowledgment
        assertEquals(0, p.enc.blockedStreams());
    }

    @Test
    void encoderRespectsThePeersBlockedStreamsLimit() throws Http3Exception {
        Pair p = new Pair(4096, 1);
        byte[] a = p.enc.encode(0, List.of(f("x-a", "1")));
        assertEquals(1, p.enc.blockedStreams());
        // A second stream may not block: it gets literals, decodable without the encoder stream.
        byte[] b = p.enc.encode(4, List.of(f("x-a", "1"), f("x-b", "2")));
        assertEquals("0000", hex(Arrays.copyOf(b, 2)));
        assertEquals(1, p.enc.blockedStreams());
        // The blocked stream itself may block again.
        byte[] a2 = p.enc.encode(0, List.of(f("x-b", "2")));
        assertTrue(a2[0] != 0);

        assertNull(p.dec.decode(0, a));
        assertEquals(List.of(f("x-a", "1"), f("x-b", "2")), p.dec.decode(4, b));
        p.deliverEncoderStream(List.of(0L));
        assertEquals(List.of(f("x-a", "1")), p.dec.resume(0));
        assertEquals(List.of(f("x-b", "2")), p.dec.decode(0, a2));
        p.deliverDecoderStream();
        assertEquals(0, p.enc.blockedStreams());
        assertEquals(2, p.enc.knownReceivedCount());
    }

    @Test
    void decoderEnforcesItsBlockedStreamsLimit() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096);
        enc.setPeerSettings(4096, 5); // the encoder believes more than the decoder allows
        QpackDecoder dec = new QpackDecoder(4096, 2);
        assertNull(dec.decode(0, enc.encode(0, List.of(f("x", "0")))));
        assertNull(dec.decode(4, enc.encode(4, List.of(f("x", "4")))));
        assertEquals(2, dec.blockedStreams());
        byte[] third = enc.encode(8, List.of(f("x", "8")));
        Http3Exception e = assertConnectionError(DECOMPRESSION, () -> dec.decode(8, third));
        TestBytes.assertContains(e.getMessage(), "SETTINGS_QPACK_BLOCKED_STREAMS");
        assertThrows(IllegalStateException.class, () -> dec.decode(0, third)); // already blocked
        assertThrows(IllegalStateException.class, () -> dec.resume(0)); // still blocked
        assertThrows(IllegalStateException.class, () -> dec.resume(12)); // never blocked
    }

    @Test
    void blockedSectionsResumeInPieces() throws Http3Exception {
        Pair p = new Pair(4096, 10);
        List<List<HeaderField>> sent = new ArrayList<>();
        List<byte[]> sections = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            List<HeaderField> fields = List.of(f("x-n", "v" + i), f("x-same", "s"), f(":path", "/" + i));
            sent.add(fields);
            sections.add(p.enc.encode(4L * i, fields));
        }
        for (int i = 0; i < 5; i++) assertNull(p.dec.decode(4L * i, sections.get(i)));
        byte[] stream = p.enc.encoderStreamBytes();
        List<Long> ready = new ArrayList<>();
        for (byte b : stream) ready.addAll(p.dec.onEncoderStream(new byte[] {b})); // one octet at a time
        assertEquals(List.of(0L, 4L, 8L, 12L, 16L), ready);
        for (int i = 0; i < 5; i++) assertEquals(sent.get(i), p.dec.resume(4L * i));
        p.enc.onDecoderStream(p.dec.decoderStreamBytes());
        assertEquals(0, p.enc.blockedStreams());
        assertEquals(p.enc.insertCount(), p.enc.knownReceivedCount());
    }

    @Test
    void entriesAreEvictedOnlyWhenAcknowledgedAndUnreferenced() throws Http3Exception {
        Pair p = new Pair(100, 10); // room for one 50-octet entry at a time
        assertEquals(0, p.enc.insert("x-a", "12345678901234")); // 3 + 14 + 32 = 49
        assertEquals(1, p.enc.insert("x-b", "12345678901234"));
        // Both unacknowledged: nothing can be evicted.
        assertEquals(-1, p.enc.insert("x-c", "12345678901234"));
        p.deliverEncoderStream();
        p.deliverDecoderStream(); // Insert Count Increment 2
        // Reference entry 0 from a section that stays unacknowledged.
        byte[] section = p.enc.encode(0, List.of(f("x-a", "12345678901234")));
        assertEquals(1, p.enc.referenceCount(0));
        assertEquals(-1, p.enc.insert("x-c", "12345678901234")); // entry 0 is the oldest and in use
        assertEquals(List.of(f("x-a", "12345678901234")), p.dec.decode(0, section));
        p.deliverDecoderStream(); // Section Acknowledgment
        assertEquals(0, p.enc.referenceCount(0));
        assertEquals(2, p.enc.insert("x-c", "12345678901234"));
        assertNull(p.enc.dynamicTableEntry(0));
        p.deliverEncoderStream();
        assertNull(p.dec.dynamicTableEntry(0));
        assertEquals(f("x-c", "12345678901234"), p.dec.dynamicTableEntry(2));
        assertEquals(3, p.enc.insert("x-d", "12345678901234")); // evicts entry 1: acknowledged and unused
        // Now no entry is evictable, so a new field cannot be inserted: it goes out as a literal.
        byte[] s2 = p.enc.encode(4, List.of(f("x-e", "12345678901234")));
        assertEquals("0000", hex(Arrays.copyOf(s2, 2)));
        assertEquals(List.of(f("x-e", "12345678901234")), p.dec.decode(4, s2));
    }

    @Test
    void streamCancellationReleasesReferences() throws Http3Exception {
        Pair p = new Pair(4096, 10);
        byte[] section = p.enc.encode(8, List.of(f("x-a", "1"), f("x-b", "2")));
        assertEquals(1, p.enc.referenceCount(0));
        assertEquals(1, p.enc.blockedStreams());
        assertNull(p.dec.decode(8, section));
        p.dec.cancelStream(8);
        p.enc.onDecoderStream(p.dec.decoderStreamBytes());
        assertEquals(0, p.enc.referenceCount(0));
        assertEquals(0, p.enc.referenceCount(1));
        assertEquals(0, p.enc.blockedStreams());
        assertEquals(0, p.enc.knownReceivedCount()); // a cancellation acknowledges nothing
        // An acknowledgment for the cancelled stream is now an error.
        assertConnectionError(DECODER_STREAM, () -> p.enc.onDecoderStream(hex("88")));
    }

    @Test
    void cancellationIsNotSentWithoutADynamicTable() {
        QpackDecoder dec = new QpackDecoder();
        dec.cancelStream(4);
        assertEquals(0, dec.decoderStreamBytes().length);
    }

    @Test
    void severalSectionsOnOneStreamAreAcknowledgedInOrder() throws Http3Exception {
        Pair p = new Pair(4096, 10);
        byte[] headers = p.enc.encode(0, List.of(f("x-a", "1")));
        byte[] trailers = p.enc.encode(0, List.of(f("x-b", "2")));
        p.deliverEncoderStream();
        p.dec.decode(0, headers);
        p.enc.onDecoderStream(p.dec.decoderStreamBytes());
        assertEquals(0, p.enc.referenceCount(0));
        assertEquals(1, p.enc.referenceCount(1));
        p.dec.decode(0, trailers);
        p.enc.onDecoderStream(p.dec.decoderStreamBytes());
        assertEquals(0, p.enc.referenceCount(1));
    }

    @Test
    void requiredInsertCountWrapsAround() throws Http3Exception {
        // 128 octets: MaxEntries 4, so the encoded count wraps every 8 inserts.
        Pair p = new Pair(128, 4);
        Random random = new Random(42);
        for (int i = 0; i < 200; i++) {
            List<HeaderField> fields = List.of(f("x", Integer.toString(random.nextInt(30))));
            byte[] section = p.enc.encode(4L * i, fields);
            assertTrue((section[0] & 0xff) <= 8);
            p.deliverEncoderStream();
            assertEquals(fields, p.dec.decode(4L * i, section));
            p.deliverDecoderStream();
        }
        assertTrue(p.enc.insertCount() > 50);
    }

    @Test
    void capacityChangesAreSentAndChecked() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(1000);
        enc.setPeerSettings(500, 0);
        assertEquals(500, enc.maxDynamicTableCapacity());
        assertThrows(IllegalArgumentException.class, () -> enc.setCapacity(501));
        enc.setCapacity(300);
        assertEquals("3f8d02", hex(enc.encoderStreamBytes()));
        enc.insert("x", "y");
        assertThrows(IllegalStateException.class, () -> enc.setCapacity(0)); // unacknowledged entry
        enc.onDecoderStream(hex("01"));
        enc.setCapacity(0);
        assertEquals(0, enc.dynamicTableLength());

        QpackDecoder dec = new QpackDecoder(500, 0);
        dec.onEncoderStream(hex("3f8d02 4178 0179")); // capacity 300, insert x=y
        assertEquals(1, dec.dynamicTableLength());
        dec.onEncoderStream(hex("20")); // capacity 0 evicts it
        assertEquals(0, dec.dynamicTableLength());
        assertEquals(1, dec.insertCount());
    }

    // --- decoder-stream errors at the encoder --------------------------------------------------

    @Test
    void invalidDecoderInstructions() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096);
        enc.setPeerSettings(4096, 10);
        enc.insert("x", "y");
        assertConnectionError(DECODER_STREAM, () -> enc.onDecoderStream(hex("84"))); // no such section
        assertConnectionError(DECODER_STREAM, () -> enc.onDecoderStream(hex("00"))); // increment 0
        QpackEncoder enc2 = new QpackEncoder(4096);
        enc2.setPeerSettings(4096, 10);
        enc2.insert("x", "y");
        assertConnectionError(DECODER_STREAM, () -> enc2.onDecoderStream(hex("02"))); // beyond the inserts
        QpackEncoder enc3 = new QpackEncoder(4096);
        assertConnectionError(DECODER_STREAM, () -> enc3.onDecoderStream(hex("ff ffffffffffffffffff 01"))); // overflow
        // Cancelling a stream without sections is harmless.
        new QpackEncoder().onDecoderStream(hex("44"));
    }

    @Test
    void decoderInstructionsMaySplitAnywhere() throws Http3Exception {
        Pair p = new Pair(4096, 100);
        for (int i = 0; i < 40; i++) {
            byte[] s = p.enc.encode(1000L * i, List.of(f("x-" + i, "v")));
            p.deliverEncoderStream();
            p.dec.decode(1000L * i, s);
        }
        byte[] instructions = p.dec.decoderStreamBytes();
        assertTrue(instructions.length > 40); // stream IDs above 127 take two octets
        for (byte b : instructions) p.enc.onDecoderStream(new byte[] {b});
        assertEquals(40, p.enc.knownReceivedCount());
        assertEquals(0, p.enc.blockedStreams());
        assertEquals(0, p.enc.referenceCount(0));
    }

    @Test
    void largeStreamIdsInDecoderInstructions() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096);
        enc.setPeerSettings(4096, 10);
        long id = QuicVarInt.MAX_VALUE - 3;
        enc.encode(id, List.of(f("x", "y")));
        QpackDecoder dec = new QpackDecoder(4096, 10);
        dec.onEncoderStream(enc.encoderStreamBytes());
        dec.decode(id, enc.encode(id, List.of(f("x", "y"))));
        dec.cancelStream(id);
        enc.onDecoderStream(dec.decoderStreamBytes());
        assertEquals(0, enc.blockedStreams());
    }

    // --- encoder-stream errors at the decoder --------------------------------------------------

    @Test
    void invalidEncoderInstructions() {
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f46"))); // capacity 101
        // Entry larger than the capacity, rejected from its declared length before its octets arrive.
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f45 c0 7f00")));
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f45 5f7f")));
        // Static index 99 (out of range), dynamic relative index into an empty table, duplicate of nothing.
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f45 ff24 00")));
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f45 80 00")));
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f45 00")));
        // An insert while the capacity is still 0.
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("4178 0179")));
        // Integer overflow and invalid Huffman.
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f ffffffffffffffffff01")));
        assertConnectionError(ENCODER_STREAM, () -> new QpackDecoder(100, 0).onEncoderStream(hex("3f45 c0 84ffffffff")));
    }

    @Test
    void duplicateOfAnEvictedEntryIsAnError() throws Http3Exception {
        QpackDecoder dec = new QpackDecoder(100, 0);
        dec.onEncoderStream(hex("3f1d 4178 0179 4179 017a")); // capacity 60: x=y, then y=z evicts it
        assertEquals(1, dec.dynamicTableLength());
        dec.onEncoderStream(hex("00")); // duplicate y=z (relative 0): fine
        assertConnectionError(ENCODER_STREAM, () -> dec.onEncoderStream(hex("02"))); // relative 2 is x=y, evicted
    }

    // --- field-section errors at the decoder ---------------------------------------------------

    @Test
    void malformedFieldSections() throws Http3Exception {
        QpackDecoder dec = new QpackDecoder(4096, 10);
        dec.onEncoderStream(hex("3fe11f 4161 0131 4162 0132")); // a=1, b=2
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex(""))); // no prefix
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("00"))); // half a prefix
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0000 ff24"))); // static index 99
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0000 5f00"))); // literal without its value
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0000 5f00 05616263"))); // value runs past the end
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("ff02 00"))); // encoded RIC 257, beyond 2 * MaxEntries
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0281 80"))); // RIC 1, Base -1
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0080"))); // RIC 0 with a sign bit
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0200 81"))); // relative index before entry 0
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0200 10"))); // post-base 0 = entry 1 >= RIC 1
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0300 01 00"))); // post-base name 1 = entry 3 >= RIC 2
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0000 5f00 81ff"))); // Huffman padding of 8 bits
    }

    @Test
    void referencesToEvictedEntriesAreErrors() throws Http3Exception {
        QpackDecoder dec = new QpackDecoder(100, 0);
        dec.onEncoderStream(hex("3f1d 4178 0179 4179 017a")); // capacity 60: x=y (0) evicted by y=z (1)
        // RIC 2 (encoded 2 % 6 + 1 = 3), Base 2: relative 1 is entry 0.
        assertConnectionError(DECOMPRESSION, () -> dec.decode(0, hex("0300 81")));
        assertEquals(List.of(f("y", "z")), dec.decode(0, hex("0300 80")));
    }

    // --- limits --------------------------------------------------------------------------------

    @Test
    void fieldSectionSizeLimitIsAStreamErrorThatKeepsTheConnection() throws Http3Exception {
        Pair p = new Pair(4096, 10);
        List<HeaderField> fields = List.of(f("x-a", "1234567"), f("x-b", "1234567")); // 42 + 42
        p.dec.setMaxFieldSectionSize(84);
        byte[] s1 = p.enc.encode(0, fields);
        p.deliverEncoderStream();
        assertEquals(fields, p.dec.decode(0, s1)); // exactly the limit
        p.dec.setMaxFieldSectionSize(83);
        byte[] s2 = p.enc.encode(4, fields);
        FieldSectionSizeException e = assertThrows(FieldSectionSizeException.class, () -> p.dec.decode(4, s2));
        assertEquals(Http3ErrorCode.H3_EXCESSIVE_LOAD, e.errorCode());
        assertEquals(4, e.streamId());
        assertFalse(e.isConnectionError());
        assertEquals(84, e.size());
        assertEquals(83, e.limit());
        // The section was still acknowledged, so the encoder's references are released.
        p.deliverDecoderStream();
        assertEquals(0, p.enc.blockedStreams());
        assertEquals(0, p.enc.referenceCount(0));
    }

    @Test
    void sizeBombIsBounded() throws Http3Exception {
        // One large entry referenced many times: a few octets on the wire, megabytes decoded.
        QpackDecoder dec = new QpackDecoder(4096, 0);
        byte[] big = new byte[3000];
        Arrays.fill(big, (byte) 'a');
        ByteArrayOutputStream insert = new ByteArrayOutputStream();
        insert.writeBytes(hex("3fe11f 4178"));
        QpackWire.writeInt(insert, 0x00, 7, big.length);
        insert.writeBytes(big);
        dec.onEncoderStream(insert.toByteArray());
        byte[] lines = new byte[10_000];
        Arrays.fill(lines, (byte) 0x80);
        byte[] section = concat(hex("0200"), lines);
        FieldSectionSizeException e = assertThrows(FieldSectionSizeException.class, () -> dec.decode(0, section));
        assertTrue(e.size() > 10_000_000);
    }

    @Test
    void encoderRespectsThePeersMaxFieldSectionSize() throws Http3Exception {
        QpackEncoder enc = new QpackEncoder(4096);
        enc.applyPeerSettings(Http3Settings.builder().qpackMaxTableCapacity(4096).maxFieldSectionSize(40).build());
        assertNotNull(enc.encode(0, List.of(f("a", "1234567")))); // 40
        assertThrows(IllegalArgumentException.class, () -> enc.encode(0, List.of(f("a", "12345678"))));
        assertEquals(1, enc.dynamicTableLength()); // the rejected section changed nothing
        assertThrows(IllegalArgumentException.class, () -> enc.encode(0, List.of(f("a", "Ā"))));
    }

    // --- randomized round trips ----------------------------------------------------------------

    @Test
    void randomSectionsRoundTripWithDelayedAndSplitStreams() throws Http3Exception {
        for (long seed = 1; seed <= 20; seed++) {
            Random random = new Random(seed);
            int capacity = new int[] {0, 64, 200, 1024, 4096}[random.nextInt(5)];
            int blocked = random.nextInt(4);
            QpackEncoder enc = new QpackEncoder(capacity).setHuffman(random.nextBoolean()).setNeverIndexSensitiveNames(false);
            enc.setPeerSettings(capacity, blocked);
            QpackDecoder dec = new QpackDecoder(capacity, blocked);
            Deque<byte[]> encoderInFlight = new ArrayDeque<>();
            java.util.Map<Long, List<HeaderField>> expected = new java.util.HashMap<>();
            java.util.Map<Long, byte[]> waiting = new java.util.HashMap<>();
            for (int i = 0; i < 300; i++) {
                long streamId = 4L * i;
                List<HeaderField> fields = randomFields(random);
                byte[] section = enc.encode(streamId, fields);
                byte[] instructions = enc.encoderStreamBytes();
                if (instructions.length > 0) encoderInFlight.add(instructions);
                expected.put(streamId, fields);
                // Deliver some encoder-stream data, in random pieces, before or after the section.
                while (!encoderInFlight.isEmpty() && random.nextInt(3) != 0) {
                    for (long ready : deliverInPieces(dec, encoderInFlight.poll(), random)) {
                        assertEquals(expected.get(ready), dec.resume(ready));
                        waiting.remove(ready);
                    }
                }
                List<HeaderField> decoded = dec.decode(streamId, section);
                if (decoded == null) {
                    waiting.put(streamId, section);
                } else {
                    assertEquals(fields, decoded);
                }
                if (random.nextInt(4) == 0) enc.onDecoderStream(dec.decoderStreamBytes());
            }
            while (!encoderInFlight.isEmpty()) {
                for (long ready : deliverInPieces(dec, encoderInFlight.poll(), random)) {
                    assertEquals(expected.get(ready), dec.resume(ready));
                    waiting.remove(ready);
                }
            }
            assertTrue(waiting.isEmpty(), "seed " + seed + ": still blocked " + waiting.keySet());
            enc.onDecoderStream(dec.decoderStreamBytes());
            assertEquals(enc.insertCount(), dec.insertCount());
            assertEquals(enc.insertCount(), enc.knownReceivedCount());
            assertEquals(0, enc.blockedStreams());
            assertEquals(enc.dynamicTableLength(), dec.dynamicTableLength());
            for (long abs = enc.insertCount() - enc.dynamicTableLength(); abs < enc.insertCount(); abs++) {
                assertEquals(enc.dynamicTableEntry(abs), dec.dynamicTableEntry(abs));
                assertEquals(0, enc.referenceCount(abs));
            }
        }
    }

    private static List<Long> deliverInPieces(QpackDecoder dec, byte[] data, Random random) throws Http3Exception {
        List<Long> ready = new ArrayList<>();
        int pos = 0;
        while (pos < data.length) {
            int n = 1 + random.nextInt(data.length - pos);
            ready.addAll(dec.onEncoderStream(data, pos, n));
            pos += n;
        }
        return ready;
    }

    static List<HeaderField> randomFields(Random random) {
        List<HeaderField> fields = new ArrayList<>();
        for (int i = random.nextInt(8); i >= 0; i--) {
            switch (random.nextInt(6)) {
                case 0 -> fields.add(QpackStaticTable.ENTRIES[random.nextInt(QpackStaticTable.LENGTH)]);
                case 1 -> fields.add(f(QpackStaticTable.ENTRIES[random.nextInt(QpackStaticTable.LENGTH)].name(), "v" + random.nextInt(20)));
                case 2 -> fields.add(new HeaderField("x-secret", "s" + random.nextInt(5), true));
                default -> {
                    char[] v = new char[random.nextInt(40)];
                    for (int j = 0; j < v.length; j++) v[j] = (char) random.nextInt(256);
                    fields.add(f("x-f" + random.nextInt(12), random.nextInt(3) == 0 ? new String(v) : "val" + random.nextInt(8)));
                }
            }
        }
        return fields;
    }

    /** An encoder and a decoder that agree on settings, with helpers to carry their streams. */
    private static final class Pair {
        final QpackEncoder enc;
        final QpackDecoder dec;

        Pair(long capacity, int blocked) {
            enc = new QpackEncoder(capacity);
            enc.setPeerSettings(capacity, blocked);
            dec = new QpackDecoder(capacity, blocked);
        }

        void deliverEncoderStream() throws Http3Exception {
            dec.onEncoderStream(enc.encoderStreamBytes());
        }

        void deliverEncoderStream(List<Long> expectReady) throws Http3Exception {
            assertEquals(expectReady, dec.onEncoderStream(enc.encoderStreamBytes()));
        }

        void deliverDecoderStream() throws Http3Exception {
            enc.onDecoderStream(dec.decoderStreamBytes());
        }
    }

    @Test
    void decoderStreamBytesAreDrained() throws Http3Exception {
        Pair p = new Pair(4096, 1);
        p.enc.insert("x", "y");
        p.deliverEncoderStream();
        assertArrayEquals(hex("01"), p.dec.decoderStreamBytes());
        assertEquals(0, p.dec.decoderStreamBytes().length);
    }
}
