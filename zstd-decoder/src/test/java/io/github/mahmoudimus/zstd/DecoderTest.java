package io.github.mahmoudimus.zstd;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class DecoderTest {

    private static final ZstdDecompressor ZSTD = ZstdDecompressor.create();

    private static void assertCorrupt(byte[] data, String messagePart) {
        ZstdException e = assertThrows(ZstdException.class, () -> ZSTD.decompress(data));
        assertTrue(e.getMessage().contains(messagePart), e.getMessage());
    }

    @Test
    void xxh64MatchesTheReferenceVectors() {
        assertEquals(0xEF46DB3751D8E999L, xxh64(new byte[0]));
        assertEquals(0xD24EC4F1A98C6E5BL, xxh64("a".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0x44BC2CF5AD770999L, xxh64("abc".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0xC4255BA3D1AF5461L, xxh64("0123456789abcdef0123456789abcdef0123".getBytes(StandardCharsets.US_ASCII)));
        byte[] bytes = new byte[768];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) i;
        assertEquals(0x8E03C838C596036FL, xxh64(bytes));
        // Fed in uneven pieces, the result is the same.
        Xxh64 h = new Xxh64();
        for (int off = 0, step = 1; off < bytes.length; off += step, step = step % 37 + 3) {
            h.update(bytes, off, Math.min(step, bytes.length - off));
        }
        assertEquals(0x8E03C838C596036FL, h.digest());
    }

    private static long xxh64(byte[] data) {
        Xxh64 h = new Xxh64();
        h.update(data, 0, data.length);
        return h.digest();
    }

    @Test
    void emptyInputIsEmptyOutput() throws IOException {
        assertEquals(0, ZSTD.decompress(new byte[0]).length);
    }

    @Test
    void checksumsAreVerifiedUnlessDisabled() throws IOException {
        byte[] data = Fixtures.named("prose-1").compressed();
        data[data.length - 1] ^= 1;
        ZstdException e = assertThrows(ZstdException.class, () -> ZSTD.decompress(data));
        assertTrue(e.getMessage().contains("checksum"), e.getMessage());
        byte[] out = ZstdDecompressor.builder().verifyChecksums(false).build().decompress(data);
        assertEquals(Fixtures.named("prose-1").sha256(), Fixtures.sha256(out));
    }

    @Test
    void everyTruncationIsReported() {
        for (String name : new String[] {"byte", "few-symbols", "runs", "rle-literals"}) {
            byte[] data = Fixtures.named(name).compressed();
            for (int n = 1; n < data.length; n++) {
                byte[] prefix = Arrays.copyOf(data, n);
                assertThrows(ZstdException.class, () -> ZSTD.decompress(prefix), name + " cut to " + n + " bytes");
            }
        }
    }

    @Test
    void windowLimitIsEnforced() throws IOException {
        byte[] data = Fixtures.named("prose-22-long").compressed();
        ZstdDecompressor small = ZstdDecompressor.builder().maxWindowSize(1 << 16).build();
        ZstdException e = assertThrows(ZstdException.class, () -> small.decompress(data));
        assertTrue(e.getMessage().contains("window"), e.getMessage());
        assertEquals(400_000, ZSTD.decompress(data).length);
    }

    @Test
    void outputLimitIsEnforced() {
        byte[] data = Fixtures.named("zeros").compressed();
        ZstdException e = assertThrows(ZstdException.class, () -> ZSTD.decompress(data, 100_000));
        assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
    }

    @Test
    void framesNamingAnUnknownDictionaryAreRejected() throws IOException {
        assertCorrupt(Fixtures.named("dict-trained").compressed(), "dictionary");
        ZstdDictionary dict = ZstdDictionary.of(Fixtures.resource("trained.dict"));
        assertTrue(dict.id() > 0);
        assertEquals(dict.id(), ZstdDictionary.of(Fixtures.resource("trained.dict")).id());
        assertEquals(0, ZstdDictionary.of(Fixtures.resource("raw.dict")).id());
    }

    @Test
    void malformedHeadersAreRejected() throws IOException {
        assertCorrupt(new byte[] {1, 2, 3, 4, 5}, "magic");
        assertCorrupt(new byte[] {1, 2}, "truncated");
        byte[] reserved = Fixtures.named("byte").compressed();
        reserved[4] |= 0x08;
        assertCorrupt(reserved, "reserved");
        byte[] trailing = Arrays.copyOf(Fixtures.named("byte").compressed(), Fixtures.named("byte").compressed().length + 1);
        assertCorrupt(trailing, "truncated");
        byte[] skipTooLong = {0x50, 0x2A, 0x4D, 0x18, 10, 0, 0, 0, 1, 2};
        assertCorrupt(skipTooLong, "skippable");
        assertArrayEquals(new byte[0], ZSTD.decompress(new byte[] {0x5F, 0x2A, 0x4D, 0x18, 2, 0, 0, 0, 9, 9}));
    }

    @Test
    void reservedBlockTypeIsRejected() {
        // A single-segment frame of size 1 whose only block has type 3.
        byte[] data = {0x28, (byte) 0xB5, 0x2F, (byte) 0xFD, 0x20, 0x01, 0x0F, 0x00, 0x00};
        assertCorrupt(data, "reserved block type");
    }

    @Test
    void streamSemantics() throws IOException {
        byte[] data = Fixtures.named("two-frames").compressed();
        ZstdInputStream in = new ZstdInputStream(new ByteArrayInputStream(data));
        int first = in.read();
        assertTrue(first >= 0);
        assertTrue(in.available() > 0);
        byte[] rest = in.readAllBytes();
        assertEquals(Fixtures.named("two-frames").size(), 1 + rest.length);
        assertEquals(-1, in.read());
        in.close();
        assertThrows(IOException.class, in::read);
        assertEquals(0, in.available());
    }
}
