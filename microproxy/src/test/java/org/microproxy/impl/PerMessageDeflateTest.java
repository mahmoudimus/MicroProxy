package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import org.junit.jupiter.api.Test;
import org.microproxy.WebSocketPeer;
import org.microproxy.http.HttpHeaders;

/** Parsing permessage-deflate parameters, and the compressor and decompressor the relay uses. */
class PerMessageDeflateTest {

    private static List<String> elements(String header) {
        return HttpHeaders.splitList(header);
    }

    @Test
    void offersKeepOnlyPermessageDeflateWithKnownParameters() {
        assertEquals("permessage-deflate; client_max_window_bits, permessage-deflate",
                PerMessageDeflate.supportedOffers(elements("x-webkit-deflate-frame, permessage-deflate; client_max_window_bits,"
                        + " permessage-deflate; foo=1, permessage-deflate")));
        assertEquals("permessage-deflate; server_no_context_takeover; client_no_context_takeover;"
                + " server_max_window_bits=10; client_max_window_bits=\"9\"",
                PerMessageDeflate.supportedOffers(elements("permessage-deflate; server_no_context_takeover;"
                        + " client_no_context_takeover; server_max_window_bits=10; client_max_window_bits=\"9\"")));
        // Out-of-range or missing values, values on flags and repeats make an offer unusable.
        for (String bad : List.of("permessage-deflate; server_max_window_bits=16", "permessage-deflate; server_max_window_bits",
                "permessage-deflate; client_max_window_bits=7", "permessage-deflate; server_no_context_takeover=1",
                "permessage-deflate; client_no_context_takeover; client_no_context_takeover", "x-other")) {
            assertNull(PerMessageDeflate.supportedOffers(elements(bad)), bad);
        }
        assertNull(PerMessageDeflate.supportedOffers(List.of()));
    }

    @Test
    void answersGiveTheAgreedParameters() throws Exception {
        assertNull(PerMessageDeflate.agreed(List.of()));
        assertEquals(PerMessageDeflate.Params.DEFAULT, PerMessageDeflate.agreed(elements("permessage-deflate")));
        assertEquals(new PerMessageDeflate.Params(true, true, 10, 9), PerMessageDeflate.agreed(elements(
                "Permessage-Deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=10;"
                        + " client_max_window_bits=9")));
        // A valueless client_max_window_bits in an answer is read as no limit.
        assertEquals(PerMessageDeflate.Params.DEFAULT, PerMessageDeflate.agreed(elements("permessage-deflate; client_max_window_bits")));
        assertThrows(PerMessageDeflate.UnsupportedException.class,
                () -> PerMessageDeflate.agreed(elements("permessage-deflate, x-other")));
        assertThrows(PerMessageDeflate.UnsupportedException.class, () -> PerMessageDeflate.agreed(elements("x-other")));
        assertThrows(PerMessageDeflate.UnsupportedException.class,
                () -> PerMessageDeflate.agreed(elements("permessage-deflate; mystery")));
    }

    private static byte[] inflate(PerMessageDeflate.Decompressor d, byte[] data, int limit) throws Exception {
        PerMessageDeflate.Buffer out = new PerMessageDeflate.Buffer(16);
        d.inflate(data, true, out, limit);
        return out.toArray();
    }

    private static byte[] deflate(PerMessageDeflate.Compressor c, byte[] data) {
        return c.deflate(data, 0, data.length, true).toArray();
    }

    @Test
    void withContextTakeoverLaterMessagesReferToEarlierOnes() throws Exception {
        PerMessageDeflate.Compressor c = new PerMessageDeflate.Compressor(false, 15);
        PerMessageDeflate.Decompressor d = new PerMessageDeflate.Decompressor(false);
        byte[] message = "the quick brown fox jumps over the lazy dog, again and again".getBytes(StandardCharsets.UTF_8);
        byte[] first = deflate(c, message);
        byte[] second = deflate(c, message);
        assertTrue(second.length < first.length / 2, first.length + " then " + second.length);
        assertArrayEquals(message, inflate(d, first, 1000));
        assertArrayEquals(message, inflate(d, second, 1000));
        // A fresh decompressor cannot read the second message on its own.
        assertThrows(DataFormatException.class, () -> inflate(new PerMessageDeflate.Decompressor(false), second, 1000));
        c.end();
        d.end();
    }

    @Test
    void withoutContextTakeoverEachMessageStandsAlone() throws Exception {
        PerMessageDeflate.Compressor c = new PerMessageDeflate.Compressor(true, 15);
        byte[] message = "the quick brown fox jumps over the lazy dog, again and again".getBytes(StandardCharsets.UTF_8);
        byte[] first = deflate(c, message);
        byte[] second = deflate(c, message);
        assertArrayEquals(first, second);
        PerMessageDeflate.Decompressor d = new PerMessageDeflate.Decompressor(true);
        assertArrayEquals(message, inflate(d, first, 1000));
        assertArrayEquals(message, inflate(d, second, 1000));
        assertArrayEquals(message, inflate(new PerMessageDeflate.Decompressor(true), second, 1000));
    }

    @Test
    void framesOfAMessageCompressAndInflateOneAtATime() throws Exception {
        PerMessageDeflate.Compressor c = new PerMessageDeflate.Compressor(false, 15);
        PerMessageDeflate.Decompressor d = new PerMessageDeflate.Decompressor(false);
        byte[] whole = "abcabcabcabc-defdefdef-abcabc".getBytes(StandardCharsets.UTF_8);
        PerMessageDeflate.Buffer out = new PerMessageDeflate.Buffer(16);
        for (int off = 0; off < whole.length; off += 10) {
            int len = Math.min(10, whole.length - off);
            boolean last = off + len == whole.length;
            byte[] part = c.deflate(whole, off, len, last).toArray();
            d.inflate(part, last, out, 1000);
        }
        assertArrayEquals(whole, out.toArray());
    }

    @Test
    void underFifteenWindowBitsTheCompressorMakesNoBackReferences() {
        byte[] block = new byte[2048];
        new Random(5).nextBytes(block);
        byte[] message = new byte[block.length * 4];
        for (int i = 0; i < 4; i++) System.arraycopy(block, 0, message, i * block.length, block.length);
        // A full window refers back 2 KiB, more than a 10-bit (1 KiB) window holds.
        byte[] full = deflate(new PerMessageDeflate.Compressor(false, 15), message);
        assertEquals(2048, WebSocketPeer.maxDistance(full));
        for (int bits = 8; bits < 15; bits++) {
            PerMessageDeflate.Compressor small = new PerMessageDeflate.Compressor(false, bits);
            byte[] first = deflate(small, message);
            byte[] second = deflate(small, message);
            assertEquals(0, WebSocketPeer.maxDistance(first), "bits " + bits);
            assertEquals(0, WebSocketPeer.maxDistance(second), "bits " + bits);
        }
        // Huffman coding still compresses text.
        byte[] text = "aaaaaaaaaabbbbbcccdd".repeat(100).getBytes(StandardCharsets.UTF_8);
        byte[] huffman = deflate(new PerMessageDeflate.Compressor(false, 9), text);
        assertTrue(huffman.length < text.length / 3, huffman.length + " of " + text.length);
    }

    @Test
    void inflatingStopsAtTheLimit() throws Exception {
        byte[] zeros = new byte[1 << 20];
        byte[] bomb = deflate(new PerMessageDeflate.Compressor(false, 15), zeros);
        assertTrue(bomb.length < 2000, "a megabyte of zeros compresses to " + bomb.length + " bytes");
        PerMessageDeflate.Decompressor d = new PerMessageDeflate.Decompressor(false);
        assertThrows(PerMessageDeflate.TooBigException.class, () -> inflate(d, bomb, 64 * 1024));
        assertEquals(zeros.length, inflate(new PerMessageDeflate.Decompressor(false), bomb, zeros.length).length);
    }

    @Test
    void aMessageEndingWithAFinalBlockResetsTheDecompressor() throws Exception {
        // Some senders finish each message (BFINAL); the next one starts a new stream.
        Deflater finishing = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] message = "finished message".getBytes(StandardCharsets.UTF_8);
        byte[][] compressed = new byte[2][];
        for (int i = 0; i < 2; i++) {
            finishing.reset();
            finishing.setInput(message);
            finishing.finish();
            byte[] buf = new byte[256];
            compressed[i] = Arrays.copyOf(buf, finishing.deflate(buf));
        }
        PerMessageDeflate.Decompressor d = new PerMessageDeflate.Decompressor(false);
        assertArrayEquals(message, inflate(d, compressed[0], 1000));
        assertArrayEquals(message, inflate(d, compressed[1], 1000));
    }

    @Test
    void invalidDataIsAFormatError() {
        PerMessageDeflate.Decompressor d = new PerMessageDeflate.Decompressor(false);
        assertThrows(DataFormatException.class, () -> inflate(d, new byte[] {(byte) 0xff, (byte) 0xff, 0x13}, 1000));
    }
}
