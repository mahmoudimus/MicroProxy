package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microproxy.ClientHello;
import org.microproxy.TlsHellos;

/** Finding and parsing ClientHellos: real ones from the JDK, fragmented, odd and malformed ones. */
class TlsClientHelloTest {

    private static byte[] jdkRecords;

    @BeforeAll
    static void captureJdkHello() throws Exception {
        jdkRecords = TlsHellos.fromJdkClient("example.com", "h2", "http/1.1");
    }

    /** Parses {@code records} as the proxy does after reading all of them. */
    private static ClientHello parseRecords(byte[] records) throws Exception {
        int[] need = new int[1];
        byte[] message = TlsClientHello.message(records, records.length, TlsClientHello.MAX_MESSAGE_SIZE, need);
        assertNotNull(message, "complete records give a message");
        return TlsClientHello.parse(message);
    }

    @Test
    void parsesTheJdkClientsHello() throws Exception {
        ClientHello hello = parseRecords(jdkRecords);
        assertEquals("example.com", hello.sni());
        assertEquals(List.of("h2", "http/1.1"), hello.alpnProtocols());
        assertTrue(hello.versionNames().containsAll(List.of("TLSv1.3", "TLSv1.2")), hello.versionNames().toString());
        assertTrue(hello.versions().contains(0x0304));
        assertTrue(hello.cipherSuites().contains(0x1301), "TLS_AES_128_GCM_SHA256 is offered");
        assertTrue(hello.extensionTypes().containsAll(List.of(0, 16, 43)), hello.extensionTypes().toString());
        assertArrayEquals(TlsHellos.message(jdkRecords), hello.raw());
        assertTrue(hello.offersAlpn("h2"));
        assertEquals(List.of("http/1.1"), hello.httpAlpnProtocols(false));
    }

    @Test
    void aJdkClientWithoutSniOrAlpn() throws Exception {
        ClientHello hello = parseRecords(TlsHellos.fromJdkClient(null));
        assertNull(hello.sni());
        assertEquals(List.of(), hello.alpnProtocols());
        assertFalse(hello.cipherSuites().isEmpty());
    }

    @Test
    void aHelloSplitAcrossRecordsAndReads() throws Exception {
        byte[] message = TlsHellos.message(jdkRecords);
        for (int recordSize : new int[] {1, 7, 100, 512, message.length}) {
            byte[] records = TlsHellos.records(message, recordSize);
            int[] need = new int[1];
            // Bytes arrive one at a time: the scan asks for more until the message is whole.
            int have = 0;
            byte[] found = null;
            while (found == null) {
                found = TlsClientHello.message(records, have, TlsClientHello.MAX_MESSAGE_SIZE, need);
                if (found == null) {
                    assertTrue(need[0] > have, "asks for more than it has");
                    assertTrue(need[0] <= records.length, "never asks for more than the hello's records");
                    have = Math.min(need[0], records.length);
                }
            }
            assertArrayEquals(message, found, "record size " + recordSize);
            assertEquals("example.com", TlsClientHello.parse(found).sni());
        }
    }

    @Test
    void readsThroughAByteReaderWithoutConsuming() throws Exception {
        byte[] message = TlsHellos.message(jdkRecords);
        // Records of 100 bytes, more than one pooled buffer (64 bytes here) in all.
        byte[] records = TlsHellos.records(message, 100);
        byte[] stream = Arrays.copyOf(records, records.length + 5);
        System.arraycopy("after".getBytes(StandardCharsets.US_ASCII), 0, stream, records.length, 5);
        BufferPool pool = new BufferPool(64, 4);
        ByteReader in = new ByteReader(new ByteArrayInputStream(stream), pool);
        int[] need = {5};
        byte[] found = null;
        while (found == null) {
            assertTrue(in.ensureBuffered(need[0]));
            byte[] buffered = in.peekBuffered();
            found = TlsClientHello.message(buffered, buffered.length, TlsClientHello.MAX_MESSAGE_SIZE, need);
        }
        assertArrayEquals(message, found);
        // Nothing was consumed: the same bytes come out again, then the rest of the stream.
        byte[] replay = new byte[stream.length];
        in.readFully(replay, 0, replay.length);
        assertArrayEquals(stream, replay);
        in.release();
        assertEquals(0, pool.outstanding(), "the pooled buffer went back");
    }

    @Test
    void greaseAlpnIsKeptButNotTakenForHttp() throws Exception {
        String grease = new String(new byte[] {0x0a, 0x0a}, StandardCharsets.ISO_8859_1);
        ClientHello hello = TlsClientHello.parse(
                TlsHellos.build(List.of("grease.test"), List.of(grease, "http/1.1"), 0x7a7a, 0x0304, 0x0303));
        assertEquals(List.of(grease, "http/1.1"), hello.alpnProtocols());
        assertEquals(List.of("http/1.1"), hello.httpAlpnProtocols(true));
        assertEquals(List.of("TLSv1.3", "TLSv1.2"), hello.versionNames());
        assertTrue(ClientHello.isGrease(0x7a7a));
        assertTrue(ClientHello.isGrease(0x0a0a));
        assertFalse(ClientHello.isGrease(0x0304));
        assertTrue(hello.cipherSuites().contains(0x0a0a), "GREASE cipher suites are reported as sent");
    }

    @Test
    void sniIsOnlyAValidSingleHostName() throws Exception {
        assertNull(TlsClientHello.parse(TlsHellos.build(List.of(), List.of("h2"))).sni());
        assertNull(TlsClientHello.parse(TlsHellos.build(List.of("a.test", "b.test"), null)).sni());
        assertNull(TlsClientHello.parse(TlsHellos.build(List.of("bad host"), null)).sni());
        assertNull(TlsClientHello.parse(TlsHellos.build(List.of("a..test"), null)).sni());
        assertEquals("under_score.test.", TlsClientHello.parse(TlsHellos.build(List.of("under_score.test."), null)).sni());
        // Without supported_versions, the legacy version is the offer.
        assertEquals(List.of(0x0303), TlsClientHello.parse(TlsHellos.build(List.of("a.test"), null)).versions());
    }

    @Test
    void notTls() {
        byte[] get = "GET / HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII);
        assertFalse(TlsClientHello.startsLikeTlsRecord(get, get.length));
        assertFalse(TlsClientHello.startsLikeTlsRecord(new byte[] {0x16, 0x02, 0x01}, 3));
        assertFalse(TlsClientHello.startsLikeTlsRecord(new byte[] {0x16, 0x03, 0x04}, 3));
        assertTrue(TlsClientHello.startsLikeTlsRecord(new byte[] {0x16, 0x03}, 2), "so far, so TLS");
        assertTrue(TlsClientHello.startsLikeTlsRecord(jdkRecords, jdkRecords.length));
        // A TLS record that holds another handshake message, or another content type.
        byte[] serverHello = TlsHellos.records(new byte[] {2, 0, 0, 1, 0}, 64);
        assertThrows(TlsClientHello.Malformed.class,
                () -> TlsClientHello.message(serverHello, serverHello.length, 1024, new int[1]));
        byte[] alert = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
        assertThrows(TlsClientHello.Malformed.class, () -> TlsClientHello.message(alert, alert.length, 1024, new int[1]));
        byte[] empty = {0x16, 0x03, 0x01, 0x00, 0x00};
        assertThrows(TlsClientHello.Malformed.class, () -> TlsClientHello.message(empty, empty.length, 1024, new int[1]));
    }

    @Test
    void theSizeIsBounded() {
        // A message that claims 1 MiB: refused from its header, before the records arrive.
        byte[] header = TlsHellos.records(new byte[] {1, 0x10, 0, 0}, 64);
        assertThrows(TlsClientHello.TooLarge.class,
                () -> TlsClientHello.message(header, header.length, TlsClientHello.MAX_MESSAGE_SIZE, new int[1]));
        // Within the bound, split into one-byte records, the message completes.
        byte[] fits = new byte[1004];
        fits[0] = 1;
        fits[2] = (byte) (1000 >> 8);
        fits[3] = (byte) 1000;
        byte[] records = TlsHellos.records(fits, 1);
        assertArrayEquals(fits, assertDoesNotThrow(() -> TlsClientHello.message(records, records.length, 1024, new int[1])));
        assertThrows(TlsClientHello.TooLarge.class, () -> TlsClientHello.message(records, records.length, 999, new int[1]));
    }

    @Test
    void malformedInputFailsCleanly() throws Exception {
        byte[] records = jdkRecords;
        Random random = new Random(20_261_010L);
        int parsed = 0;
        for (int i = 0; i < 20_000; i++) {
            byte[] mutated = records.clone();
            switch (i % 4) {
                case 0 -> { // flip bits
                    for (int j = 1 + random.nextInt(8); j > 0; j--) {
                        mutated[random.nextInt(mutated.length)] ^= (byte) (1 << random.nextInt(8));
                    }
                }
                case 1 -> mutated = Arrays.copyOf(mutated, random.nextInt(mutated.length)); // truncate
                case 2 -> { // random bytes after a valid record header
                    for (int j = 5; j < mutated.length; j++) mutated[j] = (byte) random.nextInt(256);
                }
                default -> { // overwrite a length field somewhere in the message
                    int at = 5 + random.nextInt(mutated.length - 7);
                    mutated[at] = (byte) random.nextInt(256);
                    mutated[at + 1] = (byte) random.nextInt(256);
                }
            }
            try {
                byte[] message = TlsClientHello.message(mutated, mutated.length, TlsClientHello.MAX_MESSAGE_SIZE, new int[1]);
                if (message != null) {
                    TlsClientHello.parse(message);
                    parsed++;
                }
            } catch (TlsClientHello.Malformed | TlsClientHello.TooLarge expected) {
                // refused cleanly
            }
        }
        assertTrue(parsed > 0, "some mutations still parse");
    }
}
