package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.Secrets;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.NewSessionTicket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/** Session tickets, PSK resumption and 0-RTT between in-memory client and server sessions. */
class ResumptionTest {

    /** A wall clock tests move by hand. */
    static final class Clock implements InstantSource {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }
    }

    private final Clock clock = new Clock();
    private final Ticketer ticketer = Ticketer.create(Duration.ofHours(1), clock);

    private TlsConfig.Builder client() {
        return HandshakeTest.client().clock(clock);
    }

    private TlsConfig.Builder server() {
        return HandshakeTest.server().clock(clock).sessionTickets(ticketer);
    }

    private Handshakes connect(TlsConfig client, TlsConfig server, SessionTicket ticket, Predicate<byte[]> params)
            throws QuicException {
        return connect(client, server, ticket, params, Handshakes.NONE);
    }

    private Handshakes connect(TlsConfig client, TlsConfig server, SessionTicket ticket, Predicate<byte[]> params,
            Handshakes.Tamper tamper) throws QuicException {
        Handshakes h = new Handshakes(TlsSession.client(client, HandshakeTest.HOST, Handshakes.CLIENT_PARAMS, ticket),
                TlsSession.server(server, Handshakes.SERVER_PARAMS, params), new Random(3), tamper);
        h.complete();
        assertTrue(h.client.isHandshakeComplete());
        assertTrue(h.server.isHandshakeComplete());
        for (EncryptionLevel level : List.of(EncryptionLevel.HANDSHAKE, EncryptionLevel.ONE_RTT)) {
            assertArrayEquals(h.clientSecrets.get(level).client(), h.serverSecrets.get(level).client());
            assertArrayEquals(h.clientSecrets.get(level).server(), h.serverSecrets.get(level).server());
        }
        return h;
    }

    private static List<SessionTicket> tickets(TlsSession client) {
        List<SessionTicket> out = new ArrayList<>();
        for (SessionTicket t; (t = client.pollNewTicket()) != null; ) out.add(t);
        return out;
    }

    /** A full handshake; returns the tickets the client got. */
    private List<SessionTicket> firstConnection(TlsConfig.Builder client, TlsConfig.Builder server) throws QuicException {
        Handshakes h = connect(client.build(), server.build(), null, null);
        assertFalse(h.client.isResumed());
        assertFalse(h.server.isResumed());
        return tickets(h.client);
    }

    @Test
    void serverIssuesTicketsAfterTheHandshake() throws Exception {
        List<SessionTicket> tickets = firstConnection(client(), server().earlyData(true));
        assertEquals(2, tickets.size());
        SessionTicket t = tickets.get(0);
        assertEquals(HandshakeTest.HOST, t.serverName());
        assertEquals("h3", t.alpn());
        assertEquals(CipherSuite.TLS_AES_128_GCM_SHA256, t.cipherSuite());
        assertTrue(t.allowsEarlyData());
        assertEquals(Duration.ofHours(1), t.lifetime());
        assertArrayEquals(Handshakes.SERVER_PARAMS, t.transportParameters());
        assertFalse(t.peerCertificates().isEmpty());
        assertFalse(java.util.Arrays.equals(t.ticket, tickets.get(1).ticket), "tickets differ");
        assertFalse(java.util.Arrays.equals(t.psk, tickets.get(1).psk), "PSKs differ by nonce");
    }

    @Test
    void noTicketsWithoutATicketer() throws Exception {
        assertTrue(firstConnection(client(), HandshakeTest.server()).isEmpty());
        assertTrue(firstConnection(client(), server().ticketsPerConnection(0)).isEmpty());
        assertFalse(firstConnection(client(), server()).get(0).allowsEarlyData(), "no 0-RTT unless enabled");
    }

    @Test
    void resumesWithATicket() throws Exception {
        SessionTicket ticket = firstConnection(client(), server()).get(0);
        clock.advance(Duration.ofMinutes(5));
        Handshakes h = connect(client().build(), server().build(), ticket, null);
        assertTrue(h.client.isResumed());
        assertTrue(h.server.isResumed());
        assertFalse(h.client.isEarlyDataOffered());
        assertFalse(h.client.isEarlyDataAccepted());
        assertNull(h.client.peerSignatureScheme(), "no CertificateVerify in a resumed handshake");
        assertEquals(ticket.peerCertificates(), h.client.peerCertificates());
        assertEquals("h3", h.server.negotiatedAlpn());
        assertEquals(HandshakeTest.HOST, h.server.serverName());
        assertArrayEquals(h.client.exportKeyingMaterial("EXPORTER-x", null, 16),
                h.server.exportKeyingMaterial("EXPORTER-x", null, 16));
        assertEquals(2, tickets(h.client).size(), "fresh tickets after a resumption");
    }

    @Test
    void earlyDataAccepted() throws Exception {
        SessionTicket ticket = firstConnection(client().earlyData(true), server().earlyData(true)).get(0);
        TlsSession client = TlsSession.client(client().earlyData(true).build(), HandshakeTest.HOST,
                Handshakes.CLIENT_PARAMS, ticket);
        Secrets early = client.nextSecrets();
        assertEquals(EncryptionLevel.ZERO_RTT, early.level(), "0-RTT keys at once");
        assertEquals(ticket.cipherSuite(), early.suite());
        assertNull(client.nextSecrets());
        assertTrue(client.isEarlyDataOffered());

        TlsSession server = TlsSession.server(server().earlyData(true).build(), Handshakes.SERVER_PARAMS,
                remembered -> java.util.Arrays.equals(remembered, Handshakes.SERVER_PARAMS));
        server.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(client.writeHandshake(EncryptionLevel.INITIAL)));
        Secrets serverEarly = server.nextSecrets();
        assertEquals(EncryptionLevel.ZERO_RTT, serverEarly.level(), "0-RTT keys before the handshake keys");
        assertArrayEquals(early.client(), serverEarly.client());
        assertEquals(EncryptionLevel.HANDSHAKE, server.nextSecrets().level());
        assertTrue(server.isEarlyDataAccepted());
        assertTrue(server.isResumed());

        client.readHandshake(EncryptionLevel.INITIAL, ByteBuffer.wrap(server.writeHandshake(EncryptionLevel.INITIAL)));
        assertFalse(client.isEarlyDataAccepted());
        client.readHandshake(EncryptionLevel.HANDSHAKE, ByteBuffer.wrap(server.writeHandshake(EncryptionLevel.HANDSHAKE)));
        assertTrue(client.isEarlyDataAccepted());
        assertTrue(client.isResumed());
        assertTrue(client.isHandshakeComplete());
    }

    @Test
    void earlyDataRejectedWhenTheServerHasItOff() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        Handshakes h = connect(client().earlyData(true).build(), server().build(), ticket, null);
        assertTrue(h.client.isEarlyDataOffered());
        assertNotNull(h.clientSecrets.get(EncryptionLevel.ZERO_RTT));
        assertNull(h.serverSecrets.get(EncryptionLevel.ZERO_RTT));
        assertTrue(h.client.isResumed(), "resumed all the same");
        assertFalse(h.client.isEarlyDataAccepted());
        assertFalse(h.server.isEarlyDataAccepted());
    }

    @Test
    void clientWithoutEarlyDataDoesNotOfferIt() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        Handshakes h = connect(client().build(), server().earlyData(true).build(), ticket, null);
        assertFalse(h.client.isEarlyDataOffered());
        assertNull(h.clientSecrets.get(EncryptionLevel.ZERO_RTT));
        assertTrue(h.client.isResumed());
    }

    @Test
    void replayedTicketGetsNoEarlyData() throws Exception {
        TlsConfig serverConfig = server().earlyData(true).build();
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        Handshakes first = connect(client().earlyData(true).build(), serverConfig, ticket, null);
        assertTrue(first.server.isEarlyDataAccepted());
        // The same ticket again, as a replayed first flight would bring it
        Handshakes replay = connect(client().earlyData(true).build(), serverConfig, ticket, null);
        assertTrue(replay.server.isResumed(), "the handshake itself is not replayable, so it may resume");
        assertFalse(replay.server.isEarlyDataAccepted());
        assertFalse(replay.client.isEarlyDataAccepted());
    }

    @Test
    void staleTicketAgeGetsNoEarlyData() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        TlsConfig serverConfig = server().earlyData(true).build();
        // The client's age is frozen in its ClientHello, the server's moves on: as with a late replay
        TlsSession client = TlsSession.client(client().earlyData(true).build(), HandshakeTest.HOST,
                Handshakes.CLIENT_PARAMS, ticket);
        clock.advance(Duration.ofSeconds(30));
        TlsSession server = TlsSession.server(serverConfig, Handshakes.SERVER_PARAMS);
        Handshakes h = new Handshakes(client, server, new Random(1), Handshakes.NONE);
        h.complete();
        assertTrue(server.isResumed());
        assertFalse(server.isEarlyDataAccepted());
        assertFalse(client.isEarlyDataAccepted());
    }

    @Test
    void expiredTicketMakesAFullHandshake() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        TlsSession client = TlsSession.client(client().earlyData(true).build(), HandshakeTest.HOST,
                Handshakes.CLIENT_PARAMS, ticket);
        assertTrue(client.isEarlyDataOffered());
        clock.advance(Duration.ofHours(1).plusSeconds(1));
        Handshakes h = new Handshakes(client, TlsSession.server(server().earlyData(true).build(),
                Handshakes.SERVER_PARAMS), new Random(1), Handshakes.NONE);
        h.complete();
        assertFalse(h.server.isResumed());
        assertFalse(h.client.isResumed());
        assertFalse(h.client.isEarlyDataAccepted());
        assertNotNull(h.client.peerSignatureScheme(), "a full handshake");

        // A client does not offer an expired ticket at all
        TlsSession late = TlsSession.client(client().earlyData(true).build(), HandshakeTest.HOST,
                Handshakes.CLIENT_PARAMS, ticket);
        assertFalse(late.isEarlyDataOffered());
        assertNull(late.nextSecrets());
    }

    @Test
    void anotherServersTicketMakesAFullHandshake() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        TlsConfig other = HandshakeTest.server().clock(clock).earlyData(true)
                .sessionTickets(Ticketer.create(Duration.ofHours(1), clock)).build();
        Handshakes h = connect(client().earlyData(true).build(), other, ticket, null);
        assertFalse(h.server.isResumed());
        assertFalse(h.client.isEarlyDataAccepted());
    }

    @Test
    void ticketForAnotherServerNameIsNotOffered() throws Exception {
        SessionTicket ticket = firstConnection(client(), server()).get(0);
        TlsSession client = TlsSession.client(client().verifyHostname(false).build(), "other.test",
                Handshakes.CLIENT_PARAMS, ticket);
        Handshakes h = new Handshakes(client, TlsSession.server(server().build(), Handshakes.SERVER_PARAMS),
                new Random(1), Handshakes.NONE);
        h.complete();
        assertFalse(h.client.isResumed());
    }

    @Test
    void alpnChangeRejectsEarlyData() throws Exception {
        SessionTicket ticket = firstConnection(client().alpnProtocols("h3", "other"),
                server().alpnProtocols("h3", "other")).get(0);
        assertEquals("h3", ticket.alpn());
        Handshakes h = connect(client().alpnProtocols("h3", "other").earlyData(true).build(),
                server().alpnProtocols("other", "h3").earlyData(true).build(), ticket, null);
        assertEquals("other", h.client.negotiatedAlpn());
        assertTrue(h.client.isResumed());
        assertFalse(h.server.isEarlyDataAccepted());
        assertFalse(h.client.isEarlyDataAccepted());
    }

    @Test
    void transportParameterCheckRejectsEarlyData() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        AtomicInteger asked = new AtomicInteger();
        Handshakes h = connect(client().earlyData(true).build(), server().earlyData(true).build(), ticket,
                remembered -> {
                    asked.incrementAndGet();
                    assertArrayEquals(Handshakes.SERVER_PARAMS, remembered);
                    return false;
                });
        assertEquals(1, asked.get());
        assertTrue(h.server.isResumed());
        assertFalse(h.client.isEarlyDataAccepted());
    }

    @Test
    void applicationVetoAndFailingPolicy() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        List<EarlyDataAttempt> seen = new ArrayList<>();
        EarlyDataPolicy veto = attempt -> {
            seen.add(attempt);
            return false;
        };
        Handshakes h = connect(client().earlyData(true).build(),
                server().earlyData(true).earlyDataPolicy(EarlyDataPolicy.antiReplay().and(veto)).build(), ticket, null);
        assertFalse(h.client.isEarlyDataAccepted());
        assertEquals(1, seen.size());
        assertEquals("h3", seen.get(0).alpn());
        assertEquals(HandshakeTest.HOST, seen.get(0).serverName());
        assertTrue(seen.get(0).ageSkew().toMillis() < 1000);

        SessionTicket next = firstConnection(client(), server().earlyData(true)).get(0);
        Handshakes failing = connect(client().earlyData(true).build(), server().earlyData(true)
                .earlyDataPolicy(attempt -> {
                    throw new IllegalStateException("boom");
                }).build(), next, null);
        assertTrue(failing.server.isResumed());
        assertFalse(failing.client.isEarlyDataAccepted());
    }

    @Test
    void helloRetryRequestDropsEarlyDataButResumes() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        Handshakes h = connect(client().groups(NamedGroup.SECP256R1, NamedGroup.X25519).earlyData(true).build(),
                server().groups(NamedGroup.X25519).earlyData(true).build(), ticket, null);
        assertTrue(h.client.usedHelloRetryRequest());
        assertTrue(h.client.isEarlyDataOffered());
        assertTrue(h.server.isResumed());
        assertFalse(h.server.isEarlyDataAccepted());
        assertFalse(h.client.isEarlyDataAccepted());
    }

    @Test
    void retryToASuiteOfAnotherHashDropsThePsk() throws Exception {
        SessionTicket ticket = firstConnection(client(), server()).get(0);
        assertEquals(CipherSuite.TLS_AES_128_GCM_SHA256, ticket.cipherSuite());
        Handshakes h = connect(client().groups(NamedGroup.SECP256R1, NamedGroup.X25519).build(),
                server().groups(NamedGroup.X25519).cipherSuites(CipherSuite.TLS_AES_256_GCM_SHA384).build(), ticket, null);
        assertTrue(h.client.usedHelloRetryRequest());
        assertFalse(h.client.isResumed());
        assertEquals(CipherSuite.TLS_AES_256_GCM_SHA384, h.client.cipherSuite());
    }

    @Test
    void suiteOfTheSameHashResumesWithoutEarlyData() throws Exception {
        SessionTicket ticket = firstConnection(client(), server().earlyData(true)).get(0);
        Handshakes h = connect(client().earlyData(true).build(), server().earlyData(true)
                .cipherSuites(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256).build(),
                ticket, null);
        assertEquals(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, h.client.cipherSuite());
        assertTrue(h.client.isResumed());
        assertFalse(h.client.isEarlyDataAccepted(), "0-RTT needs the very suite of the ticket");
    }

    @Test
    void badBinderIsDecryptError() throws Exception {
        SessionTicket ticket = firstConnection(client(), server()).get(0);
        Handshakes.Tamper flipLastByte = (fromServer, level, bytes) -> {
            if (!fromServer && level == EncryptionLevel.INITIAL) {
                bytes = bytes.clone();
                bytes[bytes.length - 1] ^= 1; // the end of the binder
            }
            return bytes;
        };
        QuicException e = assertThrows(QuicException.class,
                () -> connect(client().build(), server().build(), ticket, null, flipLastByte));
        assertEquals(TlsAlert.DECRYPT_ERROR, Handshakes.alert(e));
    }

    @Test
    void noResumptionWithClientAuthentication() throws Exception {
        TlsConfig.Builder authServer = server().clientAuth(ClientAuth.REQUEST)
                .clientTrustManager(TestCerts.CA.trustManager());
        assertTrue(firstConnection(client(), authServer).isEmpty(), "no tickets");
    }

    @Test
    void clientChecksTickets() throws Exception {
        Handshakes h = connect(client().build(), HandshakeTest.server().build(), null, null);
        byte[] tooLong = new NewSessionTicket(604801, 1, new byte[] {0}, new byte[] {1}, List.of()).encode();
        QuicException e = assertThrows(QuicException.class,
                () -> h.client.readHandshake(EncryptionLevel.ONE_RTT, ByteBuffer.wrap(tooLong)));
        assertEquals(TlsAlert.ILLEGAL_PARAMETER, Handshakes.alert(e));

        Handshakes h2 = connect(client().build(), HandshakeTest.server().build(), null, null);
        byte[] tlsEarlyData = new NewSessionTicket(60, 1, new byte[] {0}, new byte[] {1}, List.of(
                new Extension(ExtensionType.EARLY_DATA, Extensions.encodeMaxEarlyDataSize(1024)))).encode();
        QuicException e2 = assertThrows(QuicException.class,
                () -> h2.client.readHandshake(EncryptionLevel.ONE_RTT, ByteBuffer.wrap(tlsEarlyData)));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e2.code());

        Handshakes h3 = connect(client().build(), HandshakeTest.server().build(), null, null);
        byte[] zeroLifetime = new NewSessionTicket(0, 1, new byte[] {0}, new byte[] {1}, List.of()).encode();
        h3.client.readHandshake(EncryptionLevel.ONE_RTT, ByteBuffer.wrap(zeroLifetime));
        assertNull(h3.client.pollNewTicket(), "a zero lifetime ticket is discarded");
    }

    // --- the ticketer ---

    @Test
    void ticketerRotatesKeys() {
        Ticketer t = Ticketer.create(Duration.ofSeconds(10), clock);
        byte[] one = t.encrypt("ticket 1".getBytes());
        assertArrayEquals("ticket 1".getBytes(), t.decrypt(one));
        clock.advance(Duration.ofSeconds(11)); // rotates: one is the previous key's
        byte[] two = t.encrypt("ticket 2".getBytes());
        assertArrayEquals("ticket 1".getBytes(), t.decrypt(one));
        assertArrayEquals("ticket 2".getBytes(), t.decrypt(two));
        clock.advance(Duration.ofSeconds(11)); // rotates again: one's key is gone
        byte[] three = t.encrypt("ticket 3".getBytes());
        assertNull(t.decrypt(one));
        assertArrayEquals("ticket 2".getBytes(), t.decrypt(two));
        assertArrayEquals("ticket 3".getBytes(), t.decrypt(three));
    }

    @Test
    void ticketerRejectsTamperedAndForeignTickets() {
        Ticketer t = Ticketer.create(Duration.ofSeconds(10), clock);
        byte[] sealed = t.encrypt(new byte[40]);
        assertEquals(16 + 12 + 40 + 16, sealed.length);
        for (int i : new int[] {0, 20, 40, sealed.length - 1}) {
            byte[] bad = sealed.clone();
            bad[i] ^= 1;
            assertNull(t.decrypt(bad), "flipped byte " + i);
        }
        assertNull(t.decrypt(new byte[10]));
        assertNull(t.decrypt(java.util.Arrays.copyOf(sealed, sealed.length + 1)), "longer than any ticket sealed");
        assertNull(Ticketer.create(Duration.ofSeconds(10), clock).decrypt(sealed));
        assertThrows(IllegalArgumentException.class, () -> Ticketer.create(Duration.ofDays(8), clock));
    }

    // --- the client's cache ---

    @Test
    void memoryCacheIsBoundedAndSingleUse() throws Exception {
        List<SessionTicket> tickets = firstConnection(client(), server().ticketsPerConnection(10));
        ClientSessionMemoryCache cache = new ClientSessionMemoryCache(2);
        for (SessionTicket t : tickets) cache.put("a", t);
        assertEquals(ClientSessionMemoryCache.MAX_TICKETS_PER_SERVER, cache.size("a"));
        assertTrue(cache.take("a") == tickets.get(9), "newest first");
        assertEquals(7, cache.size("a"));
        cache.put("b", tickets.get(0));
        cache.put("c", tickets.get(1)); // evicts "a", the server added first
        assertEquals(0, cache.size("a"));
        assertNull(cache.take("a"));
        assertTrue(cache.take("b") == tickets.get(0));
        assertNull(cache.take("b"), "single use");
        assertNull(new ClientSessionMemoryCache(0).take("x"));
        ClientSessionMemoryCache none = new ClientSessionMemoryCache(0);
        none.put("x", tickets.get(0));
        assertNull(none.take("x"));
    }

    // --- the anti-replay policy ---

    private static EarlyDataAttempt attempt(byte id, long clientMillis, long serverMillis) {
        return new EarlyDataAttempt("s", "h3", new byte[] {id}, Instant.EPOCH, Duration.ofMillis(clientMillis),
                Duration.ofMillis(serverMillis));
    }

    @Test
    void antiReplayWindowAndSingleUse() {
        AtomicLong nanos = new AtomicLong();
        AntiReplay policy = new AntiReplay(Duration.ofSeconds(10), 3, nanos::get);
        assertFalse(policy.accept(attempt((byte) 1, 1000, 12_000)), "ages 11 s apart");
        assertTrue(policy.accept(attempt((byte) 1, 1000, 10_900)));
        assertFalse(policy.accept(attempt((byte) 1, 1000, 1000)), "the same ticket again");
        assertTrue(policy.accept(attempt((byte) 2, 5000, 5000)));
        assertTrue(policy.accept(attempt((byte) 3, 5000, 5000)));
        assertFalse(policy.accept(attempt((byte) 4, 5000, 5000)), "full: refuse rather than forget");
        nanos.addAndGet(Duration.ofSeconds(21).toNanos());
        assertTrue(policy.accept(attempt((byte) 4, 5000, 5000)), "expired entries make room");
        assertEquals(1, policy.size());
        assertTrue(policy.accept(attempt((byte) 1, 5000, 5000)), "forgotten after twice the window");
    }
}
