/*
 * The round-trip and invalid-token tests are ported from quinn-proto src/token.rs (tests), and
 * the log tests from src/bloom_token_log.rs (tests) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class TokenTest {

    private static final Random RNG = new Random(0xdeadbeefL);

    /** A settable wall clock. */
    static final class FakeInstantSource implements InstantSource {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static TokenKey key() {
        byte[] master = new byte[64];
        RNG.nextBytes(master);
        return new TokenKey(master);
    }

    private static TokenPayload roundTrip(TokenPayload payload) {
        Token token = Token.create(payload, RNG);
        TokenKey key = key();
        byte[] encoded = token.encode(key);
        Token decoded = Token.decode(key, encoded);
        assertNotNull(decoded, "token didn't decrypt or decode");
        assertArrayEquals(token.nonce(), decoded.nonce());
        return decoded.payload();
    }

    @Test
    void retryTokenSanity() throws Exception {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getByName("::1"), 4433);
        ConnectionId cid = ConnectionId.random(RNG, 20);
        Instant issued = Instant.EPOCH.plusSeconds(42);
        TokenPayload.Retry back = assertInstanceOf(TokenPayload.Retry.class,
                roundTrip(new TokenPayload.Retry(address, cid, issued)));
        assertEquals(address, back.address());
        assertEquals(cid, back.originalDestinationId());
        assertEquals(issued, back.issued());
    }

    @Test
    void validationTokenSanity() throws Exception {
        InetAddress ip = InetAddress.getByName("::1");
        Instant issued = Instant.EPOCH.plusSeconds(42);
        TokenPayload.Validation back = assertInstanceOf(TokenPayload.Validation.class,
                roundTrip(new TokenPayload.Validation(ip, issued)));
        assertEquals(ip, back.ip());
        assertEquals(issued, back.issued());
    }

    @Test
    void ipv4AndEmptyCidRoundTrip() throws Exception {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getByName("192.0.2.7"), 65535);
        TokenPayload.Retry back = assertInstanceOf(TokenPayload.Retry.class,
                roundTrip(new TokenPayload.Retry(address, ConnectionId.EMPTY, Instant.EPOCH.plusMillis(1500))));
        assertEquals(address, back.address());
        assertEquals(ConnectionId.EMPTY, back.originalDestinationId());
        assertEquals(Instant.EPOCH.plusSeconds(1), back.issued(), "fractions of a second are dropped");
    }

    @Test
    void invalidTokenReturnsNull() {
        byte[] garbage = new byte[32];
        RNG.nextBytes(garbage);
        assertNull(Token.decode(key(), garbage));
        assertNull(Token.decode(key(), new byte[3]));
    }

    @Test
    void tamperedOrForeignTokensDoNotOpen() throws Exception {
        TokenKey key = key();
        byte[] encoded = Token.create(new TokenPayload.Validation(InetAddress.getByName("10.0.0.1"), Instant.EPOCH),
                RNG).encode(key);
        assertNotNull(Token.decode(key, encoded));
        assertNull(Token.decode(key(), encoded), "another server's key");
        for (int i = 0; i < encoded.length; i++) {
            byte[] tampered = encoded.clone();
            tampered[i] ^= 1;
            assertNull(Token.decode(key, tampered), "bit flipped at " + i);
        }
        assertThrows(IllegalArgumentException.class, () -> new TokenKey(new byte[16]));
    }

    // ---- validation ----

    private final FakeInstantSource clock = new FakeInstantSource();
    private final TokenKey serverKey = key();

    private TokenValidator validator(TokenLog log) {
        return new TokenValidator(serverKey, clock, TokenValidator.DEFAULT_RETRY_TOKEN_LIFETIME,
                TokenValidator.DEFAULT_VALIDATION_TOKEN_LIFETIME, log, RNG);
    }

    @Test
    void retryTokenValidatesItsClientUntilExpiry() throws Exception {
        TokenValidator v = validator(TokenLog.NONE);
        InetSocketAddress client = new InetSocketAddress(InetAddress.getByName("198.51.100.1"), 5000);
        ConnectionId odcid = ConnectionId.of(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
        ConnectionId retryScid = ConnectionId.of(new byte[] {9, 9, 9, 9});
        byte[] token = v.retryToken(client, odcid);

        IncomingToken in = v.validate(token, retryScid, client);
        assertTrue(in.validated());
        assertEquals(odcid, in.originalDestinationId());
        assertEquals(retryScid, in.retrySourceId());

        // Another port: an authentic token from the wrong address fails the connection
        QuicException e = assertThrows(QuicException.class,
                () -> v.validate(token, retryScid, new InetSocketAddress(client.getAddress(), 5001)));
        assertEquals(QuicException.INVALID_TOKEN, e.code());

        clock.now = clock.now.plusSeconds(15);
        assertTrue(v.validate(token, retryScid, client).validated(), "valid for exactly its lifetime");
        clock.now = clock.now.plusSeconds(1);
        e = assertThrows(QuicException.class, () -> v.validate(token, retryScid, client));
        assertEquals(QuicException.INVALID_TOKEN, e.code());
    }

    @Test
    void newTokenValidatesItsIpOnceWithinItsLifetime() throws Exception {
        TokenValidator v = validator(new BloomTokenLog());
        InetAddress ip = InetAddress.getByName("2001:db8::1");
        byte[] token = v.validationToken(ip);
        ConnectionId dcid = ConnectionId.of(new byte[] {7, 7, 7, 7, 7, 7, 7, 7});

        IncomingToken in = v.validate(token, dcid, new InetSocketAddress(ip, 1234));
        assertTrue(in.validated(), "any port of the same address");
        assertNull(in.retrySourceId());
        assertEquals(dcid, in.originalDestinationId());
        assertFalse(v.validate(token, dcid, new InetSocketAddress(ip, 1234)).validated(), "a replay");

        byte[] other = v.validationToken(ip);
        assertFalse(v.validate(other, dcid, new InetSocketAddress(InetAddress.getByName("2001:db8::2"), 1234))
                .validated(), "another address");
        clock.now = clock.now.plus(Duration.ofDays(14)).plusSeconds(1);
        assertFalse(v.validate(other, dcid, new InetSocketAddress(ip, 1234)).validated(), "expired");
    }

    @Test
    void missingOrForeignTokensLeaveTheClientUnvalidated() throws Exception {
        TokenValidator v = validator(TokenLog.NONE);
        ConnectionId dcid = ConnectionId.of(new byte[] {1, 1, 1, 1, 1, 1, 1, 1});
        InetSocketAddress client = new InetSocketAddress(InetAddress.getByName("192.0.2.1"), 443);
        assertEquals(IncomingToken.unvalidated(dcid), v.validate(new byte[0], dcid, client));
        byte[] foreign = Token.create(new TokenPayload.Retry(client, dcid, clock.now), RNG).encode(key());
        assertEquals(IncomingToken.unvalidated(dcid), v.validate(foreign, dcid, client));
        // With the null log, NEW_TOKEN tokens never validate
        assertFalse(v.validate(v.validationToken(client.getAddress()), dcid, client).validated());
    }

    // ---- BloomTokenLog ----

    private static byte[] nonce() {
        byte[] n = new byte[16];
        RNG.nextBytes(n);
        return n;
    }

    @Test
    void optimalKNum() {
        assertEquals(58, BloomTokenLog.optimalKNum(10 << 20, 1_000_000));
        assertEquals(1, BloomTokenLog.optimalKNum(10 << 20, 1_000_000_000_000_000L));
        BloomTokenLog.optimalKNum(10 << 20, 0);
        BloomTokenLog.optimalKNum(Long.MAX_VALUE, 1_000_000);
    }

    @Test
    void bloomTokenLogConversion() {
        BloomTokenLog log = BloomTokenLog.withExpectedItems(800, 200);
        Instant issued = Instant.parse("2026-01-01T00:00:00Z");
        Duration lifetime = Duration.ofSeconds(1_000_000);
        for (int i = 0; i < 200; i++) {
            byte[] token = nonce();
            boolean accepted = log.checkAndInsert(token, issued, lifetime);
            if (!log.filter1.isBloom()) {
                assertEquals(i + 1, log.filter1.set.size());
                assertTrue(accepted);
            } else {
                assertTrue(i > 10, "bloomed too early");
            }
            assertFalse(log.checkAndInsert(token, issued, lifetime), "a reuse is refused");
        }
        assertTrue(log.filter1.isBloom(), "didn't bloom");
    }

    @Test
    void turnOver() {
        BloomTokenLog log = BloomTokenLog.withExpectedItems(800, 200);
        Duration lifetime = Duration.ofSeconds(1_000);
        List<Object[]> old = new ArrayList<>();
        int accepted = 0;
        for (int i = 0; i < 200; i++) {
            byte[] token = nonce();
            Instant now = Instant.EPOCH.plus(lifetime.multipliedBy(10)).plus(lifetime.multipliedBy(i).dividedBy(10));
            Instant issued = now.minusMillis((long) (lifetime.toMillis() * RNG.nextDouble() * 3));
            if (log.checkAndInsert(token, issued, lifetime)) {
                accepted++;
            }
            old.add(new Object[] {token, issued});
            Object[] pick = old.get(RNG.nextInt(old.size()));
            assertFalse(log.checkAndInsert((byte[]) pick[0], (Instant) pick[1], lifetime));
        }
        assertTrue(accepted > 0);
    }

    @Test
    void degenerateParametersDoNotFail() {
        for (BloomTokenLog log : new BloomTokenLog[] {BloomTokenLog.withExpectedItems(0, 200),
                BloomTokenLog.withExpectedItems(100, 0), new BloomTokenLog(100, 0)}) {
            Instant issued = Instant.parse("2026-01-01T00:00:00Z");
            for (int i = 0; i < 200; i++) {
                log.checkAndInsert(nonce(), issued, Duration.ofSeconds(1_000_000));
            }
            assertFalse(log.checkAndInsert(nonce(), issued, Duration.ZERO));
        }
    }
}
