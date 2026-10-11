/*
 * Ported from quinn-proto src/token.rs (IncomingToken::from_header) and the token issuance of
 * src/endpoint.rs and src/connection/mod.rs, with the lifetimes of src/config/mod.rs
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Objects;
import java.util.random.RandomGenerator;

/**
 * Issues and checks a server's address validation tokens (RFC 9000 section 8.1): Retry tokens,
 * bound to the client's address and port and valid for {@code retryTokenLifetime}, and NEW_TOKEN
 * tokens, bound to its IP address, valid for {@code validationTokenLifetime} and logged against
 * reuse.
 *
 * <p>A token the server cannot open is ignored, since it may come from another server or version
 * (RFC 9000 section 8.1.3); but an authentic Retry token that does not match the client's address
 * or has expired fails the connection with {@code INVALID_TOKEN}.
 *
 * <p>Wall-clock time comes from an injectable {@link InstantSource}, so tests can control expiry.
 *
 * <p><b>Threads.</b> Safe to share if the {@link TokenLog} and random source are; the endpoint
 * layer must serialize calls when they are not, as with {@link BloomTokenLog}.
 */
public final class TokenValidator {

    /** quinn's default Retry token lifetime, 15 seconds. */
    public static final Duration DEFAULT_RETRY_TOKEN_LIFETIME = Duration.ofSeconds(15);
    /** quinn's default NEW_TOKEN token lifetime, two weeks. */
    public static final Duration DEFAULT_VALIDATION_TOKEN_LIFETIME = Duration.ofDays(14);

    private final TokenKey key;
    private final InstantSource clock;
    private final Duration retryTokenLifetime;
    private final Duration validationTokenLifetime;
    private final TokenLog log;
    private final RandomGenerator random;

    /**
     * A validator.
     *
     * @param key the server's token key
     * @param clock the wall clock
     * @param retryTokenLifetime how long Retry tokens are valid
     * @param validationTokenLifetime how long NEW_TOKEN tokens are valid
     * @param log the reuse log for NEW_TOKEN tokens
     * @param random the source of nonces; a {@link java.security.SecureRandom} outside tests
     */
    public TokenValidator(TokenKey key, InstantSource clock, Duration retryTokenLifetime,
            Duration validationTokenLifetime, TokenLog log, RandomGenerator random) {
        this.key = Objects.requireNonNull(key, "key");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.retryTokenLifetime = Objects.requireNonNull(retryTokenLifetime, "retryTokenLifetime");
        this.validationTokenLifetime = Objects.requireNonNull(validationTokenLifetime, "validationTokenLifetime");
        this.log = Objects.requireNonNull(log, "log");
        this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * A token for a Retry packet.
     *
     * @param client the client's address and port
     * @param originalDestinationId the Destination Connection ID of the client's Initial
     * @return the sealed token
     */
    public byte[] retryToken(InetSocketAddress client, ConnectionId originalDestinationId) {
        return Token.create(new TokenPayload.Retry(client, originalDestinationId, clock.instant()), random).encode(key);
    }

    /**
     * A token for a NEW_TOKEN frame. Send a fresh one when a NEW_TOKEN frame is lost, so a client
     * that receives both cannot reuse one token twice.
     *
     * @param client the client's IP address
     * @return the sealed token
     */
    public byte[] validationToken(InetAddress client) {
        return Token.create(new TokenPayload.Validation(client, clock.instant()), random).encode(key);
    }

    /**
     * Checks the token of a client's first Initial packet.
     *
     * @param token the token, empty if none
     * @param destinationId the Initial's Destination Connection ID
     * @param remote the client's address and port
     * @return whether the address is validated, and the connection IDs to authenticate in the
     *     transport parameters
     * @throws QuicException {@code INVALID_TOKEN} for an authentic Retry token from another address
     *     or past its lifetime
     */
    public IncomingToken validate(byte[] token, ConnectionId destinationId, InetSocketAddress remote)
            throws QuicException {
        IncomingToken unvalidated = IncomingToken.unvalidated(destinationId);
        if (token.length == 0) {
            return unvalidated;
        }
        Token decoded = Token.decode(key, token);
        if (decoded == null) {
            return unvalidated; // perhaps another server's or version's: proceed without
        }
        Instant now = clock.instant();
        switch (decoded.payload()) {
            case TokenPayload.Retry r -> {
                if (!r.address().equals(remote)) {
                    throw new QuicException(QuicException.INVALID_TOKEN, "Retry token for another address");
                }
                if (r.issued().plus(retryTokenLifetime).isBefore(now)) {
                    throw new QuicException(QuicException.INVALID_TOKEN, "expired Retry token");
                }
                return new IncomingToken(destinationId, r.originalDestinationId(), true);
            }
            case TokenPayload.Validation v -> {
                if (!v.ip().equals(remote.getAddress())) {
                    return unvalidated;
                }
                if (v.issued().plus(validationTokenLifetime).isBefore(now)) {
                    return unvalidated;
                }
                if (!log.checkAndInsert(decoded.nonce(), v.issued(), validationTokenLifetime)) {
                    return unvalidated;
                }
                return new IncomingToken(null, destinationId, true);
            }
        }
    }
}
