/*
 * Ported from quinn-proto src/token.rs (TokenLog, NoneTokenLog) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.token;

import java.time.Duration;
import java.time.Instant;

/**
 * Limits the reuse of NEW_TOKEN tokens, which attackers could replay to use the server as an
 * amplifier (RFC 9000 section 8.1.4). Retry tokens are not logged: they expire within seconds.
 *
 * <p>False positives (refusing a fresh token) are safe: the client is just not validated yet.
 * False negatives must be rare enough that replays cannot amplify much.
 */
@FunctionalInterface
public interface TokenLog {

    /** A log that refuses every token, so NEW_TOKEN tokens never validate an address. */
    TokenLog NONE = (nonce, issued, lifetime) -> false;

    /**
     * Records that a token was used.
     *
     * @param nonce the token's unique nonce
     * @param issued when the token was issued
     * @param lifetime how long such tokens are valid
     * @return true if the token is accepted, false if it may have been used before
     */
    boolean checkAndInsert(byte[] nonce, Instant issued, Duration lifetime);
}
