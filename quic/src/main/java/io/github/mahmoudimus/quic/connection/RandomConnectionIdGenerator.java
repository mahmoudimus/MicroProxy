/*
 * Ported from quinn-proto src/cid_generator.rs (RandomConnectionIdGenerator) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Generates random connection IDs of a fixed length, 8 bytes by default.
 *
 * <p><b>Threads.</b> Safe to share if the {@link Random} is (a {@link SecureRandom} is).
 */
public final class RandomConnectionIdGenerator implements ConnectionIdGenerator {

    /** The default ID length, 8 bytes. */
    public static final int DEFAULT_LENGTH = 8;

    private final int length;
    private final long lifetime;
    private final Random random;

    /**
     * A generator of 8-byte IDs from a new {@link SecureRandom}, which never expire.
     */
    public RandomConnectionIdGenerator() {
        this(DEFAULT_LENGTH, -1, new SecureRandom());
    }

    /**
     * A generator.
     *
     * @param length the ID length, 0 to 20
     * @param lifetime how long IDs live in nanoseconds, or -1 for forever
     * @param random the source of randomness; a {@link SecureRandom} outside tests
     * @throws IllegalArgumentException if the length is out of range
     */
    public RandomConnectionIdGenerator(int length, long lifetime, Random random) {
        if (length < 0 || length > ConnectionId.MAX_LENGTH) {
            throw new IllegalArgumentException("connection ID length " + length);
        }
        this.length = length;
        this.lifetime = lifetime;
        this.random = random;
    }

    @Override
    public ConnectionId generateCid() {
        return ConnectionId.random(random, length);
    }

    @Override
    public int cidLength() {
        return length;
    }

    @Override
    public long cidLifetime() {
        return lifetime;
    }
}
