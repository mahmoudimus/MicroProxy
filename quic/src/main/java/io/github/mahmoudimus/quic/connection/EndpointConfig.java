/*
 * Ported from quinn-proto src/config/mod.rs (EndpointConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.QuicVersion;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Settings shared by every connection of an endpoint: how local connection IDs are made, the key
 * stateless reset tokens derive from, the QUIC versions accepted, and the stateless reset rate
 * limit. Immutable and shareable.
 */
public final class EndpointConfig {

    final ConnectionIdGenerator cidGenerator;
    final byte[] resetKey;
    final List<QuicVersion> supportedVersions;
    final Duration minResetInterval;

    private EndpointConfig(Builder b) {
        this.cidGenerator = b.cidGenerator;
        this.resetKey = b.resetKey.clone();
        this.supportedVersions = List.copyOf(b.supportedVersions);
        this.minResetInterval = b.minResetInterval;
    }

    /**
     * The default settings: random 8-byte connection IDs that never expire, a random reset key,
     * QUIC version 1 and version 2, at most one stateless reset per 20 ms.
     *
     * @return new default settings (with a fresh reset key)
     */
    public static EndpointConfig defaults() {
        return builder().build();
    }

    /**
     * A builder starting from the defaults.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The length of local connection IDs; short header packets are parsed with it.
     *
     * @return 0 to 20
     */
    public int cidLength() {
        return cidGenerator.cidLength();
    }

    /**
     * The QUIC versions accepted, in preference order.
     *
     * @return the versions
     */
    public List<QuicVersion> supportedVersions() {
        return supportedVersions;
    }

    /** Builds an {@link EndpointConfig}. Not thread-safe. */
    public static final class Builder {
        private ConnectionIdGenerator cidGenerator = new RandomConnectionIdGenerator();
        private byte[] resetKey;
        private List<QuicVersion> supportedVersions = List.of(QuicVersion.V1, QuicVersion.V2);
        private Duration minResetInterval = Duration.ofMillis(20);

        private Builder() {
            resetKey = new byte[64];
            new SecureRandom().nextBytes(resetKey);
        }

        /**
         * The local connection ID generator. Its length is fixed for the endpoint; a length of 0
         * routes packets by the peer's address instead (zero-length connection IDs).
         *
         * @param generator the generator; must be thread-safe
         * @return this builder
         */
        public Builder cidGenerator(ConnectionIdGenerator generator) {
            this.cidGenerator = Objects.requireNonNull(generator, "generator");
            return this;
        }

        /**
         * Random local connection IDs of a length.
         *
         * @param length 0 to 20 bytes
         * @return this builder
         */
        public Builder cidLength(int length) {
            this.cidGenerator = new RandomConnectionIdGenerator(length, -1, new SecureRandom());
            return this;
        }

        /**
         * The secret stateless reset tokens are derived from. Endpoints that should be able to
         * reset each other's connections after a restart share it.
         *
         * @param key at least 32 bytes
         * @return this builder
         */
        public Builder resetKey(byte[] key) {
            if (key.length < 32) {
                throw new IllegalArgumentException("reset key of " + key.length + " bytes");
            }
            this.resetKey = key.clone();
            return this;
        }

        /**
         * The QUIC versions to accept. A server answers others with Version Negotiation.
         *
         * @param versions one or more versions, in preference order
         * @return this builder
         */
        public Builder supportedVersions(QuicVersion... versions) {
            if (versions.length == 0) {
                throw new IllegalArgumentException("no versions");
            }
            this.supportedVersions = List.of(versions);
            return this;
        }

        /**
         * The least time between two stateless resets, which bounds what spoofed packets can make
         * the endpoint send.
         *
         * @param interval the interval
         * @return this builder
         */
        public Builder minResetInterval(Duration interval) {
            this.minResetInterval = Objects.requireNonNull(interval, "interval");
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration
         */
        public EndpointConfig build() {
            return new EndpointConfig(this);
        }
    }
}
