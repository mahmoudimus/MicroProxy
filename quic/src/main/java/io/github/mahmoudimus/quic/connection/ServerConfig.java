/*
 * Ported from quinn-proto src/config/mod.rs (ServerConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.tls.TlsConfig;
import io.github.mahmoudimus.quic.token.TokenKey;
import io.github.mahmoudimus.quic.token.TokenValidator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.InstantSource;
import java.util.Objects;

/**
 * How a server accepts connections: its TLS configuration (certificates, possibly selected per SNI,
 * and ALPN), the transport settings, Retry-based address validation and the connection cap.
 * Immutable and shareable.
 */
public final class ServerConfig {

    final TlsConfig tls;
    final TransportConfig transport;
    final boolean retry;
    final TokenKey tokenKey;
    final Duration retryTokenLifetime;
    final int maxConnections;
    final InstantSource clock;

    private ServerConfig(Builder b) {
        this.tls = b.tls;
        this.transport = b.transport;
        this.retry = b.retry;
        this.tokenKey = b.tokenKey;
        this.retryTokenLifetime = b.retryTokenLifetime;
        this.maxConnections = b.maxConnections;
        this.clock = b.clock;
    }

    /**
     * A builder.
     *
     * @param tls the TLS configuration, with a certificate or certificate selector and ALPN
     * @return a new builder
     */
    public static Builder builder(TlsConfig tls) {
        return new Builder(tls);
    }

    /**
     * The TLS configuration.
     *
     * @return the configuration
     */
    public TlsConfig tls() {
        return tls;
    }

    /**
     * The transport settings of accepted connections.
     *
     * @return the settings
     */
    public TransportConfig transport() {
        return transport;
    }

    /**
     * Whether clients must prove their address with a Retry round trip before a connection is
     * created (RFC 9000 section 8.1.2).
     *
     * @return true if Retry is on
     */
    public boolean retry() {
        return retry;
    }

    /**
     * The most connections the endpoint holds at once; further connection attempts are refused.
     *
     * @return the cap
     */
    public int maxConnections() {
        return maxConnections;
    }

    TokenValidator tokenValidator(SecureRandom random) {
        return new TokenValidator(tokenKey, clock, retryTokenLifetime,
                TokenValidator.DEFAULT_VALIDATION_TOKEN_LIFETIME, io.github.mahmoudimus.quic.token.TokenLog.NONE,
                random);
    }

    /** Builds a {@link ServerConfig}. Not thread-safe. */
    public static final class Builder {
        private final TlsConfig tls;
        private TransportConfig transport = TransportConfig.defaults();
        private boolean retry;
        private TokenKey tokenKey;
        private Duration retryTokenLifetime = TokenValidator.DEFAULT_RETRY_TOKEN_LIFETIME;
        private int maxConnections = 4096;
        private InstantSource clock = InstantSource.system();

        private Builder(TlsConfig tls) {
            this.tls = Objects.requireNonNull(tls, "tls");
        }

        /**
         * The transport settings.
         *
         * @param transport the settings
         * @return this builder
         */
        public Builder transport(TransportConfig transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Turns Retry-based address validation on or off (off by default).
         *
         * @param retry whether to send Retry to clients without a valid token
         * @return this builder
         */
        public Builder retry(boolean retry) {
            this.retry = retry;
            return this;
        }

        /**
         * The key Retry tokens are sealed with; servers behind one address share it.
         *
         * @param key the key, or null for a random one
         * @return this builder
         */
        public Builder tokenKey(TokenKey key) {
            this.tokenKey = key;
            return this;
        }

        /**
         * How long a Retry token stays valid.
         *
         * @param lifetime the lifetime, 15 seconds by default
         * @return this builder
         */
        public Builder retryTokenLifetime(Duration lifetime) {
            this.retryTokenLifetime = Objects.requireNonNull(lifetime, "lifetime");
            return this;
        }

        /**
         * The most connections held at once.
         *
         * @param max at least 1; 4096 by default
         * @return this builder
         */
        public Builder maxConnections(int max) {
            if (max < 1) {
                throw new IllegalArgumentException("maxConnections " + max);
            }
            this.maxConnections = max;
            return this;
        }

        /**
         * The wall clock token expiry is checked against.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(InstantSource clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration
         */
        public ServerConfig build() {
            if (tokenKey == null) {
                tokenKey = TokenKey.random(new SecureRandom());
            }
            return new ServerConfig(this);
        }
    }
}
