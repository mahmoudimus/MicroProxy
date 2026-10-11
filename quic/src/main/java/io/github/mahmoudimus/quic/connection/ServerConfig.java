/*
 * Ported from quinn-proto src/config/mod.rs (ServerConfig and ValidationTokenConfig: the NEW_TOKEN
 * tokens sent per connection, their lifetime and the reuse log) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.tls.TlsConfig;
import io.github.mahmoudimus.quic.token.BloomTokenLog;
import io.github.mahmoudimus.quic.token.TokenKey;
import io.github.mahmoudimus.quic.token.TokenLog;
import io.github.mahmoudimus.quic.token.TokenValidator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.InstantSource;
import java.util.Objects;

/**
 * How a server accepts connections: its TLS configuration (certificates, possibly selected per SNI,
 * ALPN, session tickets and 0-RTT), the transport settings, Retry-based address validation, the
 * NEW_TOKEN tokens that let returning clients skip the Retry, and the connection cap. Immutable and
 * shareable.
 */
public final class ServerConfig {

    final TlsConfig tls;
    final TransportConfig transport;
    final boolean retry;
    final TokenKey tokenKey;
    final Duration retryTokenLifetime;
    final int maxConnections;
    final InstantSource clock;
    final int newTokens;
    final Duration validationTokenLifetime;

    private ServerConfig(Builder b) {
        this.tls = b.tls;
        this.transport = b.transport;
        this.retry = b.retry;
        this.tokenKey = b.tokenKey;
        this.retryTokenLifetime = b.retryTokenLifetime;
        this.maxConnections = b.maxConnections;
        this.clock = b.clock;
        this.newTokens = b.newTokens;
        this.validationTokenLifetime = b.validationTokenLifetime;
    }

    /**
     * How many NEW_TOKEN tokens a connection sends the client after its handshake.
     *
     * @return the count
     */
    public int newTokens() {
        return newTokens;
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

    /** A validator for one endpoint, with its own log of the NEW_TOKEN tokens used. */
    TokenValidator tokenValidator(SecureRandom random) {
        TokenLog log = newTokens > 0 ? new BloomTokenLog() : TokenLog.NONE;
        return new TokenValidator(tokenKey, clock, retryTokenLifetime, validationTokenLifetime, log, random);
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
        private int newTokens = 2;
        private Duration validationTokenLifetime = TokenValidator.DEFAULT_VALIDATION_TOKEN_LIFETIME;

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
         * How many NEW_TOKEN tokens to send each client after its handshake (RFC 9000 section
         * 8.1.3). A client presents one in its next connection's first Initial, which validates its
         * address so that Retry is skipped; each token is accepted once.
         *
         * @param count 0 to send none; 2 by default, as quinn sends
         * @return this builder
         */
        public Builder newTokens(int count) {
            if (count < 0 || count > 16) {
                throw new IllegalArgumentException("newTokens " + count);
            }
            this.newTokens = count;
            return this;
        }

        /**
         * How long a NEW_TOKEN token stays valid.
         *
         * @param lifetime the lifetime, two weeks by default
         * @return this builder
         */
        public Builder validationTokenLifetime(Duration lifetime) {
            this.validationTokenLifetime = Objects.requireNonNull(lifetime, "lifetime");
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
