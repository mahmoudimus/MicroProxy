/*
 * Ported from quinn-proto src/config/mod.rs (ClientConfig) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.util.Objects;

/**
 * How a client connects: its TLS configuration (trust, server name, ALPN), the transport settings
 * and the QUIC version. Immutable and shareable.
 */
public final class ClientConfig {

    final TlsConfig tls;
    final TransportConfig transport;
    final QuicVersion version;
    final int initialDcidLength;

    private ClientConfig(Builder b) {
        this.tls = b.tls;
        this.transport = b.transport;
        this.version = b.version;
        this.initialDcidLength = b.initialDcidLength;
    }

    /**
     * A builder.
     *
     * @param tls the TLS configuration, with ALPN and the trust to check the server with
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
     * The transport settings.
     *
     * @return the settings
     */
    public TransportConfig transport() {
        return transport;
    }

    /**
     * The QUIC version connections start with.
     *
     * @return the version
     */
    public QuicVersion version() {
        return version;
    }

    /** Builds a {@link ClientConfig}. Not thread-safe. */
    public static final class Builder {
        private final TlsConfig tls;
        private TransportConfig transport = TransportConfig.defaults();
        private QuicVersion version = QuicVersion.V1;
        private int initialDcidLength = ConnectionId.MAX_LENGTH;

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
         * The QUIC version to use, version 1 by default.
         *
         * @param version the version
         * @return this builder
         */
        public Builder version(QuicVersion version) {
            this.version = Objects.requireNonNull(version, "version");
            return this;
        }

        /**
         * The length of the random Destination Connection ID of the first Initial.
         *
         * @param length 8 to 20 bytes (RFC 9000 section 7.2); 20 by default
         * @return this builder
         */
        public Builder initialDcidLength(int length) {
            if (length < 8 || length > ConnectionId.MAX_LENGTH) {
                throw new IllegalArgumentException("initial Destination Connection ID length " + length);
            }
            this.initialDcidLength = length;
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration
         */
        public ClientConfig build() {
            return new ClientConfig(this);
        }
    }
}
