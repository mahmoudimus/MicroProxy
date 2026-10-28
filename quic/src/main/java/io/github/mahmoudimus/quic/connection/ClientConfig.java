/*
 * Ported from quinn-proto src/config/mod.rs (ClientConfig, with its token store) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicVersion;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.util.Objects;

/**
 * How a client connects: its TLS configuration (trust, server name, ALPN, 0-RTT), the transport
 * settings, the QUIC version and the {@link SessionCache} that keeps session tickets and NEW_TOKEN
 * tokens between connections. Immutable and shareable.
 */
public final class ClientConfig {

    final TlsConfig tls;
    final TransportConfig transport;
    final QuicVersion version;
    final int initialDcidLength;
    final SessionCache sessionCache;
    final boolean activeMigration;
    final boolean preferredAddress;
    final io.github.mahmoudimus.quic.params.TransportParameterProfile transportParameterProfile;

    private ClientConfig(Builder b) {
        this.tls = b.tls;
        this.transport = b.transport;
        this.version = b.version;
        this.initialDcidLength = b.initialDcidLength;
        this.sessionCache = b.sessionCache;
        this.activeMigration = b.activeMigration;
        this.preferredAddress = b.preferredAddress;
        this.transportParameterProfile = b.transportParameterProfile;
    }

    /**
     * The cache of session tickets and tokens connections use.
     *
     * @return the cache, or null to leave it to the caller ({@code QuicClient} then uses one of
     *     its own)
     */
    public SessionCache sessionCache() {
        return sessionCache;
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
        private SessionCache sessionCache;
        private boolean activeMigration = true;
        private boolean preferredAddress = true;
        private io.github.mahmoudimus.quic.params.TransportParameterProfile transportParameterProfile;

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
         * The cache of session tickets and NEW_TOKEN tokens: resumption, 0-RTT (with {@link
         * TlsConfig.Builder#earlyData(boolean)}) and Retry-free reconnection. {@link
         * SessionCache#none()} turns them off.
         *
         * @param cache the cache, or null for the caller's default
         * @return this builder
         */
        public Builder sessionCache(SessionCache cache) {
            this.sessionCache = cache;
            return this;
        }

        /**
         * Whether connections may migrate to a new local address ({@link Connection#probePath}),
         * on by default. Off, the client sends {@code disable_active_migration} and refuses to
         * migrate. A server that sent {@code disable_active_migration} is never migrated away from
         * either way, except to its preferred address.
         *
         * @param activeMigration whether to allow active migration
         * @return this builder
         */
        public Builder activeMigration(boolean activeMigration) {
            this.activeMigration = activeMigration;
            return this;
        }

        /**
         * Whether to move to a server's preferred address (RFC 9000 section 9.6) once the
         * handshake is confirmed, on by default: the client probes the address of its current
         * path's family with the connection ID the server gave for it, and switches when the
         * server answers.
         *
         * @param preferredAddress whether to follow a preferred address
         * @return this builder
         */
        public Builder preferredAddress(boolean preferredAddress) {
            this.preferredAddress = preferredAddress;
            return this;
        }

        /**
         * The transport parameters as a browser sends them ({@link
         * io.github.mahmoudimus.quic.params.TransportParameterProfile#chrome156()}): its parameters, in
         * its order, with its GREASE; their values are still the connection's, so the {@link
         * #transport} configuration should match the browser's too. Default none: the client's own.
         *
         * @param profile the profile, or null for none
         * @return this builder
         */
        public Builder transportParameterProfile(io.github.mahmoudimus.quic.params.TransportParameterProfile profile) {
            this.transportParameterProfile = profile;
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
