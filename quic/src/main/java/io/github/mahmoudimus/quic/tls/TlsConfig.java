// Ported from rustls src/client/config.rs, src/server/config.rs and src/builder.rs (the client and
// server configuration: suites, groups, verifier, certificate resolver, ALPN, enable_early_data,
// the ticketer, send_tls13_tickets and max_early_data_size) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import javax.net.ssl.X509TrustManager;

/**
 * Configuration for TLS 1.3 handshakes in QUIC, shared by any number of {@link TlsSession}s. A
 * client needs a server name and ALPN protocols; a server needs a certificate (or a selector that
 * picks one per server name) and ALPN protocols or an ALPN selector. Built with {@link #builder()};
 * instances are immutable.
 *
 * <p>Defaults: all three cipher suites; the groups X25519, P-256 and P-384, in that order of
 * preference; the signature schemes {@code ecdsa_secp256r1_sha256}, {@code
 * ecdsa_secp384r1_sha384}, {@code rsa_pss_rsae_sha256/384/512} and {@code ed25519}; the JDK's
 * default trust manager with host name verification; no client authentication; no session
 * tickets and no 0-RTT.
 *
 * <p><b>Resumption.</b> A server with a {@link Builder#sessionTickets(Ticketer) ticketer} sends
 * {@link Builder#ticketsPerConnection(int) tickets} after each handshake and accepts them for PSK
 * resumption ({@code psk_dhe_ke} only: a resumed handshake still does a fresh (EC)DHE exchange). A
 * client resumes with a {@link SessionTicket} the connection layer passes to {@link
 * TlsSession#client(TlsConfig, String, byte[], SessionTicket)}. With {@link
 * Builder#earlyData(boolean) earlyData}, a client offers 0-RTT data when its ticket allows it, and a
 * server allows 0-RTT in its tickets and accepts it when its {@link Builder#earlyDataPolicy
 * policy} does; see {@link EarlyDataPolicy} for the replay risk.
 */
public final class TlsConfig {

    /** The default limit on a handshake message body: 64 KiB. */
    public static final int DEFAULT_MAX_HANDSHAKE_MESSAGE_SIZE = 64 * 1024;

    final List<CipherSuite> cipherSuites;
    final List<NamedGroup> groups;
    final List<SignatureScheme> signatureSchemes;
    final SecureRandom random;
    final int maxHandshakeMessageSize;
    final List<byte[]> alpnProtocols;
    // Client.
    final String serverName;
    final X509TrustManager trustManager;
    final boolean trustAllCertificates;
    final boolean verifyHostname;
    final CertifiedKey clientCertificate;
    // Server.
    final Function<ClientHelloInfo, CertifiedKey> certificateSelector;
    final Function<ClientHelloInfo, String> alpnSelector;
    final ClientAuth clientAuth;
    final X509TrustManager clientTrustManager;
    // Resumption and 0-RTT.
    final InstantSource clock;
    final boolean earlyData;
    final Ticketer ticketer;
    final int ticketsPerConnection;
    final EarlyDataPolicy earlyDataPolicy;

    private TlsConfig(Builder b) {
        this.cipherSuites = List.copyOf(b.cipherSuites);
        this.groups = List.copyOf(b.groups);
        this.signatureSchemes = List.copyOf(b.signatureSchemes);
        this.random = b.random != null ? b.random : new SecureRandom();
        this.maxHandshakeMessageSize = b.maxHandshakeMessageSize;
        List<byte[]> alpn = new ArrayList<>();
        for (String p : b.alpnProtocols) alpn.add(p.getBytes(StandardCharsets.ISO_8859_1));
        this.alpnProtocols = List.copyOf(alpn);
        this.serverName = b.serverName;
        this.trustManager = b.trustManager;
        this.trustAllCertificates = b.trustAllCertificates;
        this.verifyHostname = b.verifyHostname;
        this.clientCertificate = b.clientCertificate;
        this.certificateSelector = b.certificateSelector;
        this.alpnSelector = b.alpnSelector;
        this.clientAuth = b.clientAuth;
        this.clientTrustManager = b.clientTrustManager;
        this.clock = b.clock;
        this.earlyData = b.earlyData;
        this.ticketer = b.ticketer;
        this.ticketsPerConnection = b.ticketsPerConnection;
        this.earlyDataPolicy = b.earlyDataPolicy != null ? b.earlyDataPolicy
                : b.earlyData && b.ticketer != null ? EarlyDataPolicy.antiReplay() : EarlyDataPolicy.REJECT;
    }

    /**
     * Whether 0-RTT is enabled: offered by a client, allowed and accepted by a server.
     *
     * @return true if enabled
     */
    public boolean earlyData() {
        return earlyData;
    }

    /**
     * The server's ticketer.
     *
     * @return the ticketer, or null if the server issues no tickets
     */
    public Ticketer ticketer() {
        return ticketer;
    }

    /**
     * Starts a configuration with the defaults.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /** The trust manager a client uses: the configured one or the JDK's default. */
    X509TrustManager serverTrust() {
        return trustManager != null ? trustManager : CertificateChecks.defaultTrustManager();
    }

    /** The trust manager a server uses for client certificates: the configured one or the JDK's default. */
    X509TrustManager clientTrust() {
        return clientTrustManager != null ? clientTrustManager : CertificateChecks.defaultTrustManager();
    }

    /** Builds a {@link TlsConfig}. Builders are not thread-safe. */
    public static final class Builder {

        private List<CipherSuite> cipherSuites = List.of(CipherSuite.values());
        private List<NamedGroup> groups = List.of(NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1);
        private List<SignatureScheme> signatureSchemes = List.of(
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                SignatureScheme.ECDSA_SECP384R1_SHA384,
                SignatureScheme.RSA_PSS_RSAE_SHA256,
                SignatureScheme.RSA_PSS_RSAE_SHA384,
                SignatureScheme.RSA_PSS_RSAE_SHA512,
                SignatureScheme.ED25519);
        private SecureRandom random;
        private int maxHandshakeMessageSize = DEFAULT_MAX_HANDSHAKE_MESSAGE_SIZE;
        private List<String> alpnProtocols = List.of();
        private String serverName;
        private X509TrustManager trustManager;
        private boolean trustAllCertificates;
        private boolean verifyHostname = true;
        private CertifiedKey clientCertificate;
        private Function<ClientHelloInfo, CertifiedKey> certificateSelector;
        private Function<ClientHelloInfo, String> alpnSelector;
        private ClientAuth clientAuth = ClientAuth.NONE;
        private X509TrustManager clientTrustManager;
        private InstantSource clock = InstantSource.system();
        private boolean earlyData;
        private Ticketer ticketer;
        private int ticketsPerConnection = 2;
        private EarlyDataPolicy earlyDataPolicy;

        private Builder() {}

        /**
         * The cipher suites to offer (client) or accept (server), most preferred first. A server
         * picks the first of its suites the client offers.
         *
         * @param suites one or more suites
         * @return this builder
         */
        public Builder cipherSuites(CipherSuite... suites) {
            this.cipherSuites = nonEmpty(List.of(suites), "cipher suites");
            return this;
        }

        /**
         * The key exchange groups, most preferred first. A client sends a key share for the first
         * and lists them all in {@code supported_groups}; a server takes the first of its groups
         * the client sent a key share for, or else asks for the first of its groups the client
         * supports with a HelloRetryRequest.
         *
         * @param groups one or more groups
         * @return this builder
         */
        public Builder groups(NamedGroup... groups) {
            this.groups = nonEmpty(List.of(groups), "groups");
            return this;
        }

        /**
         * The signature schemes allowed for CertificateVerify, most preferred first. The {@code
         * rsa_pkcs1} schemes cannot be used here; a client always advertises them as well, for
         * the signatures in certificate chains.
         *
         * @param schemes one or more schemes
         * @return this builder
         * @throws IllegalArgumentException if a scheme cannot sign a TLS 1.3 CertificateVerify
         */
        public Builder signatureSchemes(SignatureScheme... schemes) {
            List<SignatureScheme> list = nonEmpty(List.of(schemes), "signature schemes");
            for (SignatureScheme s : list) {
                if (!s.allowedInCertificateVerify()) {
                    throw new IllegalArgumentException(s + " is only for certificate signatures in TLS 1.3");
                }
            }
            this.signatureSchemes = list;
            return this;
        }

        /**
         * The source of randomness for hello randoms, key shares and signatures.
         *
         * @param random the random source
         * @return this builder
         */
        public Builder secureRandom(SecureRandom random) {
            this.random = Objects.requireNonNull(random);
            return this;
        }

        /**
         * The largest handshake message body accepted from the peer; a longer one fails with
         * {@code CRYPTO_BUFFER_EXCEEDED}. This bounds what a session buffers per encryption level.
         *
         * @param bytes the limit, at least 4096 (RFC 9001 section 4.1.3)
         * @return this builder
         */
        public Builder maxHandshakeMessageSize(int bytes) {
            if (bytes < 4096 || bytes > HandshakeMessage.MAX_BODY) {
                throw new IllegalArgumentException("maxHandshakeMessageSize " + bytes);
            }
            this.maxHandshakeMessageSize = bytes;
            return this;
        }

        /**
         * The application protocols (ALPN). A client offers them in this order; a server without
         * an {@link #alpnSelector(Function) ALPN selector} picks the first of them the client
         * offered. QUIC requires ALPN, so a handshake without a common protocol fails with {@code
         * no_application_protocol}. Characters map one to one onto bytes (ISO-8859-1).
         *
         * @param protocols the protocol names, such as {@code "h3"}
         * @return this builder
         */
        public Builder alpnProtocols(String... protocols) {
            for (String p : protocols) {
                if (p.isEmpty() || p.length() > 255 || !StandardCharsets.ISO_8859_1.newEncoder().canEncode(p)) {
                    throw new IllegalArgumentException("invalid ALPN protocol: " + p);
                }
            }
            this.alpnProtocols = List.of(protocols);
            return this;
        }

        /**
         * Client: the server's host name or IP address. A host name is sent as SNI; either is
         * what the server's certificate is checked against.
         *
         * @param serverName the host name or IP literal
         * @return this builder
         */
        public Builder serverName(String serverName) {
            this.serverName = serverName;
            return this;
        }

        /**
         * Client: the trust manager that validates the server's chain. The default is the JDK's
         * default trust manager.
         *
         * @param trustManager the trust manager
         * @return this builder
         */
        public Builder trustManager(X509TrustManager trustManager) {
            this.trustManager = trustManager;
            return this;
        }

        /**
         * Client: accept any server certificate without validating its chain or name. The
         * CertificateVerify signature is still checked. For tests only.
         *
         * @param trustAll true to skip certificate validation
         * @return this builder
         */
        public Builder trustAllCertificates(boolean trustAll) {
            this.trustAllCertificates = trustAll;
            return this;
        }

        /**
         * Client: whether the server's certificate must be valid for the server name, as HTTPS
         * endpoint identification checks. On by default.
         *
         * @param verify false to skip the host name check
         * @return this builder
         */
        public Builder verifyHostname(boolean verify) {
            this.verifyHostname = verify;
            return this;
        }

        /**
         * Client: the certificate to present if the server asks for one. Without one, the client
         * answers a CertificateRequest with an empty Certificate.
         *
         * @param key the chain and key
         * @return this builder
         */
        public Builder clientCertificate(CertifiedKey key) {
            this.clientCertificate = key;
            return this;
        }

        /**
         * Server: one certificate for every connection.
         *
         * @param key the chain and key
         * @return this builder
         */
        public Builder certificate(CertifiedKey key) {
            Objects.requireNonNull(key);
            this.certificateSelector = hello -> key;
            return this;
        }

        /**
         * Server: one certificate for every connection.
         *
         * @param chain the certificates, end-entity first
         * @param privateKey the end-entity certificate's private key
         * @return this builder
         */
        public Builder certificate(List<X509Certificate> chain, PrivateKey privateKey) {
            return certificate(new CertifiedKey(chain, privateKey));
        }

        /**
         * Server: picks the certificate for each ClientHello, typically by its server name. It
         * runs on the thread that feeds the session its handshake data. Returning null fails the
         * handshake with {@code unrecognized_name} if the client sent a name, {@code
         * handshake_failure} otherwise.
         *
         * @param selector the selector
         * @return this builder
         */
        public Builder certificateSelector(Function<ClientHelloInfo, CertifiedKey> selector) {
            this.certificateSelector = Objects.requireNonNull(selector);
            return this;
        }

        /**
         * Server: picks the application protocol from the client's offer, instead of the {@link
         * #alpnProtocols(String...) preference list}. Returning null, or a protocol the client
         * did not offer, fails the handshake with {@code no_application_protocol}.
         *
         * @param selector the selector
         * @return this builder
         */
        public Builder alpnSelector(Function<ClientHelloInfo, String> selector) {
            this.alpnSelector = Objects.requireNonNull(selector);
            return this;
        }

        /**
         * Server: whether to ask the client for a certificate.
         *
         * @param clientAuth the policy
         * @return this builder
         */
        public Builder clientAuth(ClientAuth clientAuth) {
            this.clientAuth = Objects.requireNonNull(clientAuth);
            return this;
        }

        /**
         * Server: the trust manager that validates client certificates. The default is the JDK's
         * default trust manager.
         *
         * @param trustManager the trust manager
         * @return this builder
         */
        public Builder clientTrustManager(X509TrustManager trustManager) {
            this.clientTrustManager = trustManager;
            return this;
        }

        /**
         * The wall clock ticket ages and lifetimes are measured with.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(InstantSource clock) {
            this.clock = Objects.requireNonNull(clock);
            return this;
        }

        /**
         * Turns 0-RTT on or off (off by default). A client then offers early data when its ticket
         * allows it; a server issues tickets that allow early data and accepts it when the {@link
         * #earlyDataPolicy(EarlyDataPolicy) policy} does. 0-RTT data can be replayed; see {@link
         * EarlyDataPolicy}.
         *
         * @param enabled whether to use 0-RTT
         * @return this builder
         */
        public Builder earlyData(boolean enabled) {
            this.earlyData = enabled;
            return this;
        }

        /**
         * Server: the ticketer that seals session tickets, which turns on NewSessionTicket and PSK
         * resumption. Servers that share a ticketer accept each other's tickets. Not used with
         * {@link #clientAuth(ClientAuth) client authentication}.
         *
         * @param ticketer the ticketer, or null to issue no tickets (the default)
         * @return this builder
         */
        public Builder sessionTickets(Ticketer ticketer) {
            this.ticketer = ticketer;
            return this;
        }

        /**
         * Server: how many tickets to send after each handshake. Clients use each ticket once, so
         * more tickets allow more resumed connections before the next full handshake.
         *
         * @param count 0 to 16; 2 by default
         * @return this builder
         */
        public Builder ticketsPerConnection(int count) {
            if (count < 0 || count > 16) {
                throw new IllegalArgumentException("ticketsPerConnection " + count);
            }
            this.ticketsPerConnection = count;
            return this;
        }

        /**
         * Server: decides whether to accept 0-RTT data the protocol allows. The default, with
         * {@link #earlyData(boolean) earlyData} on, is {@link EarlyDataPolicy#antiReplay()}; compose
         * an application veto with it rather than replacing it.
         *
         * @param policy the policy
         * @return this builder
         */
        public Builder earlyDataPolicy(EarlyDataPolicy policy) {
            this.earlyDataPolicy = Objects.requireNonNull(policy);
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the immutable configuration
         */
        public TlsConfig build() {
            return new TlsConfig(this);
        }

        private static <T> List<T> nonEmpty(List<T> list, String what) {
            if (list.isEmpty()) throw new IllegalArgumentException("no " + what);
            if (list.stream().distinct().count() != list.size()) {
                throw new IllegalArgumentException("repeated " + what);
            }
            return list;
        }
    }
}
