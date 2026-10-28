package io.github.mahmoudimus.quic.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.time.InstantSource;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * An {@link SSLContext} for TLS clients that present a browser's fingerprint: its sockets'
 * handshakes are a {@link ClientHelloProfile}'s, such as {@link BrowserProfiles#chrome156()}, so a
 * server sees that browser's ClientHello (cipher suites, extensions and their order, GREASE, key
 * shares) where it would see the JDK's. Anything that takes an {@code SSLContext} for client
 * connections can use one; only client sockets are offered ({@link SSLContext#getSocketFactory}),
 * not server sockets or {@link SSLEngine}s.
 *
 * <pre>{@code
 * SSLContext chrome = FingerprintSslContext.builder(BrowserProfiles.chrome156())
 *         .trustManager(trustManager)
 *         .certificateDecompressor(brotli)
 *         .build();
 * }</pre>
 *
 * <p>Sockets made from the context share its session tickets, by server name and port, and resume
 * with them as the browser would.
 */
public final class FingerprintSslContext {

    /** What a context's sockets share. */
    record Settings(TlsClientConnection.Config config, List<String> defaultApplicationProtocols, Object attachment) {}

    /** The session of a socket whose handshake failed, as the JDK reports one. */
    static final SSLSession NULL_SESSION = new NullSession();

    private static final Provider PROVIDER = new Provider("MicroProxyFingerprint", "1.0",
            "TLS client sockets with a browser's ClientHello") {};

    private FingerprintSslContext() {}

    /**
     * A builder for a context with {@code profile}'s ClientHello.
     *
     * @param profile the ClientHello to present
     * @return the builder
     */
    public static Builder builder(ClientHelloProfile profile) {
        return new Builder(profile);
    }

    /** Configures a {@link FingerprintSslContext}. */
    public static final class Builder {
        private final ClientHelloProfile profile;
        private X509TrustManager trustManager;
        private X509KeyManager keyManager;
        private ClientSessionStore sessions = new ClientSessionMemoryCache();
        private Map<String, byte[]> applicationSettings = Map.of("h2", new byte[0]);
        private CertificateDecompressor decompressor = CertificateDecompressor.ZLIB;
        private SecureRandom random = new SecureRandom();
        private InstantSource clock = InstantSource.system();
        private int maxHandshakeMessageSize = TlsConfig.DEFAULT_MAX_HANDSHAKE_MESSAGE_SIZE;
        private List<String> defaultApplicationProtocols = List.of("http/1.1");
        private Object attachment;

        private Builder(ClientHelloProfile profile) {
            this.profile = Objects.requireNonNull(profile, "profile");
        }

        /** The servers trusted; the JDK's default trust store if not set. */
        public Builder trustManager(X509TrustManager trustManager) {
            this.trustManager = trustManager;
            return this;
        }

        /**
         * The first {@link X509TrustManager} of {@code trustManagers}, as {@link
         * SSLContext#init} takes them; the default trust store if there is none.
         */
        public Builder trustManagers(TrustManager[] trustManagers) {
            if (trustManagers != null) {
                for (TrustManager tm : trustManagers) {
                    if (tm instanceof X509TrustManager x) return trustManager(x);
                }
            }
            return this;
        }

        /** The client certificates offered when a server asks for one; none if not set. */
        public Builder keyManager(X509KeyManager keyManager) {
            this.keyManager = keyManager;
            return this;
        }

        /** The first {@link X509KeyManager} of {@code keyManagers}, as {@link SSLContext#init} takes them. */
        public Builder keyManagers(KeyManager[] keyManagers) {
            if (keyManagers != null) {
                for (KeyManager km : keyManagers) {
                    if (km instanceof X509KeyManager x) return keyManager(x);
                }
            }
            return this;
        }

        /** Where session tickets are kept; a fresh in-memory store by default, {@link ClientSessionStore#NONE} for none. */
        public Builder sessions(ClientSessionStore sessions) {
            this.sessions = Objects.requireNonNull(sessions, "sessions");
            return this;
        }

        /**
         * The ALPS settings (application_settings) answered to a server that sends its own, by ALPN
         * protocol. Chrome's, the default, are empty settings for {@code h2}.
         */
        public Builder applicationSettings(Map<String, byte[]> settings) {
            this.applicationSettings = Map.copyOf(settings);
            return this;
        }

        /**
         * Decompresses server certificates the profile offers to receive compressed; zlib only by
         * default. Chrome's profile offers Brotli alone, so a Brotli decompressor belongs here for it.
         */
        public Builder certificateDecompressor(CertificateDecompressor decompressor) {
            this.decompressor = Objects.requireNonNull(decompressor, "decompressor");
            return this;
        }

        /** The source of the handshakes' randomness. */
        public Builder random(SecureRandom random) {
            this.random = Objects.requireNonNull(random, "random");
            return this;
        }

        /** The clock tickets are timed with. */
        public Builder clock(InstantSource clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * The ALPN protocols offered when a socket's caller sets none: {@code http/1.1} by default,
         * since a browser always offers ALPN and a hello without it is not one a browser sends.
         * Empty to offer none.
         */
        public Builder defaultApplicationProtocols(List<String> protocols) {
            this.defaultApplicationProtocols = List.copyOf(protocols);
            return this;
        }

        /**
         * Something to go with the context's sockets, which code holding one reads from {@link
         * FingerprintSocket#attachment()}: MicroProxy's HTTP/2 client takes an {@code
         * Http2ClientProfile} from it for connections over the socket.
         */
        public Builder attach(Object attachment) {
            this.attachment = attachment;
            return this;
        }

        /** The longest handshake message accepted, 64 KiB by default. */
        public Builder maxHandshakeMessageSize(int bytes) {
            this.maxHandshakeMessageSize = bytes;
            return this;
        }

        /** {@return the context} */
        public SSLContext build() {
            X509TrustManager trust = trustManager != null ? trustManager : CertificateChecks.defaultTrustManager();
            Settings settings = new Settings(new TlsClientConnection.Config(profile, trust, keyManager, sessions,
                    applicationSettings, decompressor, random, clock, maxHandshakeMessageSize), defaultApplicationProtocols, attachment);
            return new SSLContext(new Spi(settings), PROVIDER, FingerprintSslSocket.TLS13) {};
        }
    }

    private static final class Spi extends SSLContextSpi {
        private final Settings settings;
        private final SSLSocketFactory factory;

        Spi(Settings settings) {
            this.settings = settings;
            this.factory = new Factory(settings);
        }

        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
            throw new KeyManagementException("a FingerprintSslContext is configured by its builder");
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return factory;
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            throw new UnsupportedOperationException("a FingerprintSslContext makes client sockets only");
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            throw new UnsupportedOperationException("a FingerprintSslContext makes sockets, not SSLEngines");
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            throw new UnsupportedOperationException("a FingerprintSslContext makes sockets, not SSLEngines");
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            return null;
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            return null;
        }
    }

    private static final class Factory extends SSLSocketFactory {
        private final Settings settings;

        Factory(Settings settings) {
            this.settings = settings;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return getSupportedCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return settings.config().profile().tls13CipherSuites().stream().map(Enum::name).toArray(String[]::new);
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) {
            return new FingerprintSslSocket(settings, s, host, port, autoClose);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return createSocket(new Socket(host, port), host, port, true);
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            return createSocket(new Socket(host, port, localHost, localPort), host, port, true);
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            return createSocket(new Socket(host, port), host.getHostAddress(), port, true);
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return createSocket(new Socket(address, port, localAddress, localPort), address.getHostAddress(), port, true);
        }
    }

    private static final class NullSession implements SSLSession {
        @Override public byte[] getId() { return new byte[0]; }
        @Override public SSLSessionContext getSessionContext() { return null; }
        @Override public long getCreationTime() { return 0; }
        @Override public long getLastAccessedTime() { return 0; }
        @Override public void invalidate() {}
        @Override public boolean isValid() { return false; }
        @Override public void putValue(String name, Object value) {}
        @Override public Object getValue(String name) { return null; }
        @Override public void removeValue(String name) {}
        @Override public String[] getValueNames() { return new String[0]; }
        @Override public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
        @Override public Certificate[] getLocalCertificates() { return null; }
        @Override public java.security.Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            throw new SSLPeerUnverifiedException("peer not authenticated");
        }
        @Override public java.security.Principal getLocalPrincipal() { return null; }
        @Override public String getCipherSuite() { return "SSL_NULL_WITH_NULL_NULL"; }
        @Override public String getProtocol() { return "NONE"; }
        @Override public String getPeerHost() { return null; }
        @Override public int getPeerPort() { return -1; }
        @Override public int getPacketBufferSize() { return TlsRecordLayer.MAX_FRAGMENT + 261; }
        @Override public int getApplicationBufferSize() { return TlsRecordLayer.MAX_FRAGMENT; }
    }
}
