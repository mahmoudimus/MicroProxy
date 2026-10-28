package io.github.mahmoudimus.quic.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * A client {@link SSLSocket} over a connected socket whose handshake is a {@link
 * TlsClientConnection}'s, so its ClientHello is a browser profile's. It reads what JSSE callers set:
 * the SNI name and ALPN protocols in {@link SSLParameters} (the context's default ALPN protocols
 * when none are set), {@code HTTPS} endpoint identification, and the enabled protocols. Cipher suites are the profile's: setting them changes nothing, since
 * that would change the fingerprint.
 *
 * <p>Failures are reported the way the JDK's own sockets report them, so code that reads JSSE
 * exceptions keeps working: a server's alert as {@code "Received fatal alert: <description>"}, a
 * peer that is not a TLS server as {@code "Unsupported or unrecognized SSL message"}, a connection
 * closed during the handshake as {@code "Remote host terminated the handshake"}, one reset as an
 * {@link SSLException} with the {@link SocketException} as its cause, and certificate
 * failures with the trust manager's {@link java.security.cert.CertificateException} as the cause.
 */
final class FingerprintSslSocket extends SSLSocket implements FingerprintSocket {

    static final String TLS13 = "TLSv1.3";
    static final String TLS12 = "TLSv1.2";

    private final FingerprintSslContext.Settings settings;
    private final Socket plain;
    private final String host;
    private final int port;
    private final boolean autoClose;
    private final List<HandshakeCompletedListener> listeners = new CopyOnWriteArrayList<>();
    private SSLParameters parameters = new SSLParameters();
    private String[] enabledProtocols = {TLS13, TLS12};
    private TlsClientConnection connection;
    private FingerprintSslSession session;
    private IOException failure;
    private InputStream in;
    private OutputStream out;
    private volatile boolean closed;

    FingerprintSslSocket(FingerprintSslContext.Settings settings, Socket plain, String host, int port, boolean autoClose) {
        this.settings = settings;
        this.plain = plain;
        this.host = host;
        this.port = port;
        this.autoClose = autoClose;
        SNIHostName sni = sni(host);
        if (sni != null) parameters.setServerNames(List.of(sni));
        parameters.setProtocols(enabledProtocols);
        parameters.setCipherSuites(getSupportedCipherSuites());
    }

    private static SNIHostName sni(String name) {
        if (name == null || HostnameChecker.isIpLiteral(name)) return null;
        try {
            return new SNIHostName(name);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @Override
    public ClientHelloProfile profile() {
        return settings.config().profile();
    }

    @Override
    public Object attachment() {
        return settings.attachment();
    }

    // --- the handshake ---

    @Override
    public synchronized void startHandshake() throws IOException {
        if (failure != null) throw failure;
        if (session != null) return;
        if (closed) throw new SocketException("Socket is closed");
        if (!Arrays.asList(enabledProtocols).contains(TLS13)) {
            // a browser's hello offers TLS 1.3; TLS 1.2 alone would be another fingerprint
            throw failure = new SSLHandshakeException("No appropriate protocol (protocol is disabled or cipher suites are inappropriate):"
                    + " a browser fingerprint needs TLSv1.3 enabled");
        }
        String serverName = null;
        List<SNIServerName> names = parameters.getServerNames();
        if (names != null) {
            for (SNIServerName name : names) {
                if (name instanceof SNIHostName h) serverName = h.getAsciiName();
            }
        }
        // the JDK checks the certificate against the SNI name, or the host the socket is for
        String verifyHost = "HTTPS".equalsIgnoreCase(parameters.getEndpointIdentificationAlgorithm())
                ? (serverName != null ? serverName : host) : null;
        String[] protocols = parameters.getApplicationProtocols();
        List<String> alpn = protocols == null || protocols.length == 0 ? settings.defaultApplicationProtocols() : List.of(protocols);
        TlsClientConnection c = new TlsClientConnection(settings.config(), plain.getInputStream(), plain.getOutputStream(),
                serverName, verifyHost, alpn,
                (serverName != null ? serverName : host) + ":" + port);
        c.allowTls12(Arrays.asList(enabledProtocols).contains(TLS12));
        try {
            c.handshake();
        } catch (IOException e) {
            failure = jsse(e);
            closeQuietly();
            throw failure;
        }
        connection = c;
        session = new FingerprintSslSession(c, host, port);
        in = new TlsInput();
        out = new TlsOutput();
        if (!listeners.isEmpty()) {
            HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, session);
            for (HandshakeCompletedListener l : listeners) l.handshakeCompleted(event);
        }
    }

    /** The JDK's exception, and message, for a failed handshake. */
    private static IOException jsse(IOException e) {
        if (e instanceof TlsClientConnection.TlsAlertException alert) {
            String name = TlsAlert.name(alert.alert());
            if (alert.received()) {
                SSLHandshakeException out = new SSLHandshakeException("Received fatal alert: " + name);
                out.initCause(e);
                return out;
            }
            String message = String.valueOf(e.getMessage());
            if (message.contains(TlsRecordLayer.NOT_TLS)) {
                SSLException out = new SSLException("Unsupported or unrecognized SSL message");
                out.initCause(e);
                return out;
            }
            SSLHandshakeException out = new SSLHandshakeException("(" + name + ") " + message);
            out.initCause(e);
            return out;
        }
        if (e instanceof EOFException) {
            SSLHandshakeException out = new SSLHandshakeException("Remote host terminated the handshake");
            out.initCause(e);
            return out;
        }
        if (e instanceof SocketException && !(e instanceof java.net.SocketTimeoutException)) {
            // the JDK's wording for a reset during the handshake, "Connection reset"
            SSLException out = new SSLException(e.getMessage());
            out.initCause(e);
            return out;
        }
        return e; // timeouts, as they are
    }

    @Override
    public SSLSession getSession() {
        try {
            startHandshake();
        } catch (IOException e) {
            return FingerprintSslContext.NULL_SESSION;
        }
        return session;
    }

    @Override
    public SSLSession getHandshakeSession() {
        return null;
    }

    @Override
    public String getApplicationProtocol() {
        if (session == null) return null;
        String p = connection.applicationProtocol();
        return p == null ? "" : p;
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        listeners.remove(listener);
    }

    // --- configuration ---

    @Override
    public synchronized SSLParameters getSSLParameters() {
        SSLParameters copy = new SSLParameters(parameters.getCipherSuites(), enabledProtocols.clone());
        copy.setServerNames(parameters.getServerNames());
        copy.setApplicationProtocols(parameters.getApplicationProtocols());
        copy.setEndpointIdentificationAlgorithm(parameters.getEndpointIdentificationAlgorithm());
        copy.setUseCipherSuitesOrder(parameters.getUseCipherSuitesOrder());
        return copy;
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters params) {
        SSLParameters copy = new SSLParameters(getSupportedCipherSuites(),
                params.getProtocols() != null ? params.getProtocols() : enabledProtocols);
        copy.setServerNames(params.getServerNames() != null ? params.getServerNames() : parameters.getServerNames());
        copy.setApplicationProtocols(params.getApplicationProtocols());
        copy.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        parameters = copy;
        if (params.getProtocols() != null) setEnabledProtocols(params.getProtocols());
    }

    @Override
    public String[] getSupportedCipherSuites() {
        List<String> names = new ArrayList<>();
        for (io.github.mahmoudimus.quic.CipherSuite s : settings.config().profile().tls13CipherSuites()) names.add(s.name());
        for (Tls12CipherSuite s : settings.config().profile().tls12CipherSuites()) names.add(s.name());
        return names.toArray(String[]::new);
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return getSupportedCipherSuites();
    }

    /** Ignored: the profile's cipher suites are part of its fingerprint. */
    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
        return new String[] {TLS13, TLS12};
    }

    @Override
    public synchronized String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols) {
        List<String> supported = List.of(getSupportedProtocols());
        for (String p : protocols) {
            if (!supported.contains(p)) throw new IllegalArgumentException("Unsupported protocol: " + p);
        }
        enabledProtocols = protocols.clone();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        if (!mode) throw new IllegalArgumentException("a browser-fingerprint socket is a client only");
    }

    @Override
    public boolean getUseClientMode() {
        return true;
    }

    @Override
    public void setNeedClientAuth(boolean need) {}

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {}

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {}

    @Override
    public boolean getEnableSessionCreation() {
        return true;
    }

    // --- streams ---

    @Override
    public InputStream getInputStream() throws IOException {
        startHandshake();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        startHandshake();
        return out;
    }

    private final class TlsInput extends InputStream {
        private byte[] buffer = new byte[0];
        private int pos;

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            while (pos >= buffer.length) {
                byte[] next = connection.read();
                if (next == null) return -1;
                buffer = next;
                pos = 0;
            }
            int n = Math.min(len, buffer.length - pos);
            System.arraycopy(buffer, pos, b, off, n);
            pos += n;
            return n;
        }

        @Override
        public int available() {
            return buffer.length - pos;
        }

        @Override
        public void close() throws IOException {
            FingerprintSslSocket.this.close();
        }
    }

    private final class TlsOutput extends OutputStream {
        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            connection.write(b, off, len);
        }

        @Override
        public void close() throws IOException {
            FingerprintSslSocket.this.close();
        }
    }

    // --- the socket underneath ---

    @Override
    public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        if (connection != null) {
            try {
                connection.closeWrite();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
        if (autoClose) plain.close();
    }

    private void closeQuietly() {
        closed = true;
        if (autoClose) {
            try {
                plain.close();
            } catch (IOException ignored) {
                // already failing
            }
        }
    }

    @Override
    public void shutdownOutput() throws IOException {
        if (connection != null) connection.closeWrite();
        plain.shutdownOutput();
    }

    @Override
    public void shutdownInput() throws IOException {
        plain.shutdownInput();
    }

    @Override
    public boolean isClosed() {
        return closed || plain.isClosed();
    }

    @Override
    public boolean isConnected() {
        return plain.isConnected();
    }

    @Override
    public boolean isBound() {
        return plain.isBound();
    }

    @Override
    public boolean isInputShutdown() {
        return plain.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return plain.isOutputShutdown();
    }

    @Override
    public InetAddress getInetAddress() {
        return plain.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return plain.getLocalAddress();
    }

    @Override
    public int getPort() {
        return plain.getPort();
    }

    @Override
    public int getLocalPort() {
        return plain.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return plain.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return plain.getLocalSocketAddress();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        plain.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return plain.getSoTimeout();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        plain.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return plain.getTcpNoDelay();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        plain.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return plain.getKeepAlive();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        plain.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return plain.getSoLinger();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        plain.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return plain.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        plain.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return plain.getReceiveBufferSize();
    }

    @Override
    public String toString() {
        return "FingerprintSslSocket[" + settings.config().profile().name() + " " + plain + "]";
    }
}
