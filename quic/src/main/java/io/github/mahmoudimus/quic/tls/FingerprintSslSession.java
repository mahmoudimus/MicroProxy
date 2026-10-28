package io.github.mahmoudimus.quic.tls;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

/** The {@link javax.net.ssl.SSLSession} of a {@link FingerprintSslSocket}'s completed handshake. */
final class FingerprintSslSession extends ExtendedSSLSession {

    private final TlsClientConnection connection;
    private final String peerHost;
    private final int peerPort;
    private final long created = System.currentTimeMillis();
    private final Map<String, Object> values = new ConcurrentHashMap<>();
    private volatile boolean valid = true;

    FingerprintSslSession(TlsClientConnection connection, String peerHost, int peerPort) {
        this.connection = connection;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
    }

    @Override
    public byte[] getId() {
        return connection.sessionId();
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return null;
    }

    @Override
    public long getCreationTime() {
        return created;
    }

    @Override
    public long getLastAccessedTime() {
        return created;
    }

    @Override
    public void invalidate() {
        valid = false;
    }

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public void putValue(String name, Object value) {
        values.put(name, value);
    }

    @Override
    public Object getValue(String name) {
        return values.get(name);
    }

    @Override
    public void removeValue(String name) {
        values.remove(name);
    }

    @Override
    public String[] getValueNames() {
        return values.keySet().toArray(String[]::new);
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        List<X509Certificate> chain = connection.peerCertificates();
        if (chain.isEmpty()) throw new SSLPeerUnverifiedException("peer not authenticated");
        return chain.toArray(Certificate[]::new);
    }

    @Override
    public Certificate[] getLocalCertificates() {
        List<X509Certificate> chain = connection.localCertificates();
        return chain.isEmpty() ? null : chain.toArray(Certificate[]::new);
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return ((X509Certificate) getPeerCertificates()[0]).getSubjectX500Principal();
    }

    @Override
    public Principal getLocalPrincipal() {
        List<X509Certificate> chain = connection.localCertificates();
        return chain.isEmpty() ? null : chain.get(0).getSubjectX500Principal();
    }

    @Override
    public String getCipherSuite() {
        return connection.cipherSuiteName();
    }

    @Override
    public String getProtocol() {
        return connection.protocol();
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    @Override
    public int getPacketBufferSize() {
        return TlsRecordLayer.MAX_FRAGMENT + 256 + 5;
    }

    @Override
    public int getApplicationBufferSize() {
        return TlsRecordLayer.MAX_FRAGMENT;
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        return new String[0];
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms() {
        return new String[0];
    }

    /** The server name this client sent, as a client's JDK session reports it. */
    @Override
    public List<SNIServerName> getRequestedServerNames() {
        String name = connection.serverName();
        return name == null ? List.of() : List.of(new SNIHostName(name));
    }

    @Override
    public String toString() {
        return "FingerprintSslSession[" + getProtocol() + " " + getCipherSuite() + " " + peerHost + ":" + peerPort + "]";
    }
}
