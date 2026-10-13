package org.microproxy.bench;

import io.netty.handler.codec.http.HttpRequest;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import org.littleshoot.proxy.MitmManager;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * A minimal LittleProxy {@link MitmManager} that intercepts the way MicroProxy's {@link
 * CertificateAuthorityMitmManager} does, by delegating to one: leaf certificates issued by the same
 * CA, for the CONNECT host plus the real server's names, with one EC key, cached per host; and
 * servers validated against the same trust anchors, with SNI and HTTPS host-name verification.
 * LittleProxy's own {@code SelfSignedMitmManager} presents one self-signed certificate for every
 * host and trusts every server, so it would not be the same work.
 */
final class LittleProxyMitmManager implements MitmManager {

    private final CertificateAuthorityMitmManager delegate;

    LittleProxyMitmManager(CertificateAuthority authority) {
        this.delegate = new CertificateAuthorityMitmManager(authority, authority.clientContext());
    }

    @Override
    public SSLEngine serverSslEngine(String peerHost, int peerPort) {
        SSLEngine engine = delegate.serverSslContext(peerHost, peerPort).createSSLEngine(peerHost, peerPort);
        engine.setUseClientMode(true);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        engine.setSSLParameters(parameters);
        return engine;
    }

    @Override
    public SSLEngine serverSslEngine() {
        SSLEngine engine = delegate.serverSslContext(null, -1).createSSLEngine();
        engine.setUseClientMode(true);
        return engine;
    }

    @Override
    public SSLEngine clientSslEngineFor(HttpRequest httpRequest, SSLSession serverSslSession) {
        // MicroProxy's manager reads only the CONNECT target from the request.
        DefaultHttpRequest connect = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, httpRequest.uri());
        SSLEngine engine = delegate.clientSslContextFor(connect, serverSslSession).createSSLEngine();
        engine.setUseClientMode(false);
        return engine;
    }
}
