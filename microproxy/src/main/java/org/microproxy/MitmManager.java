package org.microproxy;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.microproxy.http.HttpRequest;

/**
 * Enables man-in-the-middle interception of CONNECT tunnels. The proxy opens its own TLS
 * connection to the server, then completes the client's handshake with a certificate supplied
 * here, and finally proxies the decrypted requests through the normal {@link HttpFilters}.
 *
 * @see org.microproxy.mitm.CertificateAuthorityMitmManager
 */
public interface MitmManager {

    /** TLS configuration for the proxy's connection to the real server (proxy is TLS client). */
    SSLContext serverSslContext(String peerHost, int peerPort);

    /**
     * TLS configuration presented to the client (proxy is TLS server), typically holding a
     * certificate for the requested host signed by a CA the client trusts.
     *
     * @param connectRequest the client's CONNECT request
     * @param serverSslSession the established session with the real server
     */
    SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession);

    /**
     * Customizes the socket to the real server before its handshake. By default the proxy enables
     * SNI and HTTPS host-name verification; override to relax that.
     */
    default void configureServerSocket(SSLSocket socket) {}
}
