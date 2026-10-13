package org.microproxy.bench;

import java.net.InetAddress;
import javax.net.ssl.SSLContext;
import org.microproxy.tls.CertificateAuthority;

/**
 * The TLS material the MITM benchmarks share: one test CA, made once per JVM, that issues the
 * origin's certificate and that both proxies impersonate servers with; and the one client context
 * that trusts only it.
 */
public final class BenchTls {

    private static final CertificateAuthority AUTHORITY = CertificateAuthority.generate("MicroProxy benchmark CA");
    private static final SSLContext ORIGIN = AUTHORITY.serverContext(InetAddress.getLoopbackAddress().getHostAddress());
    private static final SSLContext CLIENT = AUTHORITY.clientContext();

    private BenchTls() {}

    /** {@return the test CA} */
    public static CertificateAuthority authority() {
        return AUTHORITY;
    }

    /** {@return the origin's TLS context: a certificate for the loopback address, issued by the CA} */
    public static SSLContext originContext() {
        return ORIGIN;
    }

    /** {@return the client's TLS context, which trusts only the CA} */
    public static SSLContext clientContext() {
        return CLIENT;
    }
}
