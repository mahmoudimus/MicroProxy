// Ported from rustls src/server/mod.rs (ClientHello, what a server's certificate resolver sees)
// (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import java.util.List;

/**
 * What a server's certificate and ALPN selectors see of a ClientHello. Only code points this
 * handshake supports are listed; others the client offered are left out.
 *
 * @param serverName the host name from {@code server_name} (SNI), lower case without a trailing
 *     dot, or null if the client sent none
 * @param alpnProtocols the application protocols the client offered, in its order of preference;
 *     each protocol's bytes are mapped one to one onto characters (ISO-8859-1)
 * @param signatureSchemes the client's {@code signature_algorithms} that can sign a TLS 1.3
 *     CertificateVerify, in its order of preference
 * @param cipherSuites the client's cipher suites, in its order of preference
 * @param groups the client's {@code supported_groups}, in its order of preference
 */
public record ClientHelloInfo(String serverName, List<String> alpnProtocols, List<SignatureScheme> signatureSchemes,
        List<CipherSuite> cipherSuites, List<NamedGroup> groups) {

    /**
     * Copies the lists.
     *
     * @param serverName the SNI host name, or null
     * @param alpnProtocols the offered application protocols
     * @param signatureSchemes the offered signature schemes
     * @param cipherSuites the offered cipher suites
     * @param groups the offered groups
     */
    public ClientHelloInfo {
        alpnProtocols = List.copyOf(alpnProtocols);
        signatureSchemes = List.copyOf(signatureSchemes);
        cipherSuites = List.copyOf(cipherSuites);
        groups = List.copyOf(groups);
    }
}
