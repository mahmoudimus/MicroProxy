package org.microproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A client's TLS {@code ClientHello}, the first message of a handshake, as the proxy read it before
 * deciding whether to intercept a connection: after a {@code CONNECT} is accepted, and first thing
 * on a connection to a {@linkplain HttpProxyServerBootstrap#withTransparent transparent} listener.
 * The proxy reads it without consuming it: the same bytes then start the handshake the proxy
 * completes itself, or are relayed to the server when the connection is tunnelled.
 *
 * <p>Filters see it in {@link HttpFilters#proxyToServerAllowMitm(ClientHello)}, MITM managers in
 * {@link MitmManager#shouldIntercept(ClientHello, FlowContext)}, and anything holding the client
 * connection's {@link FlowContext} through {@link FlowContext#getClientHello()}.
 *
 * <p>Values are as the client sent them, GREASE values (RFC 8701) included, except for {@link
 * #sni()}, which is only set for a single, well-formed host name.
 *
 * @param sni the host name the client asked for (Server Name Indication), or {@code null} when it
 *     sent none, or one that is not a valid host name
 * @param alpnProtocols the application protocols the client offered (ALPN), in its order of
 *     preference, decoded as ISO-8859-1; empty without the extension
 * @param versions the TLS versions the client offered, as wire values ({@code 0x0304} is TLS 1.3):
 *     those of the {@code supported_versions} extension, or else the message's legacy version
 * @param cipherSuites the cipher suites the client offered, as wire values
 * @param extensionTypes the types of the extensions the client sent, in order
 * @param raw the handshake message: its type ({@code 1}), 3-byte length and body, without the TLS
 *     record headers it arrived in
 */
public record ClientHello(
        String sni,
        List<String> alpnProtocols,
        List<Integer> versions,
        List<Integer> cipherSuites,
        List<Integer> extensionTypes,
        byte[] raw) {

    /** The ALPN identifier of HTTP/2 over TLS. */
    public static final String H2 = "h2";
    /** The ALPN identifier of HTTP/1.1. */
    public static final String HTTP_1_1 = "http/1.1";
    /** The ALPN identifier of HTTP/1.0. */
    public static final String HTTP_1_0 = "http/1.0";

    /**
     * Creates a ClientHello, copying the lists and the message bytes.
     *
     * @param sni the requested host name, or {@code null}
     * @param alpnProtocols the offered application protocols
     * @param versions the offered TLS versions, as wire values
     * @param cipherSuites the offered cipher suites, as wire values
     * @param extensionTypes the types of the extensions sent
     * @param raw the handshake message, without record headers
     * @throws NullPointerException if a list or {@code raw} is null
     */
    public ClientHello {
        alpnProtocols = List.copyOf(alpnProtocols);
        versions = List.copyOf(versions);
        cipherSuites = List.copyOf(cipherSuites);
        extensionTypes = List.copyOf(extensionTypes);
        raw = raw.clone();
    }

    /** {@return a copy of the handshake message bytes} */
    @Override
    public byte[] raw() {
        return raw.clone();
    }

    /**
     * The offered TLS versions by name ({@code "TLSv1.3"}, {@code "TLSv1.2"}, ...), as the JDK
     * names them, without GREASE and unknown values.
     *
     * @return the offered TLS versions by name, in the client's order
     */
    public List<String> versionNames() {
        List<String> names = new ArrayList<>(versions.size());
        for (int version : versions) {
            String name = switch (version) {
                case 0x0304 -> "TLSv1.3";
                case 0x0303 -> "TLSv1.2";
                case 0x0302 -> "TLSv1.1";
                case 0x0301 -> "TLSv1";
                case 0x0300 -> "SSLv3";
                default -> null;
            };
            if (name != null && !names.contains(name)) names.add(name);
        }
        return List.copyOf(names);
    }

    /**
     * Whether the client offered {@code protocol} through ALPN.
     *
     * @param protocol an ALPN identifier, such as {@link #H2}
     * @return whether the client offered it
     */
    public boolean offersAlpn(String protocol) {
        return alpnProtocols.contains(protocol);
    }

    /**
     * Whether a value is a GREASE value (RFC 8701), which clients add to lists of cipher suites,
     * extensions, versions and ALPN protocols to keep servers tolerant of unknown values.
     *
     * @param value a two-byte wire value
     * @return whether {@code value} is one of the reserved {@code 0x?A?A} values
     */
    public static boolean isGrease(int value) {
        return (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ClientHello that && Arrays.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "ClientHello[sni=" + sni + ", alpn=" + alpnProtocols + ", versions=" + versionNames()
                + ", cipherSuites=" + cipherSuites.size() + ", " + raw.length + " bytes]";
    }

    /**
     * The client's ALPN protocols that the proxy can speak over TLS: {@code h2} (when {@code
     * withHttp2} is set), {@code http/1.1} and {@code http/1.0}, in the client's order.
     *
     * @param http2 whether HTTP/2 may be included
     * @return the HTTP protocols the client offered, possibly empty
     */
    public List<String> httpAlpnProtocols(boolean http2) {
        List<String> http = new ArrayList<>(alpnProtocols.size());
        for (String p : alpnProtocols) {
            if ((http2 && H2.equals(p)) || HTTP_1_1.equals(p) || HTTP_1_0.equals(p)) {
                if (!http.contains(p)) http.add(p);
            }
        }
        return List.copyOf(http);
    }
}
