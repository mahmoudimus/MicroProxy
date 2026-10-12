package org.microproxy.impl;

/**
 * Whether the optional {@code quic} and {@code http3-codec} modules are both on the class path.
 * HTTP/3 can only be enabled with them; the classes that use them ({@code Http3Endpoint} and its
 * subclasses, {@code Http3StreamChannel}, {@code Http3UpstreamStream}, {@code Http3Listener},
 * {@code Http3Origins}, {@code TransparentQuicListener}, {@code QuicClientHello}) are only loaded once they are known to be present, so the proxy runs
 * without them ({@code Http3CodecAbsentTest} runs it so).
 */
final class Http3Support {

    /** What a server enabling HTTP/3 without the modules fails with. */
    static final String MISSING = "HTTP/3 is enabled (withHttp3, withHttp3Upstream or withTransparentQuicPort; --http3,"
            + " --http3-upstream or --transparent-quic-port; http3, http3_upstream or transparent_quic_port) but the quic"
            + " and http3-codec modules (io.github.mahmoudimus:quic,"
            + " io.github.mahmoudimus:http3-codec) are not both on the class path; add their jars to the class path"
            + " or use the microproxy-starlark -all jar, which bundles them";

    private static final boolean PRESENT = present("io.github.mahmoudimus.quic.QuicServer")
            && present("io.github.mahmoudimus.http3.QpackEncoder");

    /** Overrides the class-path check, for tests that simulate missing modules; null for none. */
    static volatile Boolean presentForTesting;

    private Http3Support() {}

    static boolean available() {
        Boolean forced = presentForTesting;
        return forced != null ? forced : PRESENT;
    }

    private static boolean present(String className) {
        try {
            Class.forName(className, false, Http3Support.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }
}
