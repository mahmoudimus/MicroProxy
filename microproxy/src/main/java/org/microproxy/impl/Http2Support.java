package org.microproxy.impl;

/**
 * Whether the optional {@code http2-codec} module is on the class path. HTTP/2 can only be enabled
 * with it; the classes that use it ({@link Http2Connection}, {@link Http2StreamChannel}) are only
 * loaded once it is known to be present, so the proxy runs without it.
 */
final class Http2Support {

    /** What a server enabling HTTP/2 without the module fails with. */
    static final String MISSING = "HTTP/2 is enabled (withHttp2, --http2 or http2=true) but the http2-codec module"
            + " (io.github.mahmoudimus:http2-codec) is not on the class path; add its jar to the class path or"
            + " use the microproxy-starlark -all jar, which bundles it";

    private static final boolean PRESENT = present();

    /** Overrides the class-path check, for tests that simulate a missing module; null for none. */
    static volatile Boolean presentForTesting;

    private Http2Support() {}

    static boolean available() {
        Boolean forced = presentForTesting;
        return forced != null ? forced : PRESENT;
    }

    private static boolean present() {
        try {
            Class.forName("io.github.mahmoudimus.http2.FrameReader", false, Http2Support.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }
}
