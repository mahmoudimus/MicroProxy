package org.microproxy.impl;

import java.lang.System.Logger.Level;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Whether the optional {@code http2-codec} module is on the class path. HTTP/2 can only be enabled
 * with it; the classes that use it ({@link Http2Endpoint} and its subclasses, {@link
 * Http2StreamChannel}, {@link Http2UpstreamStream}) are only loaded once it is known to be
 * present, so the proxy runs without it ({@code Http2CodecAbsentTest} runs it so).
 *
 * <p>HTTP/2 to clients and to servers is on by default: without the module, a proxy that leaves
 * them at their defaults speaks HTTP/1.1 and says so once ({@link #defaultsFallBack}), while one
 * that enables any kind of HTTP/2 explicitly fails to start ({@link #MISSING}).
 */
final class Http2Support {

    private static final System.Logger LOG = System.getLogger(Http2Support.class.getName());

    /** What a server enabling HTTP/2 explicitly without the module fails with. */
    static final String MISSING = "HTTP/2 is enabled (withHttp2, withHttp2Upstream or withHttp2Cleartext; --http2,"
            + " --http2-upstream or --http2-cleartext; http2, http2_upstream or http2_cleartext) but the http2-codec module"
            + " (io.github.mahmoudimus:http2-codec) is not on the class path; add its jar to the class path or"
            + " use the microproxy-starlark -all jar, which bundles it (left at their defaults, HTTP/2 to clients and"
            + " to servers falls back to HTTP/1.1 without it)";

    private static final boolean PRESENT = present();

    /** Whether {@link #defaultsFallBack} has logged at INFO (reset by tests). */
    static final AtomicBoolean FALLBACK_LOGGED = new AtomicBoolean();

    /** Overrides the class-path check, for tests that simulate a missing module; null for none. */
    static volatile Boolean presentForTesting;

    private Http2Support() {}

    static boolean available() {
        Boolean forced = presentForTesting;
        return forced != null ? forced : PRESENT;
    }

    /**
     * Notes that a server leaves HTTP/2 at its default (on) without the module, and so speaks
     * HTTP/1.1 only: logged at INFO the first time, then at DEBUG, so that a process starting many
     * servers says it once.
     */
    static void defaultsFallBack() {
        boolean first = FALLBACK_LOGGED.compareAndSet(false, true);
        LOG.log(first ? Level.INFO : Level.DEBUG, "HTTP/2 is on by default but the http2-codec module"
                + " (io.github.mahmoudimus:http2-codec) is not on the class path: clients and servers get HTTP/1.1;"
                + " add its jar for HTTP/2, or turn it off (withHttp2(false) and withHttp2Upstream(false),"
                + " --no-http2 and --no-http2-upstream) to silence this");
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
