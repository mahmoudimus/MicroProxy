package org.microproxy.bench;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import org.microproxy.tls.CertificateAuthority;

/**
 * One of the proxies being compared, started on loopback for one benchmark trial. Both proxies
 * are configured from the same {@link Options} with the same values ({@link #IDLE_TIMEOUT}, {@link
 * #CONNECT_TIMEOUT_MILLIS}, the parser limits, the {@code Via} alias), without access logs,
 * metrics or any other extra, and keep their default per-client-connection server connections
 * (neither shares a pool between clients). What cannot be made equal is listed in
 * {@code docs/project/benchmarks.md}.
 */
public interface ProxyUnderTest extends AutoCloseable {

    /** The {@code @Param} value of MicroProxy. */
    String MICROPROXY = "microproxy";

    /** The {@code @Param} value of LittleProxy. */
    String LITTLEPROXY = "littleproxy";

    /** Both proxies, in the order they are reported. */
    List<String> ALL = List.of(MICROPROXY, LITTLEPROXY);

    /** How long either proxy keeps an idle client or server connection (both proxies' default). */
    Duration IDLE_TIMEOUT = Duration.ofSeconds(70);

    /** How long either proxy waits for a server connection (both proxies' default). */
    int CONNECT_TIMEOUT_MILLIS = 40_000;

    /** The longest request or status line either proxy accepts. */
    int MAX_INITIAL_LINE_LENGTH = 8192;

    /** The largest request or response head either proxy accepts. */
    int MAX_HEADER_SIZE = 16384;

    /** The largest piece of a body either proxy reads at once. */
    int MAX_CHUNK_SIZE = 16384;

    /** The name both proxies put in their {@code Via} header, so they forward the same bytes. */
    String ALIAS = "bench";

    /** The request header the benchmark filter adds (and the origin reports back). */
    String FILTER_REQUEST_HEADER = Origin.ECHO_TRIGGER;

    /** The response header the benchmark filter adds. */
    String FILTER_RESPONSE_HEADER = "X-Bench-Res";

    /**
     * What a trial's proxy does beyond forwarding.
     *
     * @param mitm the CA to intercept CONNECT tunnels with (signing leaf certificates the same way
     *     in both proxies), or {@code null} to tunnel them untouched
     * @param filter whether to install the benchmark filter, which adds {@link
     *     #FILTER_REQUEST_HEADER} to requests and {@link #FILTER_RESPONSE_HEADER} to responses
     */
    record Options(CertificateAuthority mitm, boolean filter) {

        /** A plain forwarding proxy: no interception, no filter. */
        public static final Options PLAIN = new Options(null, false);
    }

    /** {@return the address clients connect to} */
    InetSocketAddress address();

    /** Stops the proxy and closes its connections; not part of any measurement. */
    @Override
    void close();

    /**
     * Starts the proxy named {@code name} ({@link #MICROPROXY} or {@link #LITTLEPROXY}).
     *
     * @param name which proxy
     * @param options what it does beyond forwarding
     * @return the running proxy
     */
    static ProxyUnderTest start(String name, Options options) {
        return switch (name) {
            case MICROPROXY -> MicroProxyUnderTest.start(options);
            case LITTLEPROXY -> LittleProxyUnderTest.start(options);
            default -> throw new IllegalArgumentException("unknown proxy " + name + ", expected one of " + ALL);
        };
    }

    /** {@return the address both proxies listen on: loopback, on an ephemeral port} */
    static InetSocketAddress listenAddress() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
    }
}
