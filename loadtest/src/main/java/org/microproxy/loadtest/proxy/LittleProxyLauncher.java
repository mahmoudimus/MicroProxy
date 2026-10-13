package org.microproxy.loadtest.proxy;

import java.net.InetSocketAddress;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import org.littleshoot.proxy.impl.ThreadPoolConfiguration;

/**
 * Starts LittleProxy, the baseline, as a plain forward proxy configured like MicroProxy's launcher
 * and like the JMH benchmarks' {@code LittleProxyUnderTest}: listening on a loopback port, the same
 * idle and connect timeouts, the same initial-line, header and chunk limits (8192, 16384 and 16384
 * bytes, MicroProxy's defaults), the same {@code Via} alias, no filters and no MITM. Netty's worker
 * pools keep their defaults unless {@code --workers} overrides both of them. Logging goes through
 * SLF4J's simple binding at {@code org.slf4j.simpleLogger.defaultLogLevel} ({@code littleproxy}
 * sub-command).
 */
public final class LittleProxyLauncher {

    private LittleProxyLauncher() {}

    /** {@code littleproxy --port p --idle-timeout seconds --connect-timeout millis [--workers n]}. */
    public static void main(String[] args) throws InterruptedException {
        int port = 8080;
        int idle = 70;
        int connect = 40_000;
        int workers = 0;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port" -> port = Integer.parseInt(args[++i]);
                case "--idle-timeout" -> idle = Integer.parseInt(args[++i]);
                case "--connect-timeout" -> connect = Integer.parseInt(args[++i]);
                case "--workers" -> workers = Integer.parseInt(args[++i]);
                default -> throw new IllegalArgumentException("unknown littleproxy option " + args[i]);
            }
        }
        var bootstrap = DefaultHttpProxyServer.bootstrap()
                .withName("littleproxy")
                .withAddress(new InetSocketAddress("127.0.0.1", port))
                .withIdleConnectionTimeout(idle)
                .withConnectTimeout(connect)
                .withProxyAlias("loadtest")
                .withMaxInitialLineLength(8192)
                .withMaxHeaderSize(16384)
                .withMaxChunkSize(16384);
        if (workers > 0) {
            bootstrap.withThreadPoolConfiguration(new ThreadPoolConfiguration()
                    .withClientToProxyWorkerThreads(workers)
                    .withProxyToServerWorkerThreads(workers));
        }
        HttpProxyServer server = bootstrap.start();
        System.out.println("LittleProxy listening on " + server.getListenAddress());
        Runtime.getRuntime().addShutdownHook(new Thread(server::abort, "littleproxy-shutdown"));
        Thread.currentThread().join();
    }
}
