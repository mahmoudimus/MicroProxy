package org.microproxy.loadtest.proxy;

import java.net.InetSocketAddress;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;

/**
 * Starts LittleProxy, the baseline, as a plain forward proxy configured like MicroProxy's launcher:
 * listening on a loopback port, with the same idle and connect timeouts, no filters, no MITM and
 * Netty's default thread pools ({@code littleproxy} sub-command). Logging goes through SLF4J's
 * simple binding at the level of {@code org.slf4j.simpleLogger.defaultLogLevel}.
 */
public final class LittleProxyLauncher {

    private LittleProxyLauncher() {}

    /** {@code littleproxy --port p --idle-timeout seconds --connect-timeout millis}. */
    public static void main(String[] args) throws InterruptedException {
        int port = 8080;
        int idle = 70;
        int connect = 40_000;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port" -> port = Integer.parseInt(args[++i]);
                case "--idle-timeout" -> idle = Integer.parseInt(args[++i]);
                case "--connect-timeout" -> connect = Integer.parseInt(args[++i]);
                default -> throw new IllegalArgumentException("unknown littleproxy option " + args[i]);
            }
        }
        HttpProxyServer server = DefaultHttpProxyServer.bootstrap()
                .withName("littleproxy")
                .withAddress(new InetSocketAddress("127.0.0.1", port))
                .withIdleConnectionTimeout(idle)
                .withConnectTimeout(connect)
                .start();
        System.out.println("LittleProxy listening on " + server.getListenAddress());
        Runtime.getRuntime().addShutdownHook(new Thread(server::abort, "littleproxy-shutdown"));
        Thread.currentThread().join();
    }
}
