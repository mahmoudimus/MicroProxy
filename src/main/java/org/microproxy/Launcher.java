package org.microproxy;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;

/** Command-line entry point. Run with {@code --help} for options. */
public final class Launcher {

    private static final String USAGE = """
            Usage: java -jar microproxy.jar [options]

              --config <file>              properties file (see README); flags override it
              --port <port>                listen port (default 8080)
              --address <host:port>        listen address
              --server                     listen on all interfaces, not just loopback
              --name <name>                server name for logs and threads
              --transparent                do not add Via / strip hop-by-hop headers
              --idle-timeout <seconds>     idle connection timeout (default 70, 0 = none)
              --connect-timeout <millis>   outbound connect timeout (default 40000)
              --proxy-alias <alias>        name used in Via headers
              --throttle <read> <write>    global server bandwidth limits in bytes/s
              --accept-proxy-protocol      require a PROXY protocol header on inbound connections
              --send-proxy-protocol        send a PROXY protocol v1 header upstream
              --mitm                       intercept HTTPS with a generated CA
              --mitm-ca <file.p12>         CA key store for --mitm (created if missing;
                                           default ./microproxy-ca.p12)
              --mitm-ca-password <pw>      key store password (default "microproxy")
              --mitm-trust-all             do not validate upstream server certificates
              --help                       show this help
            """;

    private Launcher() {}

    public static void main(String[] args) throws IOException {
        HttpProxyServer server = start(args, System.out);
        if (server != null) {
            Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "microproxy-shutdown"));
        }
    }

    /** Parses {@code args} and starts the proxy; returns null if only help was printed. */
    static HttpProxyServer start(String[] args, PrintStream console) throws IOException {
        Deque<String> queue = new ArrayDeque<>(List.of(args));
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap();
        boolean mitm = false;
        boolean mitmTrustAll = false;
        Path caPath = Path.of("microproxy-ca.p12");
        String caPassword = "microproxy";
        if (queue.contains("--config")) {
            List<String> all = List.copyOf(queue);
            int i = all.indexOf("--config");
            if (i + 1 >= all.size()) throw new IllegalArgumentException("--config needs a value");
            bootstrap = MicroProxy.bootstrapFromFile(Path.of(all.get(i + 1)));
        }
        while (!queue.isEmpty()) {
            String arg = queue.poll();
            switch (arg) {
                case "--help", "-h" -> {
                    console.print(USAGE);
                    return null;
                }
                case "--config" -> value(queue, arg);
                case "--port" -> bootstrap.withPort(Integer.parseInt(value(queue, arg)));
                case "--address" -> {
                    String[] parts = value(queue, arg).split(":(?=[0-9]+$)");
                    bootstrap.withAddress(new InetSocketAddress(parts[0], parts.length > 1 ? Integer.parseInt(parts[1]) : 8080));
                }
                case "--server" -> bootstrap.withAllowLocalOnly(false);
                case "--name" -> bootstrap.withName(value(queue, arg));
                case "--transparent" -> bootstrap.withTransparent(true);
                case "--idle-timeout" -> bootstrap.withIdleConnectionTimeout(Integer.parseInt(value(queue, arg)));
                case "--connect-timeout" -> bootstrap.withConnectTimeout(Integer.parseInt(value(queue, arg)));
                case "--proxy-alias" -> bootstrap.withProxyAlias(value(queue, arg));
                case "--throttle" -> bootstrap.withThrottling(
                        Long.parseLong(value(queue, arg)), Long.parseLong(value(queue, arg)));
                case "--accept-proxy-protocol" -> bootstrap.withAcceptProxyProtocol(true);
                case "--send-proxy-protocol" -> bootstrap.withSendProxyProtocol(true);
                case "--mitm" -> mitm = true;
                case "--mitm-ca" -> caPath = Path.of(value(queue, arg));
                case "--mitm-ca-password" -> caPassword = value(queue, arg);
                case "--mitm-trust-all" -> mitmTrustAll = true;
                default -> throw new IllegalArgumentException("unknown option: " + arg + "\n\n" + USAGE);
            }
        }
        if (mitm) {
            CertificateAuthority ca = CertificateAuthority.loadOrCreate(caPath, caPassword.toCharArray(), "MicroProxy CA");
            Path pem = caPath.resolveSibling(stripExtension(caPath.getFileName().toString()) + ".pem");
            ca.writeCertificatePem(pem);
            console.println("MITM enabled; trust the CA certificate in " + pem.toAbsolutePath());
            bootstrap.withManInTheMiddle(mitmTrustAll
                    ? new CertificateAuthorityMitmManager(ca, SslContexts.trustAll())
                    : new CertificateAuthorityMitmManager(ca));
        }
        HttpProxyServer server = bootstrap.start();
        console.println("MicroProxy listening on " + server.getListenAddress());
        return server;
    }

    private static String value(Deque<String> queue, String option) {
        String v = queue.poll();
        if (v == null) throw new IllegalArgumentException(option + " needs a value");
        return v;
    }

    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }
}
