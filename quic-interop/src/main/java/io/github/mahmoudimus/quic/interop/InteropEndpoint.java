package io.github.mahmoudimus.quic.interop;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicClient;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicServer;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.KeyLog;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.ClientSessionStore;
import io.github.mahmoudimus.quic.tls.SessionTicket;
import io.github.mahmoudimus.quic.tls.Ticketer;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import io.github.mahmoudimus.quic.params.TransportParameters;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Optional QUIC Interop Runner application. It does not participate in proxy routing. */
public final class InteropEndpoint {
    private static final Set<String> BOTH = Set.of("handshake", "transfer", "retry", "chacha20",
            "multiconnect", "resumption", "zerortt", "http3", "rebind-port", "rebind-addr");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(25);
    private static final Duration CLIENT_TIMEOUT = Duration.ofMinutes(5);

    private InteropEndpoint() {}

    public static void main(String[] arguments) {
        System.exit(execute(System.getenv()));
    }

    static boolean supports(String role, String testcase) {
        return (role.equals("client") || role.equals("server"))
                && (BOTH.contains(testcase) || role.equals("client") && testcase.equals("keyupdate"));
    }

    static int execute(Map<String, String> environment) {
        String role = environment.getOrDefault("ROLE", "");
        String testcase = environment.getOrDefault("TESTCASE", "");
        // The runner depends on 127 for unsupported cases, even without certificates or network.
        if (!supports(role, testcase)) {
            System.err.println("Unsupported role/testcase: " + role + "/" + testcase);
            return 127;
        }
        try {
            Options options = Options.from(environment);
            if (role.equals("server")) {
                try (EndpointServer server = startServer(options, new InetSocketAddress("::", options.port()))) {
                    server.acceptLoop();
                }
            } else {
                runClient(options);
            }
            return 0;
        } catch (Exception e) {
            System.err.println("Interop endpoint failed: " + e);
            for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
                System.err.println("Caused by: " + cause);
            }
            return 1;
        }
    }

    record Options(String testcase, int port, Path www, Path downloads, Path certs, String requests,
            Path keyLog, Path qlog) {
        static Options from(Map<String, String> env) {
            int port = Integer.parseInt(env.getOrDefault("PORT", "443"));
            if (port < 0 || port > 65535) throw new IllegalArgumentException("invalid port");
            return new Options(env.get("TESTCASE"), port, Path.of(env.getOrDefault("WWW", "/www")),
                    Path.of(env.getOrDefault("DOWNLOADS", "/downloads")), Path.of(env.getOrDefault("CERTS", "/certs")),
                    env.getOrDefault("REQUESTS", ""), optionalPath(env, "SSLKEYLOGFILE"), optionalPath(env, "QLOGDIR"));
        }

        boolean h3() { return testcase.equals("http3"); }
        boolean early() { return testcase.equals("zerortt"); }
        String alpn() { return h3() ? "h3" : "hq-interop"; }

        private static Path optionalPath(Map<String, String> env, String name) {
            String value = env.get(name);
            return value == null || value.isBlank() ? null : Path.of(value);
        }
    }

    private static TransportConfig transport(Options options, String role) throws IOException {
        TransportConfig.Builder builder = TransportConfig.builder().maxIdleTimeout(Duration.ofSeconds(45));
        if (options.testcase().equals("transfer")) {
            builder.streamReceiveWindow(32 * 1024).receiveWindow(64 * 1024);
        }
        // These tiny 0-RTT requests gain nothing from MTU probes. Their padded payload would
        // otherwise dominate the runner's measurement of application bytes sent in 1-RTT.
        if (options.early() && role.equals("client")) builder.mtuDiscovery(false);
        if (options.keyLog() != null) {
            Path parent = options.keyLog().toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            builder.keyLog(KeyLog.file(options.keyLog()));
        }
        if (options.qlog() != null) builder.qlog(new JsonQlogSink(options.qlog(), role));
        return builder.build();
    }

    private static TlsConfig.Builder tls(Options options) {
        TlsConfig.Builder builder = TlsConfig.builder().alpnProtocols(options.alpn()).earlyData(options.early());
        if (options.testcase().equals("chacha20")) builder.cipherSuites(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        return builder;
    }

    static EndpointServer startServer(Options options, InetSocketAddress bind) throws Exception {
        Path root = options.www().toRealPath();
        if (!Files.isDirectory(root)) throw new IOException("WWW is not a directory");
        TlsConfig config = tls(options).certificate(EndpointCertificates.chain(options.certs().resolve("cert.pem")),
                        EndpointCertificates.key(options.certs().resolve("priv.key")))
                .sessionTickets(Ticketer.create()).build();
        ServerConfig server = ServerConfig.builder(config).transport(transport(options, "server"))
                .migration(true).retry(options.testcase().equals("retry")).build();
        return new EndpointServer(QuicServer.bind(bind, server), root, options.h3());
    }

    static final class EndpointServer implements AutoCloseable {
        final QuicServer server;
        final AtomicInteger connections = new AtomicInteger();
        private final Path root;
        private final boolean h3;

        EndpointServer(QuicServer server, Path root, boolean h3) {
            this.server = server;
            this.root = root;
            this.h3 = h3;
        }

        void acceptLoop() throws IOException {
            while (true) {
                QuicConnection connection = server.accept();
                connections.incrementAndGet();
                Thread.ofVirtual().name("interop-connection").start(() -> serve(connection));
            }
        }

        private void serve(QuicConnection connection) {
            try {
                if (h3) Http3Files.control(connection);
                while (true) {
                    QuicStream stream = connection.acceptStream();
                    Thread.ofVirtual().name("interop-stream").start(() -> {
                        try {
                            if (!stream.isBidirectional()) {
                                if (h3) Http3Files.drain(stream);
                                else stream.stopSending(1);
                            } else if (h3) {
                                Http3Files.serve(stream, root);
                            } else {
                                serveHq(stream);
                            }
                        } catch (IOException | RuntimeException e) {
                            try {
                                if (stream.isBidirectional()) stream.reset(1);
                                stream.stopSending(1);
                            } catch (IOException ignored) {
                                // The peer may have closed or reset the stream already.
                            }
                        }
                    });
                }
            } catch (IOException e) {
                // Endpoint or connection closed, including the runner terminating a server.
            }
        }

        private void serveHq(QuicStream stream) throws IOException {
            String path = EndpointFiles.readRequest(stream.getInputStream());
            Path file = EndpointFiles.source(root, path);
            try (InputStream in = Files.newInputStream(file); OutputStream out = stream.getOutputStream()) {
                in.transferTo(out);
            }
        }

        @Override public void close() { server.close(); }
    }

    record Request(URI uri, String host, int port, String path, byte[] hqRequest) {
        static Request parse(String value) throws IOException {
            try {
                URI uri = URI.create(value);
                if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                        || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                        || uri.getPort() == 0 || uri.getPort() > 65535) throw new IOException("invalid download URL: " + value);
                EndpointFiles.relative(uri.getRawPath());
                String host = uri.getHost();
                if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
                return new Request(uri, host, uri.getPort() < 0 ? 443 : uri.getPort(), uri.getRawPath(),
                        ("GET " + uri.getRawPath() + "\r\n").getBytes(StandardCharsets.US_ASCII));
            } catch (IllegalArgumentException e) {
                throw new IOException("invalid download URL", e);
            }
        }
    }

    static void runClient(Options options) throws Exception {
        if (options.requests().isBlank()) throw new IOException("REQUESTS must contain at least one URL");
        List<Request> requests = new ArrayList<>();
        Set<Path> destinations = new HashSet<>();
        for (String value : options.requests().strip().split("\\s+")) {
            Request request = Request.parse(value);
            if (!destinations.add(EndpointFiles.relative(request.path()))) throw new IOException("duplicate download destination");
            requests.add(request);
        }
        Request first = requests.getFirst();
        for (Request request : requests) {
            if (!request.host().equalsIgnoreCase(first.host()) || request.port() != first.port()) {
                throw new IOException("the runner must request one origin per endpoint invocation");
            }
        }
        TlsConfig.Builder tls = tls(options).serverName(first.host());
        Path ca = options.certs().resolve("ca.pem");
        if (Files.exists(ca)) tls.trustManager(EndpointCertificates.trust(ca));
        InetAddress remote = InetAddress.getByName(first.host());
        InetSocketAddress bind = new InetSocketAddress(InetAddress.getByName(remote.getAddress().length == 16 ? "::" : "0.0.0.0"), 0);
        SessionCache memory = SessionCache.memory();
        CountDownLatch ticketReceived = new CountDownLatch(1);
        AtomicReference<SessionTicket> receivedTicket = new AtomicReference<>();
        ClientSessionStore tickets = new ClientSessionStore() {
            @Override public void put(String key, SessionTicket ticket) {
                memory.tickets().put(key, ticket);
                if (first.host().equals(key)) {
                    receivedTicket.set(ticket);
                    ticketReceived.countDown();
                }
            }
            @Override public SessionTicket take(String key) { return memory.tickets().take(key); }
        };
        ClientConfig config = ClientConfig.builder(tls.build()).transport(transport(options, "client"))
                .sessionCache(new SessionCache(tickets, memory.tokens())).build();
        long deadline = System.nanoTime() + CLIENT_TIMEOUT.toNanos();
        try (QuicClient client = QuicClient.create(config, bind, EndpointConfig.defaults())) {
            InetSocketAddress address = new InetSocketAddress(remote, first.port());
            if (options.testcase().equals("multiconnect")) {
                for (Request request : requests) {
                    try (QuicConnection connection = client.connect(address, first.host(), CONNECT_TIMEOUT)) {
                        downloadAll(connection, List.of(request), options, deadline);
                    }
                }
            } else if (options.testcase().equals("resumption") || options.early()) {
                if (requests.size() < 2) throw new IOException("resumption needs at least two requested files");
                try (QuicConnection connection = client.connect(address, first.host(), CONNECT_TIMEOUT)) {
                    downloadAll(connection, requests.subList(0, 1), options, deadline);
                    awaitTicket(ticketReceived, deadline);
                }
                int earlyStreams = options.early() ? earlyStreamLimit(receivedTicket.get(), requests.size() - 1) : 0;
                try (QuicConnection connection = options.early()
                        ? client.connectEarly(address, first.host(), CONNECT_TIMEOUT)
                        : client.connect(address, first.host(), CONNECT_TIMEOUT)) {
                    if (options.early() && !connection.isZeroRtt()) throw new IOException("ticket did not permit early data");
                    if (options.early()) downloadEarly(connection, requests.subList(1, requests.size()), options, deadline, earlyStreams);
                    else downloadAll(connection, requests.subList(1, requests.size()), options, deadline);
                    if (!connection.awaitHandshake(CONNECT_TIMEOUT) || !connection.isResumed()) throw new IOException("session was not resumed");
                    if (options.early() && !connection.earlyDataAccepted()) throw new IOException("0-RTT was rejected");
                }
            } else {
                try (QuicConnection connection = client.connect(address, first.host(), CONNECT_TIMEOUT)) {
                    downloadAll(connection, requests, options, deadline);
                }
            }
        }
    }

    private static void awaitTicket(CountDownLatch ticketReceived, long deadline) throws Exception {
        long wait = Math.min(deadline - System.nanoTime(), Duration.ofSeconds(10).toNanos());
        if (wait <= 0 || !ticketReceived.await(wait, TimeUnit.NANOSECONDS)) {
            throw new IOException("server did not provide a session ticket");
        }
    }

    private static void downloadAll(QuicConnection connection, List<Request> requests, Options options, long deadline) throws Exception {
        downloadAll(connection, requests, options, deadline, null);
    }

    private static int earlyStreamLimit(SessionTicket ticket, int requests) throws IOException {
        if (ticket == null || ticket.transportParameters() == null) throw new IOException("ticket has no remembered transport parameters");
        long streams;
        try {
            streams = TransportParameters.decode(ticket.transportParameters(), true).initialMaxStreamsBidi();
        } catch (io.github.mahmoudimus.quic.QuicException e) {
            throw new IOException("ticket has invalid transport parameters", e);
        }
        if (streams == 0) throw new IOException("server did not permit early request streams");
        return (int) Math.min(streams, requests);
    }

    private static void downloadEarly(QuicConnection connection, List<Request> requests, Options options,
            long deadline, int streamLimit) throws Exception {
        for (int offset = 0; offset < requests.size(); offset += streamLimit) {
            List<Request> batch = requests.subList(offset, Math.min(requests.size(), offset + streamLimit));
            List<QuicStream> streams = new ArrayList<>(batch.size());
            // Queue the complete request flight on the caller before any response task or file
            // preparation. Scheduling a virtual thread and opening a temporary file per request
            // here allowed the handshake to finish after only one GET under CPU emulation.
            for (Request request : batch) {
                QuicStream stream = connection.openBidirectionalStream();
                sendHq(stream, request.hqRequest());
                streams.add(stream);
            }
            // Respect the ticket's stream limit: consuming this batch lets a server grant more.
            downloadAll(connection, batch, options, deadline, streams);
        }
    }

    private static void downloadAll(QuicConnection connection, List<Request> requests, Options options,
            long deadline, List<QuicStream> sentRequests) throws Exception {
        if (options.h3()) Http3Files.control(connection);
        AtomicBoolean keyUpdated = new AtomicBoolean();
        if (options.h3()) Thread.ofVirtual().name("interop-h3-peer-streams").start(() -> {
            try {
                while (true) {
                    QuicStream stream = connection.acceptStream();
                    Thread.ofVirtual().start(() -> {
                        try { Http3Files.drain(stream); }
                        catch (IOException e) { connection.close(0x102, "invalid HTTP/3 peer stream"); }
                    });
                }
            } catch (IOException e) { /* connection closed */ }
        });
        var executor = Executors.newVirtualThreadPerTaskExecutor();
        List<Future<?>> downloads = new ArrayList<>();
        try {
            for (int i = 0; i < requests.size(); i++) {
                Request request = requests.get(i);
                QuicStream sent = sentRequests == null ? null : sentRequests.get(i);
                downloads.add(executor.submit(() -> {
                    QuicStream stream = sent == null ? connection.openBidirectionalStream() : sent;
                    EndpointFiles.download(options.downloads(), request.path(), out -> {
                        if (options.h3()) Http3Files.fetch(stream, request, out);
                        else {
                            if (sent == null) sendHq(stream, request.hqRequest());
                            receiveHq(stream, out, options.testcase().equals("keyupdate"), keyUpdated);
                        }
                    });
                    return null;
                }));
            }
            for (Future<?> download : downloads) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new TimeoutException("client transfer deadline");
                try {
                    download.get(remaining, TimeUnit.NANOSECONDS);
                } catch (ExecutionException e) {
                    throw new IOException("download failed", e.getCause());
                }
            }
            if (options.testcase().equals("keyupdate") && !keyUpdated.get()) throw new IOException("key update did not start");
        } finally {
            for (Future<?> download : downloads) download.cancel(true);
            executor.shutdownNow();
        }
    }

    private static void sendHq(QuicStream stream, byte[] bytes) throws IOException {
        try (OutputStream request = stream.getOutputStream()) {
            request.write(bytes);
        }
    }

    private static void receiveHq(QuicStream stream, OutputStream out, boolean update,
            AtomicBoolean keyUpdated) throws IOException {
        InputStream response = stream.getInputStream();
        byte[] buffer = new byte[16 * 1024];
        long received = 0;
        for (int n; (n = response.read(buffer)) >= 0;) {
            received += n;
            if (update && !keyUpdated.get()) {
                if (stream.connection().updateKeys()) keyUpdated.set(true);
                if (received >= 1_000_000 && !keyUpdated.get()) throw new IOException("key update did not start during first MB");
            }
            out.write(buffer, 0, n);
        }
    }
}
