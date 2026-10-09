package org.microproxy;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;

/** Origin servers, clients and helpers shared by the tests. */
public final class TestSupport {

    public static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    private TestSupport() {}

    /** Starts an HTTP origin on an ephemeral loopback port. */
    public static HttpServer origin(HttpHandler handler) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
            server.createContext("/", handler);
            server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Starts an HTTPS origin presenting the certificate in {@code context}. */
    public static HttpsServer httpsOrigin(SSLContext context, HttpHandler handler) {
        try {
            HttpsServer server = HttpsServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(context));
            server.createContext("/", handler);
            server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * A handler that answers with the request's method, URI, headers (lower-cased names) and body,
     * one item per line: {@code method: GET}, {@code uri: /x}, {@code h:via: 1.1 alias}, then a blank
     * line and the body.
     */
    public static HttpHandler echo() {
        return exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            StringBuilder sb = new StringBuilder();
            sb.append("method: ").append(exchange.getRequestMethod()).append('\n');
            sb.append("uri: ").append(exchange.getRequestURI()).append('\n');
            Map<String, List<String>> sorted = new TreeMap<>();
            exchange.getRequestHeaders().forEach((k, v) -> sorted.put(k.toLowerCase(), v));
            sorted.forEach((k, v) -> v.forEach(value -> sb.append("h:").append(k).append(": ").append(value).append('\n')));
            sb.append('\n').append(new String(body, StandardCharsets.UTF_8));
            byte[] out = sb.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        };
    }

    /** A handler that answers with a fixed status and body. */
    public static HttpHandler fixed(int status, String body) {
        return exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
            if (out.length > 0) exchange.getResponseBody().write(out);
            exchange.close();
        };
    }

    public static String url(HttpServer server, String path) {
        String scheme = server instanceof HttpsServer ? "https" : "http";
        return scheme + "://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    public static String localhostUrl(HttpServer server, String path) {
        String scheme = server instanceof HttpsServer ? "https" : "http";
        return scheme + "://localhost:" + server.getAddress().getPort() + path;
    }

    public static HttpClient client(HttpProxyServer proxy) {
        return client(proxy, null);
    }

    public static HttpClient client(HttpProxyServer proxy, SSLContext sslContext) {
        HttpClient.Builder b = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .proxy(ProxySelector.of(proxy.getListenAddress()));
        if (sslContext != null) b.sslContext(sslContext);
        return b.build();
    }

    public static HttpResponse<String> get(HttpClient client, String url) {
        return send(client, HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20)).build());
    }

    public static HttpResponse<String> send(HttpClient client, HttpRequest request) {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** Lines of an {@link #echo()} response that start with {@code h:name:}. */
    public static List<String> echoedHeader(String echoBody, String name) {
        String prefix = "h:" + name.toLowerCase() + ": ";
        return echoBody.lines().takeWhile(l -> !l.isEmpty())
                .filter(l -> l.startsWith(prefix)).map(l -> l.substring(prefix.length())).toList();
    }

    public static String echoedBody(String echoBody) {
        int i = echoBody.indexOf("\n\n");
        return i < 0 ? "" : echoBody.substring(i + 2);
    }

    public static String echoedUri(String echoBody) {
        return echoBody.lines().filter(l -> l.startsWith("uri: ")).findFirst().orElseThrow().substring(5);
    }

    /** Copies {@code headers} for assertions. */
    public static Map<String, List<String>> copy(Headers headers) {
        return new TreeMap<>(headers);
    }

    /** Sends raw bytes to {@code address} and returns everything read until the peer closes. */
    public static String rawExchange(InetSocketAddress address, String request) throws IOException {
        try (Socket s = new Socket(address.getAddress(), address.getPort())) {
            s.setSoTimeout(20_000);
            s.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    /** Reads from {@code in} until {@code marker} has been seen (inclusive). */
    public static String readUntil(InputStream in, String marker) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        while (true) {
            int b = in.read();
            if (b < 0) break;
            buf.write(b);
            if (buf.toString(StandardCharsets.ISO_8859_1).endsWith(marker)) break;
        }
        return buf.toString(StandardCharsets.ISO_8859_1);
    }

    /** A single-connection raw origin: runs {@code handler} for each accepted socket. */
    public static RawServer rawServer(RawHandler handler) {
        return new RawServer(handler);
    }

    @FunctionalInterface
    public interface RawHandler {
        void handle(Socket socket) throws Exception;
    }

    /** A tiny socket server for wire-level origin behaviour. */
    public static final class RawServer implements AutoCloseable {
        private final ServerSocket serverSocket;

        RawServer(RawHandler handler) {
            try {
                serverSocket = new ServerSocket(0, 50, LOOPBACK);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            Thread.ofVirtual().start(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        Socket s = serverSocket.accept();
                        Thread.ofVirtual().start(() -> {
                            try (s) {
                                handler.handle(s);
                            } catch (Exception ignored) {
                                // test origin
                            }
                        });
                    } catch (IOException e) {
                        return;
                    }
                }
            });
        }

        public int port() {
            return serverSocket.getLocalPort();
        }

        public InetSocketAddress address() {
            return new InetSocketAddress(LOOPBACK, port());
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }

    /**
     * Waits until {@code condition} holds, checking every 10 ms for up to 10 seconds; fails with
     * {@code what} otherwise. For state the proxy updates on its own threads.
     */
    public static void eventually(String what, java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline > 0) throw new AssertionError("timed out waiting for " + what);
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted waiting for " + what);
            }
        }
    }

    public static void write(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
    }
}
