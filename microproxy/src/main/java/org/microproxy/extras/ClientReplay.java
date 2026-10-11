/*
 * Modelled on mitmproxy's mitmproxy/addons/clientplayback.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt. MicroProxy sends the requests to its own listener instead of
 * injecting them into the proxy core.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicIntegerArray;

/**
 * Sends recorded requests again, as mitmproxy's {@code client_replay}: each goes to the proxy's own
 * listener as an ordinary client request, so every filter, addon, script, cache and recorder of the
 * proxy applies to it, and the proxy reaches the server (over TLS for {@code https://} URLs).
 *
 * <pre>{@code
 * HttpProxyServer proxy = bootstrap.start();
 * ClientReplay.Result result = ClientReplay.builder(proxy.getListenAddress()).concurrency(4).build()
 *         .replay(RecordedExchange.load(Path.of("flows.har")));
 * }</pre>
 *
 * <p>Requests are sent in absolute form ({@code GET https://host/path HTTP/1.1}) with their
 * recorded headers and body, except hop-by-hop and framing headers: {@code Host} follows the URL,
 * {@code Content-Length} the body, and each request has a connection of its own ({@code
 * Connection: close}). At most {@link Builder#concurrency} requests are in flight at once, and
 * they start in recorded order. The responses are read and discarded; {@link Result} has their
 * statuses. A proxy that requires authentication refuses them with {@code 407}.
 */
public final class ClientReplay {

    private static final System.Logger LOG = System.getLogger(ClientReplay.class.getName());
    private static final Set<String> NOT_SENT = Set.of("host", "content-length", "transfer-encoding", "connection",
            "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer", "upgrade", "expect");

    private final InetSocketAddress proxy;
    private final int concurrency;
    private final Duration timeout;

    private ClientReplay(Builder b) {
        this.proxy = b.proxy;
        this.concurrency = b.concurrency;
        this.timeout = b.timeout;
    }

    /**
     * Starts a builder for replaying through the proxy listening at {@code proxy}.
     *
     * @param proxy the proxy's listen address
     * @return a new builder
     */
    public static Builder builder(InetSocketAddress proxy) {
        return new Builder(proxy);
    }

    /**
     * What a replay did.
     *
     * @param statuses the status each request got, in recorded order; -1 where it failed
     */
    public record Result(List<Integer> statuses) {

        /** Copies the statuses. */
        public Result {
            statuses = List.copyOf(statuses);
        }

        /** {@return how many requests were sent} */
        public int sent() {
            return statuses.size();
        }

        /** {@return how many requests got no response (connection or protocol failures)} */
        public int failed() {
            return (int) statuses.stream().filter(s -> s < 0).count();
        }
    }

    /**
     * Sends {@code exchanges}' requests through the proxy and waits for every response.
     *
     * @param exchanges the recorded exchanges
     * @return the statuses the requests got
     * @throws InterruptedException if interrupted while waiting
     */
    public Result replay(List<RecordedExchange> exchanges) throws InterruptedException {
        AtomicIntegerArray statuses = new AtomicIntegerArray(exchanges.size());
        Semaphore slots = new Semaphore(concurrency);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < exchanges.size(); i++) {
                slots.acquire();
                int index = i;
                RecordedExchange e = exchanges.get(i);
                statuses.set(index, -1);
                executor.execute(() -> {
                    try {
                        statuses.set(index, send(e));
                    } catch (IOException | RuntimeException ex) {
                        LOG.log(Level.WARNING, "client replay of " + e.method() + " " + e.url() + " failed: " + ex);
                    } finally {
                        slots.release();
                    }
                });
            }
        }
        List<Integer> out = new ArrayList<>(exchanges.size());
        for (int i = 0; i < exchanges.size(); i++) out.add(statuses.get(i));
        return new Result(out);
    }

    /** Sends one request and returns its response status. */
    private int send(RecordedExchange e) throws IOException {
        String url = e.url();
        int start = url.indexOf("://");
        if (start < 0) throw new IOException("not an absolute URL: " + url);
        int end = start + 3;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) end++;
        String authority = url.substring(start + 3, end);
        int at = authority.lastIndexOf('@');
        if (at >= 0) authority = authority.substring(at + 1);
        int hash = url.indexOf('#');
        String target = hash >= 0 ? url.substring(0, hash) : url;
        if (end == url.length()) target = target + "/";

        StringBuilder head = new StringBuilder(256);
        head.append(e.method()).append(' ').append(target).append(" HTTP/1.1\r\n");
        head.append("Host: ").append(authority).append("\r\n");
        for (Map.Entry<String, String> h : e.requestHeaders()) {
            String name = h.getKey();
            if (NOT_SENT.contains(name.toLowerCase(Locale.ROOT)) || !valid(name) || !valid(h.getValue())) continue;
            head.append(name).append(": ").append(h.getValue()).append("\r\n");
        }
        byte[] body = e.requestBody();
        String method = e.method().toUpperCase(Locale.ROOT);
        if (body.length > 0 || method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) {
            head.append("Content-Length: ").append(body.length).append("\r\n");
        }
        head.append("Connection: close\r\n\r\n");

        try (Socket socket = new Socket()) {
            int millis = (int) Math.min(Integer.MAX_VALUE, timeout.toMillis());
            socket.connect(proxy, millis);
            socket.setSoTimeout(millis);
            OutputStream out = socket.getOutputStream();
            out.write(head.toString().getBytes(ISO_8859_1));
            out.write(body);
            out.flush();
            InputStream in = socket.getInputStream();
            int status;
            do {
                status = status(line(in));
                // Skip the rest of an interim (1xx) response's head.
                if (status >= 100 && status < 200) {
                    while (!line(in).isEmpty()) {
                        // its headers
                    }
                }
            } while (status >= 100 && status < 200);
            in.transferTo(OutputStream.nullOutputStream());
            return status;
        }
    }

    private static boolean valid(String s) {
        return s.indexOf('\r') < 0 && s.indexOf('\n') < 0;
    }

    private static int status(String statusLine) throws IOException {
        String[] parts = statusLine.split(" ", 3);
        if (parts.length < 2 || !parts[0].startsWith("HTTP/")) throw new IOException("bad response: " + statusLine);
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IOException("bad response: " + statusLine, e);
        }
    }

    private static String line(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream(64);
        int c;
        while ((c = in.read()) >= 0 && c != '\n') {
            if (b.size() > 65536) throw new IOException("response line too long");
            b.write(c);
        }
        if (c < 0 && b.size() == 0) throw new IOException("the proxy closed the connection without a response");
        String s = b.toString(ISO_8859_1);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    /** Configures a {@link ClientReplay}. */
    public static final class Builder {
        private final InetSocketAddress proxy;
        private int concurrency = 1;
        private Duration timeout = Duration.ofSeconds(60);

        private Builder(InetSocketAddress proxy) {
            this.proxy = Objects.requireNonNull(proxy, "proxy");
        }

        /**
         * How many requests may be in flight at once (default 1, as mitmproxy's {@code
         * client_replay_concurrency}).
         *
         * @param requests the limit, at least 1
         * @return this builder
         */
        public Builder concurrency(int requests) {
            if (requests < 1) throw new IllegalArgumentException("must be at least 1");
            this.concurrency = requests;
            return this;
        }

        /**
         * How long to wait to connect to the proxy, and for each read (default 60 seconds).
         *
         * @param timeout the timeout
         * @return this builder
         */
        public Builder timeout(Duration timeout) {
            if (timeout.isNegative() || timeout.isZero()) throw new IllegalArgumentException("must be positive");
            this.timeout = timeout;
            return this;
        }

        /**
         * Creates the replayer.
         *
         * @return the configured replayer
         */
        public ClientReplay build() {
            return new ClientReplay(this);
        }
    }
}
