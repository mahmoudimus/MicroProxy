package org.microproxy;

import io.github.mahmoudimus.http2.ErrorCode;
import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.FrameReader;
import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackDecoder;
import io.github.mahmoudimus.http2.HpackEncoder;
import io.github.mahmoudimus.http2.Http2Settings;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * A threaded HTTP/2 client for tunnels through the proxy ({@code CONNECT} and extended {@code
 * CONNECT} streams, RFC 9113 section 8.5 and RFC 8441): a thread of its own reads frames, and each
 * stream has an {@link InputStream} and an {@link OutputStream} over its DATA frames, which honour
 * flow control both ways. The JDK's HTTP client does neither, hence this one. It connects with
 * prior knowledge ({@code h2c}), with TLS and ALPN {@code h2} to a TLS listener, or through an
 * HTTP/1 {@code CONNECT} that the proxy intercepts.
 */
public final class H2StreamClient implements AutoCloseable {

    private static final long WAIT_NANOS = TimeUnit.SECONDS.toNanos(20);

    private final Socket raw;
    private final Socket socket;
    private final String scheme;
    private final String authority;
    private final FrameReader reader;
    private final FrameWriter writer;
    private final HpackEncoder encoder = new HpackEncoder();
    private final HpackDecoder decoder = new HpackDecoder();
    /** The receive window granted for each stream, and credited back as the test reads. */
    private final int receiveWindow;

    private final ReentrantLock writeLock = new ReentrantLock();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    // Guarded by lock.
    private final Map<Integer, Stream> streams = new HashMap<>();
    private Map<Integer, Long> serverSettings;
    private long connectionSendWindow = Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE;
    private long initialSendWindow = Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE;
    private int nextStreamId = 1;
    /** DATA received on the connection and not credited back: never more than its window. */
    private long connectionWindowUsed;
    private Frame.GoAway goAway;
    private IOException failure;

    private H2StreamClient(Socket raw, Socket socket, String scheme, String authority, int receiveWindow)
            throws IOException {
        this.raw = raw;
        this.socket = socket;
        this.scheme = scheme;
        this.authority = authority;
        this.receiveWindow = receiveWindow;
        this.reader = new FrameReader(new BufferedInputStream(socket.getInputStream()));
        this.writer = new FrameWriter(new BufferedOutputStream(socket.getOutputStream()));
    }

    /** Speaks HTTP/2 with prior knowledge to the proxy's plain listener; streams name {@code authority}. */
    public static H2StreamClient cleartext(InetSocketAddress proxy, String authority) throws IOException {
        Socket s = new Socket(proxy.getAddress(), proxy.getPort());
        return new H2StreamClient(s, s, "http", authority, 65_535).start();
    }

    /** Speaks HTTP/2 over TLS (ALPN {@code h2}) to the proxy's own TLS listener. */
    public static H2StreamClient tls(InetSocketAddress proxy, SSLContext trust, String authority) throws IOException {
        Socket s = new Socket(proxy.getAddress(), proxy.getPort());
        SSLSocket tls = handshake(trust, s, "localhost", proxy.getPort());
        return new H2StreamClient(s, tls, "https", authority, 65_535).start();
    }

    /** Tunnels to {@code target} with an HTTP/1 {@code CONNECT}, then speaks HTTP/2 over the intercepted TLS. */
    public static H2StreamClient intercepted(InetSocketAddress proxy, String target, SSLContext trust) throws IOException {
        return intercepted(proxy, target, trust, 65_535);
    }

    /** As {@link #intercepted(InetSocketAddress, String, SSLContext)}, granting each stream {@code receiveWindow}. */
    public static H2StreamClient intercepted(InetSocketAddress proxy, String target, SSLContext trust, int receiveWindow)
            throws IOException {
        Socket s = new Socket(proxy.getAddress(), proxy.getPort());
        s.setSoTimeout(20_000);
        TestSupport.write(s.getOutputStream(), "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        if (!head.startsWith("HTTP/1.1 200")) {
            s.close();
            throw new IOException("CONNECT refused: " + head);
        }
        String host = target.substring(0, target.lastIndexOf(':'));
        int port = Integer.parseInt(target.substring(target.lastIndexOf(':') + 1));
        SSLSocket tls = handshake(trust, s, host, port);
        return new H2StreamClient(s, tls, "https", target, receiveWindow).start();
    }

    /** Runs a TLS handshake as the client over {@code plain}, requiring ALPN {@code h2}. */
    static SSLSocket handshake(SSLContext trust, Socket plain, String host, int port) throws IOException {
        SSLSocket tls = (SSLSocket) trust.getSocketFactory().createSocket(plain, host, port, true);
        tls.setUseClientMode(true);
        SSLParameters params = tls.getSSLParameters();
        params.setApplicationProtocols(new String[] {"h2"});
        tls.setSSLParameters(params);
        tls.startHandshake();
        if (!"h2".equals(tls.getApplicationProtocol())) {
            tls.close();
            throw new IOException("ALPN did not select h2 but '" + tls.getApplicationProtocol() + "'");
        }
        return tls;
    }

    private H2StreamClient start() throws IOException {
        socket.setSoTimeout(0);
        writeLock.lock();
        try {
            writer.writeClientPreface();
            Map<Integer, Long> settings = new LinkedHashMap<>();
            if (receiveWindow != Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE) {
                settings.put(Http2Settings.INITIAL_WINDOW_SIZE, (long) receiveWindow);
            }
            writer.writeSettings(settings);
            writer.flush();
        } finally {
            writeLock.unlock();
        }
        Thread.ofVirtual().name("h2-stream-client").start(this::readLoop);
        lock.lock();
        try {
            long remaining = WAIT_NANOS;
            while (serverSettings == null && failure == null) {
                if (remaining <= 0) throw new SocketTimeoutException("no SETTINGS from the proxy");
                remaining = changed.awaitNanos(remaining);
            }
            if (serverSettings == null) throw failure;
        } catch (InterruptedException e) {
            throw new InterruptedIOException();
        } finally {
            lock.unlock();
        }
        return this;
    }

    /** The proxy's value for a setting, or null if its SETTINGS did not carry it. */
    public Long setting(int id) {
        lock.lock();
        try {
            return serverSettings.get(id);
        } finally {
            lock.unlock();
        }
    }

    /** The GOAWAY the proxy sent, or null. */
    public Frame.GoAway goAway() {
        lock.lock();
        try {
            return goAway;
        } finally {
            lock.unlock();
        }
    }

    // -------------------------------------------------------------------------------------------
    // Requests
    // -------------------------------------------------------------------------------------------

    /** The fields of an extended CONNECT (RFC 8441) for a WebSocket at {@code path}, then {@code extra} (name, value, ...). */
    public List<HeaderField> webSocket(String path, String... extra) {
        List<HeaderField> fields = new ArrayList<>();
        fields.add(new HeaderField(":method", "CONNECT"));
        fields.add(new HeaderField(":protocol", "websocket"));
        fields.add(new HeaderField(":scheme", scheme));
        fields.add(new HeaderField(":authority", authority));
        fields.add(new HeaderField(":path", path));
        fields.add(new HeaderField("sec-websocket-version", "13"));
        for (int i = 0; i < extra.length; i += 2) fields.add(new HeaderField(extra[i], extra[i + 1]));
        return fields;
    }

    /** The fields of a plain CONNECT (RFC 9113 section 8.5) to {@code target}, then {@code extra}. */
    public static List<HeaderField> connect(String target, String... extra) {
        List<HeaderField> fields = new ArrayList<>();
        fields.add(new HeaderField(":method", "CONNECT"));
        fields.add(new HeaderField(":authority", target));
        for (int i = 0; i < extra.length; i += 2) fields.add(new HeaderField(extra[i], extra[i + 1]));
        return fields;
    }

    /** The fields of a request for {@code path}, then {@code extra}. */
    public List<HeaderField> request(String method, String path, String... extra) {
        List<HeaderField> fields = new ArrayList<>();
        fields.add(new HeaderField(":method", method));
        fields.add(new HeaderField(":scheme", scheme));
        fields.add(new HeaderField(":authority", authority));
        fields.add(new HeaderField(":path", path));
        for (int i = 0; i < extra.length; i += 2) fields.add(new HeaderField(extra[i], extra[i + 1]));
        return fields;
    }

    /** Opens a stream with a HEADERS frame of {@code fields}. */
    public Stream open(List<HeaderField> fields, boolean endStream) throws IOException {
        Stream s;
        writeLock.lock();
        try {
            lock.lock();
            try {
                s = new Stream(nextStreamId, initialSendWindow);
                nextStreamId += 2;
                streams.put(s.id, s);
                if (endStream) s.localEnded = true;
            } finally {
                lock.unlock();
            }
            writer.writeHeaders(s.id, encoder.encode(fields), endStream);
            writer.flush();
        } finally {
            writeLock.unlock();
        }
        return s;
    }

    // -------------------------------------------------------------------------------------------
    // Streams
    // -------------------------------------------------------------------------------------------

    /** One stream: its response head, its DATA as streams, its end or reset. */
    public final class Stream {
        public final int id;
        // Guarded by lock.
        private final List<List<HeaderField>> headerBlocks = new ArrayList<>();
        private final ArrayDeque<byte[]> inbound = new ArrayDeque<>();
        private int headOffset;
        private boolean remoteEnded;
        /** END_STREAM arrived before any reset: a reset after it (NO_ERROR) does not undo the end. */
        private boolean endedFirst;
        private boolean localEnded;
        private ErrorCode reset;
        private long sendWindow;
        private int unacked;
        private long received;
        /** DATA received and not credited back: never more than the window this client granted. */
        private long windowUsed;

        private final InputStream in = new InputStream() {
            @Override
            public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return n < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                return Stream.this.read(b, off, len);
            }
        };

        private final OutputStream out = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                send(b, off, len, false);
            }
        };

        Stream(int id, long sendWindow) {
            this.id = id;
            this.sendWindow = sendWindow;
        }

        /** The DATA the proxy sends on the stream, crediting the windows back as it is read. */
        public InputStream in() {
            return in;
        }

        /** DATA to the proxy, waiting for flow-control window. */
        public OutputStream out() {
            return out;
        }

        /**
         * The stream as a connected socket, for TLS over a {@code CONNECT} tunnel: its streams
         * are {@link #in()} and {@link #out()}, and closing it ends the stream's output.
         */
        public Socket asSocket() {
            return new Socket() {
                private volatile boolean closed;

                @Override
                public InputStream getInputStream() {
                    return in;
                }

                @Override
                public OutputStream getOutputStream() {
                    return out;
                }

                @Override
                public boolean isConnected() {
                    return true;
                }

                @Override
                public boolean isBound() {
                    return true;
                }

                @Override
                public boolean isClosed() {
                    return closed;
                }

                @Override
                public void setSoTimeout(int timeout) {}

                @Override
                public int getSoTimeout() {
                    return 0;
                }

                @Override
                public int getSoLinger() {
                    return -1;
                }

                @Override
                public void setSoLinger(boolean on, int linger) {}

                @Override
                public void setTcpNoDelay(boolean on) {}

                @Override
                public java.net.InetAddress getInetAddress() {
                    return null;
                }

                @Override
                public void shutdownOutput() throws IOException {
                    end();
                }

                @Override
                public void close() throws IOException {
                    if (closed) return;
                    closed = true;
                    lock.lock();
                    boolean open;
                    try {
                        open = !localEnded && reset == null;
                    } finally {
                        lock.unlock();
                    }
                    if (open) end();
                }
            };
        }

        /** The response head: the first HEADERS with a final status, skipping interim ones. */
        public List<HeaderField> awaitHeaders() throws IOException {
            lock.lock();
            try {
                long remaining = WAIT_NANOS;
                while (true) {
                    for (List<HeaderField> block : headerBlocks) {
                        if (!block.isEmpty() && !block.getFirst().value().startsWith("1")) return block;
                    }
                    if (reset != null) throw new IOException("stream " + id + " reset: " + reset);
                    if (failure != null) throw new IOException("connection failed", failure);
                    if (remaining <= 0) throw new SocketTimeoutException("no response head on stream " + id);
                    remaining = changed.awaitNanos(remaining);
                }
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            } finally {
                lock.unlock();
            }
        }

        /** The response's {@code :status}. */
        public int status() throws IOException {
            return Integer.parseInt(awaitHeaders().getFirst().value());
        }

        /** The response head's value for {@code name}, or null. */
        public String header(String name) throws IOException {
            for (HeaderField f : awaitHeaders()) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        /** Reads the DATA until END_STREAM. */
        public byte[] readAll() throws IOException {
            return in.readAllBytes();
        }

        /** Reads the DATA until END_STREAM, as UTF-8. */
        public String text() throws IOException {
            return new String(readAll(), StandardCharsets.UTF_8);
        }

        /** Ends the stream's output: an empty DATA frame with END_STREAM. */
        public void end() throws IOException {
            send(new byte[0], 0, 0, true);
        }

        /** Resets the stream. */
        public void reset(ErrorCode code) throws IOException {
            lock.lock();
            try {
                localEnded = true;
                if (reset == null) reset = code;
                changed.signalAll();
            } finally {
                lock.unlock();
            }
            writeLock.lock();
            try {
                writer.writeRstStream(id, code);
                writer.flush();
            } finally {
                writeLock.unlock();
            }
        }

        /**
         * Waits until the proxy ends the stream (END_STREAM) or resets it; returns the reset's code,
         * or null if the stream ended first.
         */
        public ErrorCode awaitEnd() throws IOException {
            lock.lock();
            try {
                long remaining = WAIT_NANOS;
                while (reset == null && !remoteEnded && failure == null) {
                    if (remaining <= 0) throw new SocketTimeoutException("stream " + id + " did not end");
                    remaining = changed.awaitNanos(remaining);
                }
                return endedFirst ? null : reset;
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            } finally {
                lock.unlock();
            }
        }

        /** Waits for RST_STREAM from the proxy and returns its code. */
        public ErrorCode awaitReset() throws IOException {
            lock.lock();
            try {
                long remaining = WAIT_NANOS;
                while (reset == null && failure == null) {
                    if (remaining <= 0) throw new SocketTimeoutException("stream " + id + " was not reset");
                    remaining = changed.awaitNanos(remaining);
                }
                return reset;
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            } finally {
                lock.unlock();
            }
        }

        /** DATA bytes received so far, read or not. */
        public long received() {
            lock.lock();
            try {
                return received;
            } finally {
                lock.unlock();
            }
        }

        /** END_STREAM received; holds lock. */
        private void ended() {
            remoteEnded = true;
            if (reset == null) endedFirst = true;
        }

        private int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            int n;
            int credit = 0;
            lock.lock();
            try {
                long remaining = WAIT_NANOS;
                while (inbound.isEmpty()) {
                    if (remoteEnded) return -1;
                    if (reset != null) throw new IOException("stream " + id + " reset: " + reset);
                    if (failure != null) throw new IOException("connection failed", failure);
                    if (remaining <= 0) throw new SocketTimeoutException("no data on stream " + id);
                    remaining = changed.awaitNanos(remaining);
                }
                byte[] chunk = inbound.peekFirst();
                n = Math.min(len, chunk.length - headOffset);
                System.arraycopy(chunk, headOffset, b, off, n);
                headOffset += n;
                if (headOffset == chunk.length) {
                    inbound.pollFirst();
                    headOffset = 0;
                }
                unacked += n;
                if (unacked >= receiveWindow / 2) {
                    credit = unacked;
                    unacked = 0;
                    windowUsed -= credit;
                    connectionWindowUsed -= credit;
                }
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            } finally {
                lock.unlock();
            }
            if (credit > 0) {
                int c = credit;
                write(() -> {
                    writer.writeWindowUpdate(id, c);
                    writer.writeWindowUpdate(0, c);
                });
            }
            return n;
        }

        private void send(byte[] b, int off, int len, boolean endStream) throws IOException {
            do {
                int n;
                lock.lock();
                try {
                    long remaining = WAIT_NANOS;
                    while (true) {
                        if (reset != null) throw new IOException("stream " + id + " reset: " + reset);
                        if (failure != null) throw new IOException("connection failed", failure);
                        if (localEnded) throw new IOException("stream " + id + " already ended");
                        n = (int) Math.min(len, Math.min(16_384, Math.min(sendWindow, connectionSendWindow)));
                        if (n > 0 || len == 0) break;
                        if (remaining <= 0) throw new SocketTimeoutException("no send window on stream " + id);
                        remaining = changed.awaitNanos(remaining);
                    }
                    sendWindow -= n;
                    connectionSendWindow -= n;
                    if (endStream && n == len) localEnded = true;
                } catch (InterruptedException e) {
                    throw new InterruptedIOException();
                } finally {
                    lock.unlock();
                }
                int at = off;
                int count = n;
                boolean end = endStream && n == len;
                write(() -> writer.writeData(id, b, at, count, end));
                off += n;
                len -= n;
            } while (len > 0);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Reading
    // -------------------------------------------------------------------------------------------

    @FunctionalInterface
    private interface Write {
        void run() throws IOException;
    }

    private void write(Write action) throws IOException {
        writeLock.lock();
        try {
            action.run();
            writer.flush();
        } finally {
            writeLock.unlock();
        }
    }

    private void readLoop() {
        IOException end = null;
        try {
            Frame f;
            while ((f = reader.readFrame()) != null) {
                onFrame(f);
            }
            end = new IOException("the proxy closed the connection");
        } catch (IOException e) {
            end = e;
        } finally {
            lock.lock();
            try {
                failure = end;
                changed.signalAll();
            } finally {
                lock.unlock();
            }
        }
    }

    private void onFrame(Frame f) throws IOException {
        switch (f) {
            case Frame.Settings s -> {
                if (s.ack()) return;
                lock.lock();
                try {
                    Long window = s.values().get(Http2Settings.INITIAL_WINDOW_SIZE);
                    if (window != null) {
                        long delta = window - initialSendWindow;
                        initialSendWindow = window;
                        for (Stream st : streams.values()) st.sendWindow += delta;
                    }
                    if (serverSettings == null) serverSettings = new HashMap<>(s.values());
                    else serverSettings.putAll(s.values());
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
                write(writer::writeSettingsAck);
            }
            case Frame.Ping p -> {
                if (!p.ack()) write(() -> writer.writePing(true, p.opaqueData()));
            }
            case Frame.WindowUpdate w -> {
                lock.lock();
                try {
                    if (w.streamId() == 0) {
                        connectionSendWindow += w.increment();
                    } else {
                        Stream st = streams.get(w.streamId());
                        if (st != null) st.sendWindow += w.increment();
                    }
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
            }
            case Frame.Headers h -> {
                List<HeaderField> fields = decoder.decode(h.streamId(), h.fieldBlock());
                lock.lock();
                try {
                    Stream st = streams.get(h.streamId());
                    if (st != null) {
                        st.headerBlocks.add(fields);
                        if (h.endStream()) st.ended();
                    }
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
            }
            case Frame.Data d -> {
                lock.lock();
                try {
                    Stream st = streams.get(d.streamId());
                    connectionWindowUsed += d.flowControlledLength();
                    if (connectionWindowUsed > Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE) {
                        throw new IOException("the proxy overran the connection's flow-control window");
                    }
                    if (st != null) {
                        st.windowUsed += d.flowControlledLength();
                        if (st.windowUsed > receiveWindow) {
                            throw new IOException("the proxy overran stream " + st.id + "'s flow-control window");
                        }
                        if (d.data().length > 0) st.inbound.addLast(d.data());
                        st.received += d.data().length;
                        if (d.endStream()) st.ended();
                    }
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
            }
            case Frame.RstStream r -> {
                lock.lock();
                try {
                    Stream st = streams.get(r.streamId());
                    if (st != null && st.reset == null) st.reset = r.error();
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
            }
            case Frame.GoAway g -> {
                lock.lock();
                try {
                    goAway = g;
                    changed.signalAll();
                } finally {
                    lock.unlock();
                }
            }
            default -> {
                // ignored
            }
        }
    }

    /** Collects a whole response: head, then DATA until END_STREAM. */
    public static String body(Stream s) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        s.in().transferTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {
        socket.close();
        raw.close();
    }
}
