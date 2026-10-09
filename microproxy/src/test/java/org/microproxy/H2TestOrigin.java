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
import java.io.InterruptedIOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * A minimal HTTP/2 origin server for tests, built on the codec: TLS with ALPN {@code h2} only, one
 * virtual thread per connection reading frames and one per stream running the test's handler. It
 * honours flow control in both directions, so a test can see how much the proxy let it send, and
 * it counts what tests assert on: accepted connections, concurrent streams, resets received.
 */
final class H2TestOrigin implements AutoCloseable {

    /** What the origin does with each stream. */
    @FunctionalInterface
    interface Handler {
        void handle(Stream stream) throws Exception;
    }

    /** Settings and behaviour. */
    static final class Options {
        long maxConcurrentStreams = Http2Settings.UNLIMITED;
        /** Credit the client's DATA back at once (otherwise only as the handler reads it). */
        boolean eagerCredit = true;
        /** Connections start with a PROXY protocol v1 line before TLS. */
        boolean proxyProtocol;
        boolean enableConnectProtocol;
        TestSupport.RawHandler http1Handler;
    }

    private static final Object END = new Object();

    private final ServerSocket serverSocket;
    private final Handler handler;
    private final Options options;
    final AtomicInteger accepts = new AtomicInteger();
    /** The most streams open at once on any one connection. */
    final AtomicInteger maxOpenStreams = new AtomicInteger();
    /** Streams refused because they went past SETTINGS_MAX_CONCURRENT_STREAMS. */
    final AtomicInteger refused = new AtomicInteger();
    /** RST_STREAM codes received from the proxy. */
    final List<ErrorCode> resets = new CopyOnWriteArrayList<>();
    /** The PROXY protocol lines connections started with ({@link Options#proxyProtocol}). */
    final List<String> proxyHeaders = new CopyOnWriteArrayList<>();
    private final SSLContext context;
    final List<Conn> connections = new CopyOnWriteArrayList<>();

    H2TestOrigin(SSLContext context, Handler handler) throws IOException {
        this(context, new Options(), handler);
    }

    H2TestOrigin(SSLContext context, Options options, Handler handler) throws IOException {
        this.handler = handler;
        this.options = options;
        this.context = context;
        if (options.proxyProtocol) {
            serverSocket = new ServerSocket(0, 50, TestSupport.LOOPBACK);
        } else {
            SSLServerSocket s = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 50, TestSupport.LOOPBACK);
            s.setSSLParameters(alpnH2(s.getSSLParameters()));
            serverSocket = s;
        }
        Thread.ofVirtual().name("h2-origin-accept").start(this::acceptLoop);
    }

    private static SSLParameters alpnH2(SSLParameters params) {
        params.setApplicationProtocols(new String[] {"h2"});
        return params;
    }

    /** Reads the PROXY line from {@code plain}, then runs the TLS handshake over it as the server. */
    private SSLSocket afterProxyHeader(Socket plain) throws IOException {
        StringBuilder line = new StringBuilder();
        int b;
        while ((b = plain.getInputStream().read()) >= 0 && b != '\n') line.append((char) b);
        proxyHeaders.add(line.toString().strip());
        SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(plain, null, true);
        tls.setUseClientMode(false);
        tls.setSSLParameters(alpnH2(tls.getSSLParameters()));
        return tls;
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    InetSocketAddress address() {
        return new InetSocketAddress(TestSupport.LOOPBACK, port());
    }

    String url(String path) {
        return "https://localhost:" + port() + path;
    }

    private void acceptLoop() {
        while (!serverSocket.isClosed()) {
            Socket s;
            try {
                s = serverSocket.accept();
            } catch (IOException e) {
                return;
            }
            accepts.incrementAndGet();
            Thread.ofVirtual().name("h2-origin-conn").start(() -> {
                try {
                    SSLSocket tls = options.proxyProtocol ? afterProxyHeader(s) : (SSLSocket) s;
                    tls.startHandshake();
                    if (!"h2".equals(tls.getApplicationProtocol()) && options.http1Handler != null) {
                        try {
                            options.http1Handler.handle(tls);
                        } catch (Exception e) {
                            throw new IOException(e);
                        }
                        return;
                    }
                    Conn c = new Conn(tls);
                    connections.add(c);
                    c.serve();
                } catch (IOException e) {
                    // test origin: the connection ends
                } finally {
                    try {
                        s.close();
                    } catch (IOException ignored) {
                        // closed
                    }
                }
            });
        }
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
        for (Conn c : connections) c.socket.close();
    }

    /** One connection from the proxy. */
    final class Conn {
        final SSLSocket socket;
        private final FrameReader reader;
        private final FrameWriter writer;
        private final HpackDecoder decoder = new HpackDecoder();
        private final HpackEncoder encoder = new HpackEncoder();
        final ReentrantLock lock = new ReentrantLock();
        final Condition windowChanged = lock.newCondition();
        private final Map<Integer, Stream> streams = new HashMap<>();
        private long connectionWindow = Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE;
        private long peerInitialWindow = Http2Settings.DEFAULT_INITIAL_WINDOW_SIZE;
        private int open;
        private int lastStreamId;
        private boolean goingAway;

        Conn(SSLSocket socket) throws IOException {
            this.socket = socket;
            socket.startHandshake();
            if (!"h2".equals(socket.getApplicationProtocol())) throw new IOException("no h2");
            reader = new FrameReader(new BufferedInputStream(socket.getInputStream()));
            writer = new FrameWriter(new BufferedOutputStream(socket.getOutputStream()));
        }

        void serve() throws IOException {
            reader.readClientPreface();
            lock.lock();
            try {
                Map<Integer, Long> settings = new LinkedHashMap<>();
                if (options.maxConcurrentStreams != Http2Settings.UNLIMITED) {
                    settings.put(Http2Settings.MAX_CONCURRENT_STREAMS, options.maxConcurrentStreams);
                }
                if (options.enableConnectProtocol) settings.put(Http2Settings.ENABLE_CONNECT_PROTOCOL, 1L);
                writer.writeSettings(settings);
                writer.flush();
            } finally {
                lock.unlock();
            }
            Frame f;
            while ((f = reader.readFrame()) != null) {
                switch (f) {
                    case Frame.Settings s -> {
                        if (!s.ack()) {
                            lock.lock();
                            try {
                                Long w = s.values().get(Http2Settings.INITIAL_WINDOW_SIZE);
                                if (w != null) {
                                    long delta = w - peerInitialWindow;
                                    peerInitialWindow = w;
                                    for (Stream st : streams.values()) st.window += delta;
                                    windowChanged.signalAll();
                                }
                                writer.writeSettingsAck();
                                writer.flush();
                            } finally {
                                lock.unlock();
                            }
                        }
                    }
                    case Frame.Ping p -> {
                        if (!p.ack()) write(() -> writer.writePing(true, p.opaqueData()));
                    }
                    case Frame.WindowUpdate w -> {
                        lock.lock();
                        try {
                            if (w.streamId() == 0) {
                                connectionWindow += w.increment();
                            } else {
                                Stream st = streams.get(w.streamId());
                                if (st != null) st.window += w.increment();
                            }
                            windowChanged.signalAll();
                        } finally {
                            lock.unlock();
                        }
                    }
                    case Frame.Headers h -> onHeaders(h);
                    case Frame.Data d -> onData(d);
                    case Frame.RstStream r -> {
                        resets.add(r.error());
                        Stream st;
                        lock.lock();
                        try {
                            st = streams.remove(r.streamId());
                            if (st != null) {
                                st.reset = true;
                                if (!st.localClosed) open--;
                                st.localClosed = true;
                                windowChanged.signalAll();
                            }
                        } finally {
                            lock.unlock();
                        }
                        if (st != null) st.inbound.add(END);
                    }
                    case Frame.GoAway g -> {
                        return;
                    }
                    default -> {
                        // ignored
                    }
                }
            }
        }

        private void onHeaders(Frame.Headers h) throws IOException {
            List<HeaderField> fields = decoder.decode(h.streamId(), h.fieldBlock());
            Stream st;
            boolean fresh;
            boolean refuse = false;
            lock.lock();
            try {
                st = streams.get(h.streamId());
                fresh = st == null;
                if (fresh) {
                    lastStreamId = h.streamId();
                    if (open >= options.maxConcurrentStreams) {
                        refuse = true;
                    } else {
                        st = new Stream(this, h.streamId(), fields, peerInitialWindow);
                        streams.put(h.streamId(), st);
                        open++;
                        maxOpenStreams.accumulateAndGet(open, Math::max);
                    }
                }
            } finally {
                lock.unlock();
            }
            if (refuse) {
                refused.incrementAndGet();
                write(() -> writer.writeRstStream(h.streamId(), ErrorCode.REFUSED_STREAM));
                return;
            }
            if (fresh) {
                if (h.endStream()) st.inbound.add(END);
                Stream started = st;
                Thread.ofVirtual().name("h2-origin-stream-" + h.streamId()).start(() -> {
                    try {
                        handler.handle(started);
                    } catch (Exception e) {
                        if (!started.localClosed) {
                            try {
                                started.reset(ErrorCode.INTERNAL_ERROR);
                            } catch (IOException ignored) {
                                // connection gone
                            }
                        }
                    }
                });
            } else {
                st.trailers = fields;
                st.inbound.add(END);
            }
        }

        private void onData(Frame.Data d) throws IOException {
            Stream st;
            lock.lock();
            try {
                st = streams.get(d.streamId());
            } finally {
                lock.unlock();
            }
            int n = d.flowControlledLength();
            if (st != null && d.data().length > 0) st.inbound.add(d.data());
            if (st != null && d.endStream()) st.inbound.add(END);
            if (n > 0 && (options.eagerCredit || st == null)) {
                write(() -> {
                    writer.writeWindowUpdate(0, n);
                    if (st != null && !d.endStream()) writer.writeWindowUpdate(d.streamId(), n);
                });
            }
        }

        void write(IoAction action) throws IOException {
            lock.lock();
            try {
                action.run();
                writer.flush();
            } finally {
                lock.unlock();
            }
        }

        /** Sends GOAWAY with {@code lastStreamId}, then closes the connection once its streams are done. */
        void goAway(int lastStreamId, ErrorCode code) throws IOException {
            lock.lock();
            try {
                goingAway = true;
            } finally {
                lock.unlock();
            }
            write(() -> writer.writeGoAway(lastStreamId, code, new byte[0]));
        }
    }

    @FunctionalInterface
    interface IoAction {
        void run() throws IOException;
    }

    /** One stream: the request, and what the handler sends back. */
    final class Stream {
        final Conn conn;
        final int id;
        final List<HeaderField> headers;
        final BlockingQueue<Object> inbound = new LinkedBlockingQueue<>();
        volatile List<HeaderField> trailers = List.of();
        // Guarded by conn.lock.
        long window;
        boolean reset;
        boolean localClosed;
        /** DATA bytes sent so far. */
        final AtomicLong sent = new AtomicLong();
        /** Waiting for flow-control window. */
        volatile boolean blocked;
        private boolean ended;

        Stream(Conn conn, int id, List<HeaderField> headers, long window) {
            this.conn = conn;
            this.id = id;
            this.headers = headers;
            this.window = window;
        }

        String header(String name) {
            for (HeaderField f : headers) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        List<String> headers(String name) {
            List<String> out = new ArrayList<>();
            for (HeaderField f : headers) {
                if (f.name().equals(name)) out.add(f.value());
            }
            return out;
        }

        String trailer(String name) {
            for (HeaderField f : trailers) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        /** The next piece of the request body; null at its end (then {@link #trailers} are known). */
        byte[] read() throws IOException {
            if (ended) return null;
            Object o;
            try {
                o = inbound.poll(20, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                throw new InterruptedIOException();
            }
            if (o == null) throw new IOException("no request data in time");
            if (o == END) {
                ended = true;
                return null;
            }
            byte[] data = (byte[]) o;
            if (!options.eagerCredit) {
                conn.write(() -> {
                    conn.writer.writeWindowUpdate(0, data.length);
                    conn.writer.writeWindowUpdate(id, data.length);
                });
            }
            return data;
        }

        /** A byte-stream view for WebSocket frame tests. */
        java.io.InputStream input() {
            return new java.io.InputStream() {
                private java.io.InputStream chunk = java.io.InputStream.nullInputStream();
                @Override
                public int read() throws IOException {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
                }
                @Override
                public int read(byte[] bytes, int off, int len) throws IOException {
                    if (len == 0) return 0;
                    while (true) {
                        int n = chunk.read(bytes, off, len);
                        if (n >= 0) return n;
                        byte[] next = Stream.this.read();
                        if (next == null) return -1;
                        chunk = new java.io.ByteArrayInputStream(next);
                    }
                }
            };
        }

        byte[] readBody() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] b;
            while ((b = read()) != null) out.write(b);
            return out.toByteArray();
        }

        /** Sends the response head; {@code nameValues} are field names and values in turn. */
        void respond(int status, boolean endStream, String... nameValues) throws IOException {
            List<HeaderField> fields = new ArrayList<>();
            fields.add(new HeaderField(":status", Integer.toString(status)));
            for (int i = 0; i < nameValues.length; i += 2) fields.add(new HeaderField(nameValues[i], nameValues[i + 1]));
            sendFields(fields, endStream);
        }

        void trailers(String... nameValues) throws IOException {
            List<HeaderField> fields = new ArrayList<>();
            for (int i = 0; i < nameValues.length; i += 2) fields.add(new HeaderField(nameValues[i], nameValues[i + 1]));
            sendFields(fields, true);
        }

        private void sendFields(List<HeaderField> fields, boolean endStream) throws IOException {
            conn.lock.lock();
            try {
                if (reset) throw new IOException("stream reset");
                if (endStream) closeLocal();
                conn.writer.writeHeaders(id, conn.encoder.encode(fields), endStream);
                conn.writer.flush();
            } finally {
                conn.lock.unlock();
            }
        }

        /** Sends data, waiting for window, in frames of at most 16 KiB. */
        void data(byte[] data, boolean endStream) throws IOException {
            int off = 0;
            do {
                int n;
                conn.lock.lock();
                try {
                    while (true) {
                        if (reset) throw new IOException("stream reset");
                        n = (int) Math.min(data.length - off, Math.min(16_384, Math.min(window, conn.connectionWindow)));
                        if (n > 0 || data.length == off) break;
                        blocked = true;
                        if (!conn.windowChanged.await(30, TimeUnit.SECONDS)) throw new IOException("no window");
                    }
                    blocked = false;
                    window -= n;
                    conn.connectionWindow -= n;
                    boolean end = endStream && off + n == data.length;
                    if (end) closeLocal();
                    conn.writer.writeData(id, data, off, n, end);
                    conn.writer.flush();
                    sent.addAndGet(n);
                } catch (InterruptedException e) {
                    throw new InterruptedIOException();
                } finally {
                    conn.lock.unlock();
                }
                off += n;
            } while (off < data.length);
        }

        void reset(ErrorCode code) throws IOException {
            conn.lock.lock();
            try {
                closeLocal();
                reset = true;
                conn.writer.writeRstStream(id, code);
                conn.writer.flush();
            } finally {
                conn.lock.unlock();
            }
        }

        /** The stream stops counting as open just before its last frame goes out. Holds conn.lock. */
        private void closeLocal() {
            if (!localClosed) {
                localClosed = true;
                conn.open--;
                conn.streams.remove(id);
            }
        }
    }

    /** Builds a response body of {@code size} pseudo-random bytes. */
    static byte[] bytes(int size, long seed) {
        byte[] b = new byte[size];
        new java.util.Random(seed).nextBytes(b);
        return b;
    }

    static void closeQuietly(AutoCloseable c) {
        try {
            if (c != null) c.close();
        } catch (Exception e) {
            throw new UncheckedIOException(new IOException(e));
        }
    }
}
