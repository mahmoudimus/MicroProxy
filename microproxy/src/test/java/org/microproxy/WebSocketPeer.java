package org.microproxy;

import static org.microproxy.TestSupport.write;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import org.microproxy.http.WebSocketFrame;

/**
 * One end of a WebSocket that speaks permessage-deflate (RFC 7692) with the JDK's {@link Deflater}
 * and {@link Inflater}, as a browser or server would, for tests that need compression on the wire
 * ({@code java.net.http.WebSocket} never offers it). Also a WebSocket server built on it, and a
 * DEFLATE reader that finds the longest back-reference in a compressed payload.
 */
public final class WebSocketPeer implements AutoCloseable {

    private static final byte[] TAIL = {0, 0, (byte) 0xff, (byte) 0xff};

    /** A message as received: its type, plaintext, whether it came compressed, and its frames. */
    public record Message(int opcode, byte[] payload, boolean compressed, List<WebSocketFrame> frames) {
        public String text() {
            return new String(payload, StandardCharsets.UTF_8);
        }

        public boolean isClose() {
            return opcode == WebSocketFrame.OPCODE_CLOSE;
        }

        /** The status code of a close frame. */
        public int closeCode() {
            return (payload[0] & 0xff) << 8 | (payload[1] & 0xff);
        }
    }

    /** Agreed permessage-deflate parameters, from a {@code Sec-WebSocket-Extensions} answer. */
    public record Agreement(boolean serverNoContextTakeover, boolean clientNoContextTakeover, int serverMaxWindowBits,
            int clientMaxWindowBits) {

        /** The agreement in {@code header}, or null if it names no permessage-deflate. */
        public static Agreement parse(String header) {
            if (header == null || !header.strip().toLowerCase(Locale.ROOT).startsWith("permessage-deflate")) return null;
            boolean serverNo = false;
            boolean clientNo = false;
            int serverBits = 15;
            int clientBits = 15;
            for (String part : header.split(";")) {
                String[] kv = part.strip().split("=");
                switch (kv[0].strip()) {
                    case "server_no_context_takeover" -> serverNo = true;
                    case "client_no_context_takeover" -> clientNo = true;
                    case "server_max_window_bits" -> serverBits = Integer.parseInt(kv[1].strip());
                    case "client_max_window_bits" -> clientBits = kv.length > 1 ? Integer.parseInt(kv[1].strip()) : 15;
                    default -> { }
                }
            }
            return new Agreement(serverNo, clientNo, serverBits, clientBits);
        }
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final boolean client;
    private final Deflater deflater;
    private final Inflater inflater;
    private final boolean resetDeflater;
    private final boolean resetInflater;
    /** The response head (for a client) or the request head (for a server). */
    public final String head;

    private WebSocketPeer(Socket socket, InputStream in, OutputStream out, boolean client, Agreement agreed,
            String head) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.client = client;
        this.head = head;
        if (agreed == null) {
            deflater = null;
            inflater = null;
            resetDeflater = false;
            resetInflater = false;
        } else {
            deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
            inflater = new Inflater(true);
            resetDeflater = client ? agreed.clientNoContextTakeover() : agreed.serverNoContextTakeover();
            resetInflater = client ? agreed.serverNoContextTakeover() : agreed.clientNoContextTakeover();
        }
    }

    /** A client over {@code in}/{@code out} that agreed to {@code agreed} (null: no compression). */
    public static WebSocketPeer client(InputStream in, OutputStream out, Agreement agreed) {
        return new WebSocketPeer(null, in, out, true, agreed, "");
    }

    /**
     * Opens a WebSocket through {@code proxy} (as a forward proxy) to {@code 127.0.0.1:port},
     * offering {@code extensions} (none if null), and takes up whatever the 101 agrees to.
     */
    public static WebSocketPeer connect(HttpProxyServer proxy, int port, String extensions) throws IOException {
        InetSocketAddress at = proxy.getListenAddress();
        Socket s = new Socket(at.getAddress(), at.getPort());
        s.setSoTimeout(10_000);
        write(s.getOutputStream(), "GET http://127.0.0.1:" + port + "/chat HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n"
                + "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                + (extensions == null ? "" : "Sec-WebSocket-Extensions: " + extensions + "\r\n") + "\r\n");
        String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
        if (!head.startsWith("HTTP/1.1 101")) throw new IOException("no upgrade: " + head);
        Agreement agreed = Agreement.parse(WebSocketTestSupport.header(head, "Sec-WebSocket-Extensions"));
        return new WebSocketPeer(s, s.getInputStream(), s.getOutputStream(), true, agreed, head);
    }

    public Socket socket() {
        return socket;
    }

    @Override
    public void close() throws IOException {
        if (socket != null) socket.close();
    }

    // -------------------------------------------------------------------------------------------
    // Compression, as RFC 7692 section 7.2 describes it
    // -------------------------------------------------------------------------------------------

    /** Compresses a whole message: SYNC_FLUSH, minus the trailing empty block. */
    public byte[] compress(byte[] message) {
        deflater.setInput(message);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        do {
            n = deflater.deflate(chunk, 0, chunk.length, Deflater.SYNC_FLUSH);
            buf.write(chunk, 0, n);
        } while (n == chunk.length);
        byte[] bytes = buf.toByteArray();
        if (resetDeflater) deflater.reset();
        return endsWithTail(bytes) ? Arrays.copyOf(bytes, bytes.length - 4) : bytes;
    }

    /** Inflates a whole compressed message with this peer's context. */
    public byte[] decompress(byte[] payload) throws IOException {
        try {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            for (byte[] input : List.of(payload, TAIL)) {
                inflater.setInput(input);
                while (!inflater.needsInput() && !inflater.finished()) {
                    int n = inflater.inflate(chunk);
                    buf.write(chunk, 0, n);
                }
            }
            if (resetInflater || inflater.finished()) inflater.reset();
            return buf.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("bad compressed message", e);
        }
    }

    private static boolean endsWithTail(byte[] b) {
        return b.length >= 4 && Arrays.equals(b, b.length - 4, b.length, TAIL, 0, 4);
    }

    // -------------------------------------------------------------------------------------------
    // Frames and messages
    // -------------------------------------------------------------------------------------------

    public void send(WebSocketFrame frame) throws IOException {
        out.write(frame.toWire(client));
        out.flush();
    }

    /** Sends raw bytes (a frame built by hand). */
    public void sendRaw(byte[] bytes) throws IOException {
        out.write(bytes);
        out.flush();
    }

    /** Sends a text message, compressed if the connection agreed to it, in one frame. */
    public void sendText(String text) throws IOException {
        sendMessage(WebSocketFrame.OPCODE_TEXT, text.getBytes(StandardCharsets.UTF_8), deflater != null, 1);
    }

    /**
     * Sends a message split into {@code frames} frames; when compressed, the compressed bytes are
     * what is split, and RSV1 is set on the first frame only.
     */
    public void sendMessage(int opcode, byte[] payload, boolean compress, int frames) throws IOException {
        for (WebSocketFrame f : messageFrames(opcode, compress ? compress(payload) : payload, compress, frames)) send(f);
    }

    /** The frames of a message whose (possibly compressed) payload is {@code data}, split evenly. */
    public static List<WebSocketFrame> messageFrames(int opcode, byte[] data, boolean compressed, int frames) {
        List<WebSocketFrame> out = new ArrayList<>();
        int size = Math.max(1, (data.length + frames - 1) / frames);
        int off = 0;
        for (int i = 0; i < frames; i++) {
            int end = i == frames - 1 ? data.length : Math.min(data.length, off + size);
            boolean fin = i == frames - 1;
            int rsv = i == 0 && compressed ? 0x4 : 0;
            out.add(WebSocketFrame.of(fin, rsv, i == 0 ? opcode : WebSocketFrame.OPCODE_CONTINUATION,
                    Arrays.copyOfRange(data, off, end)));
            off = end;
        }
        return out;
    }

    /** Sees every frame this peer reads. */
    private java.util.function.Consumer<WebSocketFrame> frameListener = f -> { };

    public WebSocketFrame readFrame() throws IOException {
        WebSocketFrame f = WebSocketTestSupport.readFrame(in);
        frameListener.accept(f);
        return f;
    }

    /** The frames of a message whose end has not arrived yet (a control frame came in between). */
    private final List<WebSocketFrame> pending = new ArrayList<>();

    /**
     * Reads the next message, inflating it if its first frame has RSV1; a control frame is returned
     * as a message of its own, even between a message's frames.
     */
    public Message readMessage() throws IOException {
        while (true) {
            WebSocketFrame f = readFrame();
            if (f.opcode() >= WebSocketFrame.OPCODE_CLOSE) {
                return new Message(f.opcode(), f.payload(), false, List.of(f));
            }
            pending.add(f);
            if (f.isFinal()) break;
        }
        List<WebSocketFrame> frames = List.copyOf(pending);
        pending.clear();
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        for (WebSocketFrame f : frames) data.writeBytes(f.payload());
        boolean compressed = (frames.getFirst().rsv() & 0x4) != 0;
        byte[] payload = compressed ? decompress(data.toByteArray()) : data.toByteArray();
        return new Message(frames.getFirst().opcode(), payload, compressed, frames);
    }

    // -------------------------------------------------------------------------------------------
    // Server
    // -------------------------------------------------------------------------------------------

    /**
     * A WebSocket server that answers the upgrade with {@code Sec-WebSocket-Extensions:
     * extensions} (none if null) and keeps to what it agreed. It records every message it receives
     * (inflated), answers a text message starting with {@code ping} with {@code "echo:" + text} and
     * a binary one with the same bytes (compressed when compression was agreed), and a close frame
     * with a close frame.
     */
    public static final class Server implements AutoCloseable {
        public final List<Message> received = new CopyOnWriteArrayList<>();
        public final List<String> requests = new CopyOnWriteArrayList<>();
        /** Data frames received, whole messages or not. */
        public final java.util.concurrent.atomic.AtomicInteger fragments = new java.util.concurrent.atomic.AtomicInteger();
        /** Whether replies go out compressed when compression was agreed. */
        public volatile boolean compressReplies = true;
        private final TestSupport.RawServer server;

        public Server(String extensions) {
            this(extensions, null);
        }

        /** A server that speaks TLS with {@code tls}'s certificate first, when {@code tls} is non-null. */
        public Server(String extensions, javax.net.ssl.SSLContext tls) {
            server = TestSupport.rawServer(accepted -> {
                Socket socket = accepted;
                if (tls != null) {
                    javax.net.ssl.SSLSocket secure =
                            (javax.net.ssl.SSLSocket) tls.getSocketFactory().createSocket(accepted, null, true);
                    secure.setUseClientMode(false);
                    socket = secure;
                }
                socket.setSoTimeout(10_000);
                String request = TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
                requests.add(request);
                String key = WebSocketTestSupport.header(request, "Sec-WebSocket-Key");
                write(socket.getOutputStream(), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        + "Connection: Upgrade\r\nSec-WebSocket-Accept: " + WebSocketTestSupport.accept(key) + "\r\n"
                        + (extensions == null ? "" : "Sec-WebSocket-Extensions: " + extensions + "\r\n") + "\r\n");
                WebSocketPeer peer = new WebSocketPeer(socket, socket.getInputStream(), socket.getOutputStream(), false,
                        Agreement.parse(extensions), request);
                peer.frameListener = f -> {
                    if (f.opcode() <= WebSocketFrame.OPCODE_BINARY) fragments.incrementAndGet();
                };
                serve(peer);
            });
        }

        private void serve(WebSocketPeer peer) throws IOException {
            while (true) {
                Message m;
                try {
                    m = peer.readMessage();
                } catch (java.io.EOFException e) {
                    return;
                }
                received.add(m);
                boolean compress = peer.deflater != null && compressReplies;
                if (m.isClose()) {
                    peer.send(WebSocketFrame.close(1000, "bye"));
                    return;
                } else if (m.opcode() == WebSocketFrame.OPCODE_TEXT && m.text().toLowerCase(Locale.ROOT).startsWith("ping")) {
                    peer.sendMessage(WebSocketFrame.OPCODE_TEXT, ("echo:" + m.text()).getBytes(StandardCharsets.UTF_8),
                            compress, 1);
                } else if (m.opcode() == WebSocketFrame.OPCODE_BINARY) {
                    peer.sendMessage(WebSocketFrame.OPCODE_BINARY, m.payload(), compress, 1);
                }
            }
        }

        /** The texts of the messages received so far ({@code <close>} for a close frame). */
        public List<String> texts() {
            return received.stream().map(m -> m.isClose() ? "<close>" : m.text()).toList();
        }

        public int port() {
            return server.port();
        }

        public TestSupport.RawServer raw() {
            return server;
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }

    // -------------------------------------------------------------------------------------------
    // A DEFLATE reader (RFC 1951) that reports back-reference distances
    // -------------------------------------------------------------------------------------------

    private static final int[] LENGTH_EXTRA = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
        5, 5, 5, 5, 0};
    private static final int[] DIST_BASE = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
        769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    private static final int[] DIST_EXTRA = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10,
        10, 11, 11, 12, 12, 13, 13};
    private static final int[] CODE_ORDER = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

    /**
     * The longest back-reference in a message's compressed payload (as sent, without the
     * trailing empty block): a receiver needs a window at least this large. 0 when there are
     * no back-references.
     */
    public static int maxDistance(byte[] payload) {
        byte[] data = Arrays.copyOf(payload, payload.length + 4);
        System.arraycopy(TAIL, 0, data, payload.length, 4);
        Bits in = new Bits(data);
        int max = 0;
        while (in.pos < data.length) {
            int last = in.bits(1);
            int type = in.bits(2);
            if (type == 0) {
                in.align();
                int len = in.bits(16);
                in.bits(16);
                in.pos += len;
            } else {
                Huffman lit;
                Huffman dist;
                if (type == 1) {
                    int[] lengths = new int[288];
                    for (int i = 0; i < 288; i++) lengths[i] = i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8;
                    lit = new Huffman(lengths);
                    int[] d = new int[30];
                    Arrays.fill(d, 5);
                    dist = new Huffman(d);
                } else if (type == 2) {
                    int nlen = in.bits(5) + 257;
                    int ndist = in.bits(5) + 1;
                    int ncode = in.bits(4) + 4;
                    int[] codeLengths = new int[19];
                    for (int i = 0; i < ncode; i++) codeLengths[CODE_ORDER[i]] = in.bits(3);
                    Huffman code = new Huffman(codeLengths);
                    int[] lengths = new int[nlen + ndist];
                    int i = 0;
                    while (i < nlen + ndist) {
                        int sym = code.decode(in);
                        if (sym < 16) {
                            lengths[i++] = sym;
                        } else {
                            int repeat;
                            int value = 0;
                            if (sym == 16) {
                                value = lengths[i - 1];
                                repeat = 3 + in.bits(2);
                            } else if (sym == 17) {
                                repeat = 3 + in.bits(3);
                            } else {
                                repeat = 11 + in.bits(7);
                            }
                            for (int r = 0; r < repeat; r++) lengths[i++] = value;
                        }
                    }
                    lit = new Huffman(Arrays.copyOf(lengths, nlen));
                    dist = new Huffman(Arrays.copyOfRange(lengths, nlen, nlen + ndist));
                } else {
                    throw new IllegalArgumentException("invalid block type");
                }
                while (true) {
                    int sym = lit.decode(in);
                    if (sym < 256) continue;
                    if (sym == 256) break;
                    in.bits(LENGTH_EXTRA[sym - 257]);
                    int d = dist.decode(in);
                    max = Math.max(max, DIST_BASE[d] + in.bits(DIST_EXTRA[d]));
                }
            }
            if (last == 1) break;
        }
        return max;
    }

    private static final class Bits {
        final byte[] data;
        int pos;
        int buf;
        int count;

        Bits(byte[] data) {
            this.data = data;
        }

        int bits(int n) {
            while (count < n) {
                if (pos >= data.length) throw new IllegalArgumentException("DEFLATE data ends early");
                buf |= (data[pos++] & 0xff) << count;
                count += 8;
            }
            int v = buf & ((1 << n) - 1);
            buf >>>= n;
            count -= n;
            return v;
        }

        void align() {
            buf = 0;
            count = 0;
        }
    }

    /** A canonical Huffman code, decoded a bit at a time. */
    private static final class Huffman {
        final int[] counts = new int[16];
        final int[] symbols;

        Huffman(int[] lengths) {
            symbols = new int[lengths.length];
            for (int len : lengths) counts[len]++;
            int[] offsets = new int[16];
            for (int len = 1; len < 15; len++) offsets[len + 1] = offsets[len] + counts[len];
            for (int sym = 0; sym < lengths.length; sym++) {
                if (lengths[sym] != 0) symbols[offsets[lengths[sym]]++] = sym;
            }
        }

        int decode(Bits in) {
            int code = 0;
            int first = 0;
            int index = 0;
            for (int len = 1; len <= 15; len++) {
                code |= in.bits(1);
                int count = counts[len];
                if (code - count < first) return symbols[index + (code - first)];
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            throw new IllegalArgumentException("invalid Huffman code");
        }
    }
}
