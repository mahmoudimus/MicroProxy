package org.microproxy.impl;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.DataFormatException;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.http.WebSocketMessage;
import org.microproxy.simd.Simd;

/**
 * Relays an upgraded WebSocket connection frame by frame, for filters that watch frames, rewrite
 * them, or rewrite whole messages. {@link Tunnel} runs {@link #pump} once per direction, each on
 * its own thread.
 *
 * <ul>
 *   <li>Frames go to the frame hook one at a time. A frame that no hook changed is forwarded as
 *       it arrived; a changed one is encoded again (masked towards the server).
 *   <li>With a message hook, the data frames of a message (a text or binary frame and its
 *       continuations) are joined, after the frame hook has seen each, and the message hook sees
 *       the whole message. Control frames in between are forwarded at once. A message the hook
 *       returns unchanged keeps its fragmentation; a changed one goes out as a single frame. Hooks
 *       may return several messages, in either direction.
 *   <li>With permessage-deflate negotiated ({@link PerMessageDeflate}), hooks that rewrite see
 *       inflated payloads; the proxy deflates again with its own context on each hop.
 *   <li>A message longer than the limit (inflated, or while being joined) fails the connection
 *       with close code 1009 towards both peers; invalid compressed data fails it with 1002.
 * </ul>
 *
 * <p>Joining messages, failing one that is too big with 1009, and keeping the original
 * fragmentation of a message no hook changed follow mitmproxy's {@code
 * mitmproxy/proxy/layers/websocket.py} (MIT licence; see NOTICE).
 */
final class WebSocketRelay {

    private static final System.Logger LOG = System.getLogger(WebSocketRelay.class.getName());
    private static final SecureRandom MASKS = new SecureRandom();
    private static final int RSV1 = 0x4;
    /** Close codes (RFC 6455 section 7.4.1). */
    static final int CLOSE_PROTOCOL_ERROR = 1002;
    static final int CLOSE_MESSAGE_TOO_BIG = 1009;
    /** A message buffer keeps at most this much capacity between messages. */
    private static final int KEEP = 64 * 1024;

    /** Sees each frame and returns the frame to forward, or null to drop it. */
    @FunctionalInterface
    interface FrameHandler {
        WebSocketFrame frame(WebSocketFrame frame, boolean fromClient);
    }

    /** Sees each whole message and returns the messages to send in its place. */
    @FunctionalInterface
    interface MessageHandler {
        List<WebSocketMessage> messages(WebSocketMessage message, boolean fromClient);
    }

    private final FrameHandler frames;
    private final MessageHandler messages;
    private final int maxFrameBuffer;
    private final int maxMessageSize;
    private final PerMessageDeflate.Params clientHop;
    private final PerMessageDeflate.Params serverHop;

    private Output toServer;
    private Output toClient;
    private Inbound fromClient;
    private Inbound fromServer;

    /**
     * @param frames the frame hook, or null
     * @param messages the message hook, or null to relay frames without joining them
     * @param maxFrameBuffer frames with larger payloads are streamed and reported as truncated,
     *     unless they are compressed or belong to a message being joined
     * @param maxMessageSize the most bytes a message may have, joined or inflated
     * @param clientHop the permessage-deflate parameters agreed with the client, or null to relay
     *     its payloads as they are
     * @param serverHop the parameters agreed with the server, or null
     */
    WebSocketRelay(FrameHandler frames, MessageHandler messages, int maxFrameBuffer, int maxMessageSize,
            PerMessageDeflate.Params clientHop, PerMessageDeflate.Params serverHop) {
        this.frames = frames;
        this.messages = messages;
        this.maxFrameBuffer = maxFrameBuffer;
        this.maxMessageSize = maxMessageSize;
        this.clientHop = clientHop;
        this.serverHop = serverHop;
    }

    /** Whether frames are joined into messages. For tests. */
    boolean joinsMessages() {
        return messages != null;
    }

    /** Whether payloads are inflated on the client's and the server's hop. For tests. */
    boolean[] inflates() {
        return new boolean[] {clientHop != null, serverHop != null};
    }

    /** Binds the relay to the tunnel's two directions, before either is pumped. */
    void attach(Tunnel.Direction up, Tunnel.Direction down) {
        // The proxy is the client on the server's hop, and the server on the client's.
        toServer = new Output(up, true, serverHop == null ? null
                : new PerMessageDeflate.Compressor(serverHop.clientNoContextTakeover(), serverHop.clientMaxWindowBits()));
        toClient = new Output(down, false, clientHop == null ? null
                : new PerMessageDeflate.Compressor(clientHop.serverNoContextTakeover(), clientHop.serverMaxWindowBits()));
        fromClient = new Inbound(clientHop == null ? null
                : new PerMessageDeflate.Decompressor(clientHop.clientNoContextTakeover()));
        fromServer = new Inbound(serverHop == null ? null
                : new PerMessageDeflate.Decompressor(serverHop.serverNoContextTakeover()));
    }

    /** Frees the compressors once neither direction is being pumped. */
    void end() {
        if (toServer != null) toServer.end();
        if (toClient != null) toClient.end();
    }

    /** Parses, hands over and forwards frames from one peer until end-of-stream at a frame boundary. */
    void pump(Tunnel.Direction d) throws IOException {
        Inbound in = d.fromClient ? fromClient : fromServer;
        Output out = d.fromClient ? toServer : toClient;
        try {
            pump(d, in, out);
        } finally {
            if (in.inflate != null) in.inflate.end();
        }
    }

    private void pump(Tunnel.Direction d, Inbound in, Output out) throws IOException {
        byte[] head = new byte[14];
        while (true) {
            if (!d.readFully(head, 0, 2, true)) {
                return;
            }
            int length7 = head[1] & 0x7f;
            int pos = 2;
            long length;
            if (length7 == 126) {
                d.readFully(head, pos, 2, false);
                length = ((head[2] & 0xffL) << 8) | (head[3] & 0xffL);
                pos += 2;
            } else if (length7 == 127) {
                d.readFully(head, pos, 8, false);
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | (head[pos + i] & 0xffL);
                }
                pos += 8;
                if (length < 0) {
                    // Not valid WebSocket framing: stop interpreting, keep relaying bytes.
                    LOG.log(Level.DEBUG, d.logPrefix + "invalid WebSocket frame length; relaying raw bytes");
                    d.write(head, 0, pos);
                    d.copyAll();
                    return;
                }
            } else {
                length = length7;
            }
            if ((head[1] & 0x80) != 0) {
                d.readFully(head, pos, 4, false);
                pos += 4;
            }
            byte[] header = Arrays.copyOf(head, pos);
            boolean fin = (header[0] & 0x80) != 0;
            int rsv = (header[0] >> 4) & 0x7;
            int opcode = header[0] & 0x0f;
            boolean data = isData(opcode);

            if (data && opcode != WebSocketFrame.OPCODE_CONTINUATION) {
                if (in.active && (messages != null || in.compressed)) {
                    throw fail(d, CLOSE_PROTOCOL_ERROR, "new message before the last one ended");
                }
                in.start(opcode, (rsv & RSV1) != 0 && in.inflate != null);
            } else if (data && !in.active && messages != null) {
                throw fail(d, CLOSE_PROTOCOL_ERROR, "continuation frame outside a message");
            }
            boolean compressed = data && in.active && in.compressed;
            boolean join = data && in.active && messages != null;

            boolean buffered;
            byte[] payload = null;
            if (compressed || join) {
                // Compressed frames are inflated and joined frames kept, whatever their size.
                if (length > maxMessageSize || join && !compressed && in.message.size() + length > maxMessageSize) {
                    throw fail(d, CLOSE_MESSAGE_TOO_BIG, "message too big");
                }
                buffered = true;
            } else {
                buffered = length <= maxFrameBuffer;
            }
            if (buffered) {
                payload = new byte[(int) length];
                d.readFully(payload, 0, payload.length, false);
            }
            WebSocketFrame wire = new WebSocketFrame(header, payload, length);
            WebSocketFrame seen = wire;
            if (compressed) {
                PerMessageDeflate.Buffer plain = new PerMessageDeflate.Buffer((int) Math.min(length * 4, KEEP));
                try {
                    in.inflate.inflate(wire.payload(), fin, plain, maxMessageSize - in.inflated);
                } catch (PerMessageDeflate.TooBigException e) {
                    throw fail(d, CLOSE_MESSAGE_TOO_BIG, "message too big");
                } catch (DataFormatException e) {
                    throw fail(d, CLOSE_PROTOCOL_ERROR, "invalid compressed data");
                }
                in.inflated += plain.size();
                seen = new WebSocketFrame(header(fin, rsv & ~RSV1, opcode, plain.size(), false), plain.toArray(),
                        plain.size());
            }

            WebSocketFrame result = frames == null ? seen : handle(seen, d);
            if (join) {
                collect(d, in, out, seen, result);
                if (fin) finishMessage(d, in);
            } else {
                forward(d, in, out, header, wire, result, buffered, length);
                if (data && fin) in.end();
            }
        }
    }

    /** Opcodes 0-2: frames that carry a message's data. */
    private static boolean isData(int opcode) {
        return opcode <= WebSocketFrame.OPCODE_BINARY;
    }

    /** The handler's verdict; a failing handler, or one returning a truncated frame of its own, forwards the frame. */
    private WebSocketFrame handle(WebSocketFrame frame, Tunnel.Direction d) {
        try {
            WebSocketFrame out = frames.frame(frame, d.fromClient);
            if (out != null && out != frame && out.isTruncated()) {
                LOG.log(Level.WARNING, d.logPrefix
                        + "WebSocket frame filter returned a truncated frame; forwarding the original");
                return frame;
            }
            return out;
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, d.logPrefix + "WebSocket frame filter threw", e);
            return frame;
        }
    }

    /** Sends one frame on, as it came or as the frame hook made it. */
    private void forward(Tunnel.Direction d, Inbound in, Output out, byte[] header, WebSocketFrame wire,
            WebSocketFrame result, boolean buffered, long length) throws IOException {
        if (result == null) {
            if (!buffered) d.skip(length);
            return;
        }
        if (result == wire) {
            // Untouched and never inflated: the bytes as they came.
            out.raw(d, header, buffered ? wire : null, length);
            return;
        }
        if (!buffered) d.skip(length);
        out.frame(result, in.compressed);
    }

    /** Adds the frame hook's verdict on a data frame to the message being joined. */
    private void collect(Tunnel.Direction d, Inbound in, Output out, WebSocketFrame seen, WebSocketFrame result)
            throws IOException {
        if (result == null) {
            in.modified = true;
            return;
        }
        if (result != seen) in.modified = true;
        if (!isData(result.opcode())) {
            // The hook made a control frame of it: that goes on now.
            out.frame(result, false);
            return;
        }
        byte[] piece = result.payload();
        if (in.message.size() + (long) piece.length > maxMessageSize) {
            throw fail(d, CLOSE_MESSAGE_TOO_BIG, "message too big");
        }
        if (in.fragments.isEmpty() && result.opcode() != WebSocketFrame.OPCODE_CONTINUATION) {
            in.type = result.opcode();
        }
        in.message.append(piece, 0, piece.length);
        in.fragments.add(piece.length);
    }

    /** Hands a whole message to the message hook and sends what it returns. */
    private void finishMessage(Tunnel.Direction d, Inbound in) throws IOException {
        WebSocketMessage.Type type = in.type == WebSocketFrame.OPCODE_TEXT
                ? WebSocketMessage.Type.TEXT : WebSocketMessage.Type.BINARY;
        WebSocketMessage message = new WebSocketMessage(type, in.message.toArray(), d.fromClient);
        List<WebSocketMessage> results;
        try {
            results = messages.messages(message, d.fromClient);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, d.logPrefix + "WebSocket message filter threw", e);
            results = List.of(message);
        }
        if (results != null) {
            for (WebSocketMessage m : results) {
                if (m == null) continue;
                boolean sameWay = m.fromClient() == d.fromClient;
                Output o = m.fromClient() ? toServer : toClient;
                // Mirror the sender's choice to compress; a message sent back is compressed if it can be.
                boolean compress = o.compressor != null && (in.compressed || !sameWay);
                if (sameWay && !in.modified && in.fragments.size() > 1 && (m == message || m.equals(message))) {
                    o.fragments(type.opcode(), in.message.array(), in.fragments, compress);
                } else {
                    o.message(m.type().opcode(), m.payload(), compress);
                }
            }
        }
        in.end();
    }

    /**
     * Fails the connection (RFC 6455 section 7.1.7): a close frame with {@code code} to both
     * peers, then the exception that ends the relay.
     */
    private IOException fail(Tunnel.Direction d, int code, String reason) {
        LOG.log(Level.DEBUG, d.logPrefix + "failing the WebSocket connection (" + code + "): " + reason
                + (d.fromClient ? " from the client" : " from the server"));
        for (Output o : new Output[] {toClient, toServer}) {
            try {
                o.close(code, reason);
            } catch (IOException e) {
                // that side is gone already
            }
        }
        return new IOException("WebSocket connection failed: " + reason);
    }

    static byte[] header(boolean fin, int rsv, int opcode, int length, boolean masked) {
        int lengthBytes = length < 126 ? 0 : length <= 0xffff ? 2 : 8;
        byte[] head = new byte[2 + lengthBytes + (masked ? 4 : 0)];
        head[0] = (byte) ((fin ? 0x80 : 0) | rsv << 4 | opcode);
        int mask = masked ? 0x80 : 0;
        if (lengthBytes == 0) {
            head[1] = (byte) (mask | length);
        } else if (lengthBytes == 2) {
            head[1] = (byte) (mask | 126);
            head[2] = (byte) (length >> 8);
            head[3] = (byte) length;
        } else {
            head[1] = (byte) (mask | 127);
            for (int i = 0; i < 8; i++) {
                head[2 + i] = (byte) ((long) length >> (56 - 8 * i));
            }
        }
        return head;
    }

    /** What one peer has sent of the current message. Used only by the thread reading that peer. */
    private static final class Inbound {
        final PerMessageDeflate.Decompressor inflate;
        /** Whether a message has started and not ended. */
        boolean active;
        /** Whether the current message is compressed (RSV1 on its first frame). */
        boolean compressed;
        /** The current message's inflated bytes so far, for the limit. */
        long inflated;
        /** The opcode the joined message gets. */
        int type;
        /** The joined payload and the sizes of the pieces it was joined from. */
        final PerMessageDeflate.Buffer message = new PerMessageDeflate.Buffer(256);
        final List<Integer> fragments = new ArrayList<>();
        /** Whether the frame hook changed or dropped any frame of the message. */
        boolean modified;

        Inbound(PerMessageDeflate.Decompressor inflate) {
            this.inflate = inflate;
        }

        void start(int opcode, boolean compressed) {
            end();
            active = true;
            this.compressed = compressed;
            type = opcode;
        }

        void end() {
            active = false;
            compressed = false;
            inflated = 0;
            modified = false;
            message.clear(KEEP);
            fragments.clear();
        }
    }

    /**
     * Writes frames to one peer. Both directions' threads may write to it (a hook can send a
     * message back), so every frame is written whole under the lock, and the compressor that
     * belongs to this hop is used only under it.
     */
    private static final class Output {
        private final ReentrantLock lock = new ReentrantLock();
        private final Tunnel.Direction d;
        private final boolean masked;
        final PerMessageDeflate.Compressor compressor;
        /** Whether the message being forwarded frame by frame is compressed. */
        private boolean streaming;
        private boolean ended;

        Output(Tunnel.Direction d, boolean masked, PerMessageDeflate.Compressor compressor) {
            this.d = d;
            this.masked = masked;
            this.compressor = compressor;
        }

        /**
         * Forwards a frame as it arrived: its bytes, or its header and then its payload streamed
         * from {@code from} when it was too large to buffer.
         *
         * @param wire the buffered frame, or null to stream {@code length} bytes
         */
        void raw(Tunnel.Direction from, byte[] header, WebSocketFrame wire, long length) throws IOException {
            lock.lock();
            try {
                check();
                int opcode = header[0] & 0x0f;
                if (isData(opcode) && opcode != WebSocketFrame.OPCODE_CONTINUATION) {
                    streaming = false;
                }
                d.write(header, 0, header.length);
                if (wire != null) {
                    byte[] bytes = wire.rawBytes();
                    d.write(bytes, header.length, bytes.length - header.length);
                } else {
                    from.copy(length);
                }
                d.flush();
            } finally {
                lock.unlock();
            }
        }

        /**
         * Sends a frame of a message relayed frame by frame (or a control frame), compressing
         * data frames when the message is compressed on this hop.
         *
         * @param inboundCompressed whether the message arrived compressed (decides for its first frame)
         */
        void frame(WebSocketFrame frame, boolean inboundCompressed) throws IOException {
            byte[] payload = frame.payload();
            int opcode = frame.opcode();
            int rsv = frame.rsv();
            lock.lock();
            try {
                check();
                if (!isData(opcode)) {
                    write(frame.isFinal(), rsv, opcode, payload, 0, payload.length);
                } else {
                    boolean first = opcode != WebSocketFrame.OPCODE_CONTINUATION;
                    if (first) streaming = compressor != null && inboundCompressed;
                    rsv &= ~RSV1;
                    if (streaming) {
                        PerMessageDeflate.Buffer c = compressor.deflate(payload, 0, payload.length, frame.isFinal());
                        write(frame.isFinal(), first ? rsv | RSV1 : rsv, opcode, c.array(), 0, c.size());
                    } else {
                        write(frame.isFinal(), rsv, opcode, payload, 0, payload.length);
                    }
                    if (frame.isFinal()) streaming = false;
                }
                d.flush();
            } finally {
                lock.unlock();
            }
        }

        /** Sends a whole message as one frame. */
        void message(int opcode, byte[] payload, boolean compress) throws IOException {
            lock.lock();
            try {
                check();
                if (compress) {
                    PerMessageDeflate.Buffer c = compressor.deflate(payload, 0, payload.length, true);
                    write(true, RSV1, opcode, c.array(), 0, c.size());
                } else {
                    write(true, 0, opcode, payload, 0, payload.length);
                }
                d.flush();
            } finally {
                lock.unlock();
            }
        }

        /** Sends a whole message split as it arrived. */
        void fragments(int opcode, byte[] payload, List<Integer> sizes, boolean compress) throws IOException {
            lock.lock();
            try {
                check();
                int off = 0;
                for (int i = 0; i < sizes.size(); i++) {
                    int len = sizes.get(i);
                    boolean fin = i == sizes.size() - 1;
                    int op = i == 0 ? opcode : WebSocketFrame.OPCODE_CONTINUATION;
                    if (compress) {
                        PerMessageDeflate.Buffer c = compressor.deflate(payload, off, len, fin);
                        write(fin, i == 0 ? RSV1 : 0, op, c.array(), 0, c.size());
                    } else {
                        write(fin, 0, op, payload, off, len);
                    }
                    off += len;
                }
                d.flush();
            } finally {
                lock.unlock();
            }
        }

        /** Sends a close frame. */
        void close(int code, String reason) throws IOException {
            byte[] text = reason.getBytes(StandardCharsets.UTF_8);
            byte[] body = new byte[2 + text.length];
            body[0] = (byte) (code >> 8);
            body[1] = (byte) code;
            System.arraycopy(text, 0, body, 2, text.length);
            lock.lock();
            try {
                check();
                write(true, 0, WebSocketFrame.OPCODE_CLOSE, body, 0, body.length);
                d.flush();
            } finally {
                lock.unlock();
            }
        }

        void end() {
            lock.lock();
            try {
                ended = true;
                if (compressor != null) compressor.end();
            } finally {
                lock.unlock();
            }
        }

        private void check() throws IOException {
            if (ended) throw new IOException("WebSocket relay ended");
        }

        private void write(boolean fin, int rsv, int opcode, byte[] payload, int off, int len) throws IOException {
            byte[] head = header(fin, rsv, opcode, len, masked);
            if (!masked) {
                d.write(head, 0, head.length);
                d.write(payload, off, len);
                return;
            }
            int key = MASKS.nextInt();
            int k = head.length - 4;
            head[k] = (byte) (key >> 24);
            head[k + 1] = (byte) (key >> 16);
            head[k + 2] = (byte) (key >> 8);
            head[k + 3] = (byte) key;
            byte[] body = Arrays.copyOfRange(payload, off, off + len);
            Simd.xorMask(body, 0, len, key);
            d.write(head, 0, head.length);
            d.write(body, 0, len);
        }
    }
}
