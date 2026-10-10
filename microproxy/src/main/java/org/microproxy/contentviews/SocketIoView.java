/*
 * Ported from mitmproxy (https://github.com/mitmproxy/mitmproxy),
 * mitmproxy/contentviews/_view_socketio.py: the Engine.IO and Socket.IO packet types and their
 * names, and recognizing Socket.IO by its path. Copyright (c) 2013, Aldo Cortesi. Licensed under
 * the MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.contentviews;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Engine.IO and Socket.IO packets (protocol versions 4 and 5): a long-polling body's packets
 * (separated by the record separator, 0x1e) or one WebSocket message, one line each, such as
 * {@code SocketIO.EVENT /chat ack=12 ["message",{"text":"hi"}]}. It applies to requests whose
 * path contains {@code /socket.io/} or {@code /engine.io/}.
 */
final class SocketIoView implements ContentView {

    private static final String[] ENGINE_IO = {"OPEN", "CLOSE", "PING", "PONG", "MESSAGE", "UPGRADE", "NOOP"};
    private static final String[] SOCKET_IO = {"CONNECT", "DISCONNECT", "EVENT", "ACK", "CONNECT_ERROR", "BINARY_EVENT",
        "BINARY_ACK"};

    @Override
    public String name() {
        return "socketio";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        String path = metadata.path();
        return data.length > 0 && path != null && (path.contains("/socket.io/") || path.contains("/engine.io/")) ? 1 : 0;
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        String text = ProtoDecoder.utf8(data, 0, data.length);
        if (text == null) throw new DecodeException("not an Engine.IO payload: not UTF-8");
        StringBuilder sb = new StringBuilder();
        for (String packet : text.split("\u001e", -1)) sb.append(packet(packet)).append('\n');
        return sb.toString();
    }

    /** One packet as a line. */
    static String packet(String p) throws DecodeException {
        if (p.isEmpty()) throw new DecodeException("empty Engine.IO packet");
        if (p.charAt(0) == 'b') {
            return "EngineIO.MESSAGE (binary, base64) " + p.substring(1);
        }
        int engine = p.charAt(0) - '0';
        if (engine < 0 || engine >= ENGINE_IO.length) {
            throw new DecodeException("unknown Engine.IO packet type " + p.charAt(0));
        }
        String rest = p.substring(1);
        if (engine != 4) return join("EngineIO." + ENGINE_IO[engine], json(rest));
        if (rest.isEmpty()) throw new DecodeException("Engine.IO message without a Socket.IO packet type");
        int socket = rest.charAt(0) - '0';
        if (socket < 0 || socket >= SOCKET_IO.length) {
            throw new DecodeException("unknown Socket.IO packet type " + rest.charAt(0));
        }
        int pos = 1;
        List<String> parts = new ArrayList<>();
        parts.add("SocketIO." + SOCKET_IO[socket]);
        if (socket == 5 || socket == 6) {
            int dash = rest.indexOf('-', pos);
            if (dash > pos && rest.substring(pos, dash).chars().allMatch(Character::isDigit)) {
                parts.add("attachments=" + rest.substring(pos, dash));
                pos = dash + 1;
            }
        }
        if (pos < rest.length() && rest.charAt(pos) == '/') {
            int comma = rest.indexOf(',', pos);
            int end = comma < 0 ? rest.length() : comma;
            parts.add(rest.substring(pos, end));
            pos = comma < 0 ? end : end + 1;
        }
        int ack = pos;
        while (ack < rest.length() && Character.isDigit(rest.charAt(ack))) ack++;
        if (ack > pos) {
            parts.add("ack=" + rest.substring(pos, ack));
            pos = ack;
        }
        String payload = json(rest.substring(pos));
        if (!payload.isEmpty()) parts.add(payload);
        return String.join(" ", parts);
    }

    private static String join(String type, String payload) {
        return payload.isEmpty() ? type : type + " " + payload;
    }

    /** A JSON payload compacted, or the text as it is when it is not JSON. */
    private static String json(String s) {
        if (s.isEmpty()) return s;
        try {
            return Json.compact(Json.parse(s));
        } catch (DecodeException e) {
            return escape(s);
        }
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c >= 0x20 && c < 0x7f && c != '\\') sb.append((char) c);
            else sb.append(String.format(Locale.ROOT, "\\x%02x", c));
        }
        return sb.toString();
    }
}
