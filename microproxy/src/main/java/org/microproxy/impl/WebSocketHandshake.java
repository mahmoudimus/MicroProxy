package org.microproxy.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/** The HTTP/1 handshake fields that an RFC 8441 bridge must generate and verify. */
final class WebSocketHandshake {
    private static final SecureRandom NONCES = new SecureRandom();

    private WebSocketHandshake() {}

    static String key() {
        byte[] nonce = new byte[16];
        NONCES.nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }

    static String accept(String key) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
                    .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean valid(HttpRequest request, HttpResponse response) {
        String key = request.headers().get("Sec-WebSocket-Key");
        return response.status().code() == 101 && key != null
                && response.headers().containsValue(HttpHeaderNames.UPGRADE, "websocket", true)
                && response.headers().containsValue(HttpHeaderNames.CONNECTION, "upgrade", true)
                && response.headers().count("Sec-WebSocket-Accept") == 1
                && accept(key).equals(response.headers().get("Sec-WebSocket-Accept"));
    }
}
