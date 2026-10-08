package org.microproxy.http;

import java.util.List;

/** Helpers for connection-management and framing headers. */
public final class HttpUtil {

    private HttpUtil() {}

    /**
     * Whether the sender of {@code message} wants the connection kept open afterwards, following
     * the {@code Connection} header and the protocol version's default.
     */
    public static boolean isKeepAlive(HttpMessage message) {
        HttpHeaders headers = message.headers();
        if (headers.containsValue(HttpHeaderNames.CONNECTION, "close", true)) {
            return false;
        }
        if (message.protocolVersion().isKeepAliveDefault()) {
            return true;
        }
        return headers.containsValue(HttpHeaderNames.CONNECTION, "keep-alive", true);
    }

    /** Sets the {@code Connection} header so that {@link #isKeepAlive} returns {@code keepAlive}. */
    public static void setKeepAlive(HttpMessage message, boolean keepAlive) {
        HttpHeaders headers = message.headers();
        if (keepAlive) {
            if (message.protocolVersion().isKeepAliveDefault()) {
                headers.remove(HttpHeaderNames.CONNECTION);
            } else {
                headers.set(HttpHeaderNames.CONNECTION, "keep-alive");
            }
        } else {
            headers.set(HttpHeaderNames.CONNECTION, "close");
        }
    }

    /** Whether the final transfer coding is {@code chunked}. */
    public static boolean isTransferEncodingChunked(HttpMessage message) {
        List<String> codings = message.headers().getAllElements(HttpHeaderNames.TRANSFER_ENCODING);
        return !codings.isEmpty() && codings.get(codings.size() - 1).equalsIgnoreCase("chunked");
    }

    /**
     * Makes {@code chunked} the final transfer coding (keeping any other codings) and removes
     * {@code Content-Length}, or removes {@code chunked} again when {@code chunked} is false.
     */
    public static void setTransferEncodingChunked(HttpMessage message, boolean chunked) {
        HttpHeaders headers = message.headers();
        List<String> codings = headers.getAllElements(HttpHeaderNames.TRANSFER_ENCODING);
        codings.removeIf(c -> c.equalsIgnoreCase("chunked"));
        if (chunked) {
            codings.add("chunked");
            headers.remove(HttpHeaderNames.CONTENT_LENGTH);
        }
        if (codings.isEmpty()) {
            headers.remove(HttpHeaderNames.TRANSFER_ENCODING);
        } else {
            headers.set(HttpHeaderNames.TRANSFER_ENCODING, String.join(", ", codings));
        }
    }

    /** The {@code Content-Length} value, or {@code defaultValue} if absent or invalid. */
    public static long getContentLength(HttpMessage message, long defaultValue) {
        String value = message.headers().get(HttpHeaderNames.CONTENT_LENGTH);
        if (value == null) return defaultValue;
        try {
            return Long.parseLong(value.strip());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public static void setContentLength(HttpMessage message, long length) {
        message.headers().set(HttpHeaderNames.CONTENT_LENGTH, length);
    }

    /** Whether the request carries {@code Expect: 100-continue}. */
    public static boolean is100ContinueExpected(HttpRequest request) {
        return request.protocolVersion().isKeepAliveDefault()
                && request.headers().containsValue(HttpHeaderNames.EXPECT, "100-continue", true);
    }
}
