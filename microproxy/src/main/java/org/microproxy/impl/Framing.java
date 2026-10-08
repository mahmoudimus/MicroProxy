package org.microproxy.impl;

import java.util.List;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;

/** How the end of a message body is determined (RFC 9112 section 6). */
record Framing(Kind kind, long length) {

    enum Kind {
        /** No body at all. */
        NONE,
        /** {@code Content-Length} bytes. */
        LENGTH,
        /** {@code Transfer-Encoding: chunked}. */
        CHUNKED,
        /** Everything until the connection closes (responses only). */
        UNTIL_CLOSE
    }

    static final Framing NONE = new Framing(Kind.NONE, 0);
    static final Framing CHUNKED = new Framing(Kind.CHUNKED, -1);
    static final Framing UNTIL_CLOSE = new Framing(Kind.UNTIL_CLOSE, -1);

    boolean hasBody() {
        return kind != Kind.NONE && !(kind == Kind.LENGTH && length == 0);
    }

    /**
     * Determines and normalizes the framing of a request. Requests with both {@code
     * Transfer-Encoding} and {@code Content-Length}, conflicting lengths, or a transfer coding
     * other than a final {@code chunked} are rejected, closing the usual request smuggling holes.
     */
    static Framing forRequest(HttpRequest request) throws HttpParseException {
        HttpHeaders headers = request.headers();
        if (headers.contains(HttpHeaderNames.TRANSFER_ENCODING)) {
            if (headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
                throw new HttpParseException("both Transfer-Encoding and Content-Length present");
            }
            List<String> codings = headers.getAllElements(HttpHeaderNames.TRANSFER_ENCODING);
            if (codings.isEmpty() || !codings.get(codings.size() - 1).equalsIgnoreCase("chunked")) {
                throw new HttpParseException("request transfer coding must end with chunked");
            }
            return CHUNKED;
        }
        long length = contentLength(request);
        if (length < 0) {
            return NONE;
        }
        return length == 0 ? NONE : new Framing(Kind.LENGTH, length);
    }

    /** Determines the framing of a response to a request with {@code requestMethod}. */
    static Framing forResponse(HttpResponse response, HttpMethod requestMethod)
            throws HttpParseException {
        int code = response.status().code();
        if (requestMethod.equals(HttpMethod.HEAD)
                || (code >= 100 && code < 200)
                || code == HttpResponseStatus.NO_CONTENT.code()
                || code == HttpResponseStatus.NOT_MODIFIED.code()
                || (requestMethod.equals(HttpMethod.CONNECT) && code >= 200 && code < 300)) {
            return NONE;
        }
        HttpHeaders headers = response.headers();
        if (headers.contains(HttpHeaderNames.TRANSFER_ENCODING)) {
            List<String> codings = headers.getAllElements(HttpHeaderNames.TRANSFER_ENCODING);
            if (!codings.isEmpty() && codings.get(codings.size() - 1).equalsIgnoreCase("chunked")) {
                headers.remove(HttpHeaderNames.CONTENT_LENGTH);
                return CHUNKED;
            }
            headers.remove(HttpHeaderNames.CONTENT_LENGTH);
            return UNTIL_CLOSE;
        }
        long length = contentLength(response);
        if (length < 0) {
            return UNTIL_CLOSE;
        }
        return length == 0 ? new Framing(Kind.LENGTH, 0) : new Framing(Kind.LENGTH, length);
    }

    /** Whether a body may be written for this response at all. */
    static boolean responseMayHaveBody(HttpResponse response, HttpMethod requestMethod) {
        int code = response.status().code();
        return !requestMethod.equals(HttpMethod.HEAD)
                && !(code >= 100 && code < 200)
                && code != 204
                && code != 304;
    }

    /**
     * Parses {@code Content-Length}, collapsing identical repeated values.
     *
     * @return the length, or -1 if absent
     */
    private static long contentLength(HttpMessage message) throws HttpParseException {
        List<String> values = message.headers().getAllElements(HttpHeaderNames.CONTENT_LENGTH);
        if (values.isEmpty()) {
            return -1;
        }
        long length = -1;
        for (String v : values) {
            long parsed = parseLength(v);
            if (length >= 0 && parsed != length) {
                throw new HttpParseException("conflicting Content-Length values");
            }
            length = parsed;
        }
        if (values.size() > 1) {
            message.headers().set(HttpHeaderNames.CONTENT_LENGTH, length);
        }
        return length;
    }

    private static long parseLength(String v) throws HttpParseException {
        if (v.isEmpty() || v.length() > 18) {
            throw new HttpParseException("invalid Content-Length");
        }
        for (int i = 0; i < v.length(); i++) {
            if (v.charAt(i) < '0' || v.charAt(i) > '9') {
                throw new HttpParseException("invalid Content-Length");
            }
        }
        return Long.parseLong(v);
    }
}
