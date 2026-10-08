package org.microproxy.impl;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.microproxy.http.DefaultHttpContent;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.DefaultLastHttpContent;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;

/** Blocking HTTP/1.x parsing and serialization. */
final class HttpCodec {

    private HttpCodec() {}

    /** Size limits applied while parsing. */
    record Limits(int maxInitialLineLength, int maxHeaderSize, int maxChunkSize) {}

    /**
     * Reads a request head.
     *
     * @return the request, or {@code null} if the connection closed cleanly before a request
     */
    static HttpRequest readRequest(ByteReader in, Limits limits) throws IOException {
        String line;
        int emptyLines = 0;
        do {
            line = in.readLine(limits.maxInitialLineLength(), HttpResponseStatus.valueOf(414));
            if (line == null) return null;
            // RFC 9112 2.2: ignore at least one empty line before the request-line.
        } while (line.isEmpty() && ++emptyLines < 8);
        int sp1 = line.indexOf(' ');
        int sp2 = line.lastIndexOf(' ');
        if (sp1 <= 0 || sp2 <= sp1 + 1 || sp2 == line.length() - 1) {
            throw new HttpParseException("malformed request line");
        }
        HttpMethod method;
        HttpVersion version;
        try {
            method = HttpMethod.valueOf(line.substring(0, sp1));
            version = HttpVersion.valueOf(line.substring(sp2 + 1));
        } catch (IllegalArgumentException e) {
            throw new HttpParseException("malformed request line");
        }
        if (version.majorVersion() != 1) {
            throw new HttpParseException(HttpResponseStatus.valueOf(505), "unsupported version");
        }
        String uri = line.substring(sp1 + 1, sp2);
        HttpHeaders headers = readHeaders(in, limits.maxHeaderSize(), false);
        try {
            return new DefaultHttpRequest(version, method, uri, headers);
        } catch (IllegalArgumentException e) {
            throw new HttpParseException("malformed request-target");
        }
    }

    /**
     * Reads a response head.
     *
     * @return the response, or {@code null} if the connection closed before a response
     */
    static HttpResponse readResponse(ByteReader in, Limits limits) throws IOException {
        String line = in.readLine(limits.maxInitialLineLength(), HttpResponseStatus.BAD_GATEWAY);
        if (line == null) return null;
        // status-line = HTTP-version SP status-code SP [ reason-phrase ]
        if (line.length() < 12 || line.charAt(8) != ' ') {
            throw new HttpParseException(HttpResponseStatus.BAD_GATEWAY, "malformed status line");
        }
        HttpVersion version;
        int code;
        try {
            version = HttpVersion.valueOf(line.substring(0, 8));
            String codeText = line.substring(9, 12);
            for (int i = 0; i < 3; i++) {
                if (!Character.isDigit(codeText.charAt(i))) throw new NumberFormatException();
            }
            code = Integer.parseInt(codeText);
            if (code < 100) throw new NumberFormatException();
        } catch (IllegalArgumentException e) {
            throw new HttpParseException(HttpResponseStatus.BAD_GATEWAY, "malformed status line");
        }
        String reason = line.length() > 13 ? line.substring(13) : "";
        HttpHeaders headers = readHeaders(in, limits.maxHeaderSize(), true);
        return new DefaultHttpResponse(version, HttpResponseStatus.valueOf(code, reason), headers);
    }

    /** Reads header fields up to and including the empty line. */
    static HttpHeaders readHeaders(ByteReader in, int maxSize, boolean lenient) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        HttpResponseStatus tooLarge =
                lenient ? HttpResponseStatus.BAD_GATEWAY : HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE;
        HttpResponseStatus malformed = lenient ? HttpResponseStatus.BAD_GATEWAY : HttpResponseStatus.BAD_REQUEST;
        int total = 0;
        String pendingName = null;
        StringBuilder pendingValue = null;
        while (true) {
            String line = in.readLine(Math.max(0, maxSize - total), tooLarge);
            if (line == null) {
                throw new java.io.EOFException("connection closed in headers");
            }
            total += line.length() + 2;
            if (total > maxSize + 2) {
                throw new HttpParseException(tooLarge, "headers too large");
            }
            if (line.isEmpty()) {
                break;
            }
            char first = line.charAt(0);
            if (first == ' ' || first == '\t') {
                // obs-fold: rejected in requests (RFC 9112 5.2), unfolded in responses.
                if (!lenient || pendingName == null) {
                    throw new HttpParseException(malformed, "obsolete line folding");
                }
                pendingValue.append(' ').append(line.strip());
                continue;
            }
            if (pendingName != null) {
                addHeader(headers, pendingName, pendingValue.toString(), malformed);
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new HttpParseException(malformed, "malformed header line");
            }
            pendingName = line.substring(0, colon);
            pendingValue = new StringBuilder(line.substring(colon + 1).strip());
        }
        if (pendingName != null) {
            addHeader(headers, pendingName, pendingValue.toString(), malformed);
        }
        return headers;
    }

    private static void addHeader(
            HttpHeaders headers, String name, String value, HttpResponseStatus malformed)
            throws HttpParseException {
        try {
            headers.add(name, value);
        } catch (IllegalArgumentException e) {
            // Includes whitespace between the field name and colon (RFC 9112 5.1).
            throw new HttpParseException(malformed, "invalid header field: " + name);
        }
    }

    /** Pulls a message body off the wire in pieces of at most {@code maxChunkSize} bytes. */
    static final class BodyReader {

        private final ByteReader in;
        private final Framing framing;
        private final Limits limits;
        private long remaining;
        private boolean done;
        private long chunkRemaining = -1;

        BodyReader(ByteReader in, Framing framing, Limits limits) {
            this.in = in;
            this.framing = framing;
            this.limits = limits;
            this.remaining = framing.length();
        }

        boolean isDone() {
            return done;
        }

        /**
         * Returns the next body piece, ending with a {@link LastHttpContent}; {@code null} once the
         * last piece has been returned.
         */
        HttpContent next() throws IOException {
            if (done) return null;
            return switch (framing.kind()) {
                case NONE -> finish(new DefaultLastHttpContent());
                case LENGTH -> nextFixed();
                case CHUNKED -> nextChunked();
                case UNTIL_CLOSE -> nextUntilClose();
            };
        }

        private HttpContent finish(LastHttpContent last) {
            done = true;
            return last;
        }

        private HttpContent nextFixed() throws IOException {
            if (remaining == 0) return finish(new DefaultLastHttpContent());
            byte[] data = readSome((int) Math.min(remaining, limits.maxChunkSize()));
            if (data == null) {
                throw new java.io.EOFException("connection closed before end of body");
            }
            remaining -= data.length;
            return remaining == 0 ? finish(new DefaultLastHttpContent(data)) : new DefaultHttpContent(data);
        }

        private HttpContent nextUntilClose() throws IOException {
            byte[] data = readSome(limits.maxChunkSize());
            return data == null ? finish(new DefaultLastHttpContent()) : new DefaultHttpContent(data);
        }

        private HttpContent nextChunked() throws IOException {
            if (chunkRemaining <= 0) {
                if (chunkRemaining == 0) {
                    String crlf = in.readLine(2, HttpResponseStatus.BAD_REQUEST);
                    if (crlf == null || !crlf.isEmpty()) {
                        throw new HttpParseException("missing CRLF after chunk data");
                    }
                }
                String sizeLine = in.readLine(1024, HttpResponseStatus.BAD_REQUEST);
                if (sizeLine == null) {
                    throw new java.io.EOFException("connection closed before last chunk");
                }
                long size = parseChunkSize(sizeLine);
                if (size == 0) {
                    HttpHeaders trailers = readHeaders(in, limits.maxHeaderSize(), true);
                    return finish(new DefaultLastHttpContent(new byte[0], trailers));
                }
                chunkRemaining = size;
            }
            byte[] data = readSome((int) Math.min(chunkRemaining, limits.maxChunkSize()));
            if (data == null) {
                throw new java.io.EOFException("connection closed mid-chunk");
            }
            chunkRemaining -= data.length;
            return new DefaultHttpContent(data);
        }

        private static long parseChunkSize(String line) throws HttpParseException {
            int semi = line.indexOf(';');
            String hex = (semi >= 0 ? line.substring(0, semi) : line).strip();
            if (hex.isEmpty() || hex.length() > 15) {
                throw new HttpParseException("invalid chunk size");
            }
            try {
                return Long.parseLong(hex, 16);
            } catch (NumberFormatException e) {
                throw new HttpParseException("invalid chunk size");
            }
        }

        private byte[] readSome(int max) throws IOException {
            byte[] tmp = new byte[max];
            int n = in.read(tmp, 0, max);
            if (n < 0) return null;
            return n == max ? tmp : java.util.Arrays.copyOf(tmp, n);
        }
    }

    /** Serializes messages, applying chunked framing when the message head asks for it. */
    static final class HttpWriter {

        private static final byte[] CRLF = {'\r', '\n'};

        private final OutputStream out;
        private boolean chunked;
        private boolean bodyAllowed = true;

        HttpWriter(OutputStream out) {
            this.out = out;
        }

        /**
         * Writes a message head; a {@link FullHttpMessage} is written completely, with its {@code
         * Content-Length} corrected to the actual body size.
         *
         * @param bodyAllowed false for messages that never carry a body on the wire (responses to
         *     HEAD, 1xx/204/304, CONNECT 2xx)
         */
        void writeHead(HttpMessage message, boolean bodyAllowed) throws IOException {
            this.bodyAllowed = bodyAllowed;
            this.chunked = bodyAllowed && HttpUtil.isTransferEncodingChunked(message);
            if (message instanceof FullHttpMessage full && bodyAllowed && !chunked) {
                boolean isRequest = message instanceof FullHttpRequest;
                if (!isRequest || full.content().length > 0 || message.headers().contains(HttpHeaderNames.CONTENT_LENGTH)) {
                    HttpUtil.setContentLength(message, full.content().length);
                }
            }
            StringBuilder sb = new StringBuilder(256);
            if (message instanceof HttpRequest req) {
                sb.append(req.method().name()).append(' ').append(req.uri()).append(' ')
                        .append(req.protocolVersion().text());
            } else {
                HttpResponse res = (HttpResponse) message;
                sb.append(res.protocolVersion().text()).append(' ').append(res.status().code())
                        .append(' ').append(res.status().reasonPhrase());
            }
            sb.append("\r\n");
            appendHeaders(sb, message.headers());
            sb.append("\r\n");
            out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
            if (message instanceof FullHttpMessage full) {
                writeContent(full);
            } else {
                out.flush();
            }
        }

        /** Writes a body piece. */
        void writeContent(HttpContent content) throws IOException {
            byte[] data = content.content();
            boolean last = content instanceof LastHttpContent;
            if (bodyAllowed) {
                if (chunked) {
                    if (data.length > 0) {
                        out.write(Integer.toHexString(data.length).getBytes(StandardCharsets.ISO_8859_1));
                        out.write(CRLF);
                        out.write(data);
                        out.write(CRLF);
                    }
                    if (last) {
                        StringBuilder sb = new StringBuilder("0\r\n");
                        appendHeaders(sb, ((LastHttpContent) content).trailingHeaders());
                        sb.append("\r\n");
                        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
                    }
                } else if (data.length > 0) {
                    out.write(data);
                }
            }
            out.flush();
        }

        private static void appendHeaders(StringBuilder sb, HttpHeaders headers) {
            for (Map.Entry<String, String> e : headers) {
                sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
        }
    }
}
