package org.microproxy.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
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
    // @value-candidate: becomes a value class in the valhalla build profile
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
        String pendingValue = null;
        while (true) {
            String line = in.readLine(Math.max(0, maxSize - total), tooLarge);
            if (line == null) {
                throw new EOFException("connection closed in headers");
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
                pendingValue = pendingValue + ' ' + line.strip();
                continue;
            }
            if (pendingName != null) {
                addHeader(headers, pendingName, pendingValue, malformed);
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new HttpParseException(malformed, "malformed header line");
            }
            pendingName = line.substring(0, colon);
            int from = colon + 1;
            int to = line.length();
            while (from < to && isOws(line.charAt(from))) from++;
            while (to > from && isOws(line.charAt(to - 1))) to--;
            pendingValue = line.substring(from, to);
        }
        if (pendingName != null) {
            addHeader(headers, pendingName, pendingValue, malformed);
        }
        return headers;
    }

    private static boolean isOws(char c) {
        return Character.isWhitespace(c);
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
                throw new EOFException("connection closed before end of body");
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
                    throw new EOFException("connection closed before last chunk");
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
                throw new EOFException("connection closed mid-chunk");
            }
            chunkRemaining -= data.length;
            return new DefaultHttpContent(data);
        }

        private HttpHeaders trailers = new HttpHeaders();

        /**
         * Reads body data (without framing) into {@code dst}: the fast path for relaying bodies no
         * filter inspects. Returns -1 once the body is complete; {@link #trailers()} are then
         * available. Do not mix with {@link #next()} on the same body.
         */
        int read(byte[] dst, int off, int len) throws IOException {
            if (done) return -1;
            return switch (framing.kind()) {
                case NONE -> {
                    done = true;
                    yield -1;
                }
                case LENGTH -> {
                    if (remaining == 0) {
                        done = true;
                        yield -1;
                    }
                    int n = in.read(dst, off, (int) Math.min(len, remaining));
                    if (n < 0) throw new EOFException("connection closed before end of body");
                    remaining -= n;
                    yield n;
                }
                case UNTIL_CLOSE -> {
                    int n = in.read(dst, off, len);
                    if (n < 0) done = true;
                    yield n;
                }
                case CHUNKED -> {
                    if (chunkRemaining <= 0) {
                        if (chunkRemaining == 0) {
                            String crlf = in.readLine(2, HttpResponseStatus.BAD_REQUEST);
                            if (crlf == null || !crlf.isEmpty()) {
                                throw new HttpParseException("missing CRLF after chunk data");
                            }
                        }
                        String sizeLine = in.readLine(1024, HttpResponseStatus.BAD_REQUEST);
                        if (sizeLine == null) throw new EOFException("connection closed before last chunk");
                        long size = parseChunkSize(sizeLine);
                        if (size == 0) {
                            trailers = readHeaders(in, limits.maxHeaderSize(), true);
                            done = true;
                            yield -1;
                        }
                        chunkRemaining = size;
                    }
                    int n = in.read(dst, off, (int) Math.min(len, chunkRemaining));
                    if (n < 0) throw new EOFException("connection closed mid-chunk");
                    chunkRemaining -= n;
                    yield n;
                }
            };
        }

        /** The trailer fields of a chunked body, once {@link #read} has returned -1. */
        HttpHeaders trailers() {
            return trailers;
        }

        /** Whether more input is already buffered, so a flush can wait. */
        boolean hasBufferedInput() {
            return in.buffered() > 0;
        }

        /**
         * {@code chunk-size [BWS ";" ...]} (RFC 9112 section 7.1): hex digits only. A sign or
         * leading whitespace is rejected, since parsers that disagree on it enable smuggling.
         */
        private static long parseChunkSize(String line) throws HttpParseException {
            int semi = line.indexOf(';');
            String hex = semi >= 0 ? line.substring(0, semi).stripTrailing() : line;
            if (hex.isEmpty() || hex.length() > 15) {
                throw new HttpParseException("invalid chunk size");
            }
            for (int i = 0; i < hex.length(); i++) {
                if (!HexFormat.isHexDigit(hex.charAt(i))) {
                    throw new HttpParseException("invalid chunk size");
                }
            }
            return HexFormat.fromHexDigitsToLong(hex);
        }

        private byte[] readSome(int max) throws IOException {
            byte[] tmp = new byte[max];
            int n = in.read(tmp, 0, max);
            if (n < 0) return null;
            return n == max ? tmp : Arrays.copyOf(tmp, n);
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
            // Written straight into the (pooled) output buffer, without building a string.
            if (message instanceof HttpRequest req) {
                writeLatin1(req.method().name());
                out.write(' ');
                writeLatin1(req.uri());
                out.write(' ');
                writeLatin1(req.protocolVersion().text());
            } else {
                HttpResponse res = (HttpResponse) message;
                writeLatin1(res.protocolVersion().text());
                out.write(' ');
                writeDecimal(res.status().code());
                out.write(' ');
                writeLatin1(res.status().reasonPhrase());
            }
            out.write(CRLF);
            HttpHeaders headers = message.headers();
            for (int i = 0; i < headers.size(); i++) {
                writeLatin1(headers.nameAt(i));
                out.write(':');
                out.write(' ');
                writeLatin1(headers.valueAt(i));
                out.write(CRLF);
            }
            out.write(CRLF);
            if (message instanceof FullHttpMessage full) {
                writeContent(full);
            } else {
                out.flush();
            }
        }

        /** Writes {@code s} as ISO-8859-1, as {@link String#getBytes} would, without allocating. */
        private void writeLatin1(String s) throws IOException {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                out.write(c <= 0xFF ? c : '?');
            }
        }

        private void writeDecimal(int n) throws IOException {
            if (n >= 10) writeDecimal(n / 10);
            out.write('0' + n % 10);
        }

        /** Writes a body piece. */
        void writeContent(HttpContent content) throws IOException {
            byte[] data = content.content();
            if (bodyAllowed) {
                if (chunked) {
                    if (data.length > 0) {
                        out.write(Integer.toHexString(data.length).getBytes(StandardCharsets.ISO_8859_1));
                        out.write(CRLF);
                        out.write(data);
                        out.write(CRLF);
                    }
                    if (content instanceof LastHttpContent last) {
                        StringBuilder sb = new StringBuilder("0\r\n");
                        appendHeaders(sb, last.trailingHeaders());
                        sb.append("\r\n");
                        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
                    }
                } else if (data.length > 0) {
                    out.write(data);
                }
            }
            out.flush();
        }

        /** Writes body data, framing it as a chunk when the head asked for chunked coding. */
        void writeData(byte[] data, int off, int len) throws IOException {
            if (!bodyAllowed || len == 0) return;
            if (chunked) {
                out.write(Integer.toHexString(len).getBytes(StandardCharsets.ISO_8859_1));
                out.write(CRLF);
                out.write(data, off, len);
                out.write(CRLF);
            } else {
                out.write(data, off, len);
            }
        }

        /** Ends the body (the last chunk and trailers, when chunked) and flushes. */
        void writeEnd(HttpHeaders trailers) throws IOException {
            if (bodyAllowed && chunked) {
                StringBuilder sb = new StringBuilder("0\r\n");
                appendHeaders(sb, trailers);
                sb.append("\r\n");
                out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
            }
            out.flush();
        }

        void flush() throws IOException {
            out.flush();
        }

        private static void appendHeaders(StringBuilder sb, HttpHeaders headers) {
            for (Map.Entry<String, String> e : headers) {
                sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
        }
    }
}
