/*
 * The HAR reading is ported from mitmproxy's mitmproxy/io/har.py
 * (https://github.com/mitmproxy/mitmproxy), Copyright (c) 2013, Aldo Cortesi. Licensed under the
 * MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import java.util.zip.InflaterInputStream;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.warc.WarcReader;

/**
 * A recorded exchange, read from a HAR file (as {@link HarRecorder}, browsers and mitmproxy write
 * them) or a WARC file (as {@link org.microproxy.warc.WarcRecorder} writes them), for {@link
 * ServerReplay} and {@link ClientReplay}.
 *
 * <p>The response's headers describe its body as stored: HAR bodies are decoded, so their {@code
 * Content-Encoding} is dropped; WARC bodies keep the coding they were received with. Framing
 * headers ({@code Content-Length}, {@code Transfer-Encoding}) are dropped, since the proxy frames
 * replayed messages itself.
 *
 * @param started when the exchange started, or null if not recorded
 * @param method the request method
 * @param url the absolute request URL
 * @param requestHeaders the request headers, in order
 * @param requestBody the request body (empty if none)
 * @param status the response status, or 0 if the exchange has no response
 * @param reason the response reason phrase
 * @param responseHeaders the response headers, in order
 * @param responseBody the response body
 * @param complete whether the response body was recorded in full
 */
public record RecordedExchange(Instant started, String method, String url,
        List<Map.Entry<String, String>> requestHeaders, byte[] requestBody,
        int status, String reason, List<Map.Entry<String, String>> responseHeaders, byte[] responseBody,
        boolean complete) {

    /** Checks the parts and copies the lists. */
    public RecordedExchange {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(url, "url");
        requestHeaders = List.copyOf(requestHeaders);
        responseHeaders = List.copyOf(responseHeaders);
        requestBody = requestBody == null ? new byte[0] : requestBody;
        responseBody = responseBody == null ? new byte[0] : responseBody;
        reason = reason == null ? "" : reason;
    }

    /** {@return whether there is a complete response to replay} */
    public boolean replayable() {
        return status >= 100 && complete;
    }

    /**
     * The first value of a request header, without regard to case.
     *
     * @param name the header name
     * @return the value, or null
     */
    public String requestHeader(String name) {
        return first(requestHeaders, name);
    }

    /**
     * The first value of a response header, without regard to case.
     *
     * @param name the header name
     * @return the value, or null
     */
    public String responseHeader(String name) {
        return first(responseHeaders, name);
    }

    private static String first(List<Map.Entry<String, String>> headers, String name) {
        for (Map.Entry<String, String> h : headers) {
            if (h.getKey().equalsIgnoreCase(name)) return h.getValue();
        }
        return null;
    }

    // ---------------------------------------------------------------------------------------
    // Loading
    // ---------------------------------------------------------------------------------------

    /**
     * Reads exchanges from a HAR file ({@code .har}, or zlib-compressed {@code .zhar}), a WARC file
     * ({@code .warc}, {@code .warc.gz}), or every such file in a directory (in name order). The
     * format is told from the content, not the name.
     *
     * @param path a file or directory
     * @return the exchanges, in recorded order
     * @throws IOException if a file cannot be read or is in neither format
     */
    public static List<RecordedExchange> load(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            List<RecordedExchange> all = new ArrayList<>();
            try (Stream<Path> files = Files.list(path)) {
                for (Path f : files.filter(Files::isRegularFile).filter(RecordedExchange::looksRecorded).sorted().toList()) {
                    all.addAll(load(f));
                }
            }
            return all;
        }
        try (InputStream in = Files.newInputStream(path)) {
            byte[] start = in.readNBytes(5);
            boolean warc = (start.length >= 2 && (start[0] & 0xff) == 0x1f && (start[1] & 0xff) == 0x8b)
                    || new String(start, ISO_8859_1).startsWith("WARC/");
            return warc ? readWarc(path) : readHar(path);
        }
    }

    private static boolean looksRecorded(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".har") || name.endsWith(".zhar") || name.endsWith(".warc") || name.endsWith(".warc.gz");
    }

    /**
     * Reads the entries of a HAR file. Entries without a response keep status 0; responses cut
     * short by a recorder ({@code _truncated}) are marked incomplete.
     *
     * @param file a {@code .har} file, or a zlib-compressed {@code .zhar} file
     * @return the exchanges, in order
     * @throws IOException if the file cannot be read or is not HAR
     */
    public static List<RecordedExchange> readHar(Path file) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        if (bytes.length > 0 && bytes[0] == 0x78) {
            try (InputStream in = new InflaterInputStream(new java.io.ByteArrayInputStream(bytes))) {
                bytes = in.readAllBytes();
            }
        }
        return parseHar(new String(bytes, UTF_8));
    }

    /**
     * Parses a HAR document.
     *
     * @param json the HAR text
     * @return the exchanges, in order
     * @throws IOException if the text is not HAR
     */
    public static List<RecordedExchange> parseHar(String json) throws IOException {
        Object root;
        try {
            root = Json.parse(json);
        } catch (IllegalArgumentException e) {
            throw new IOException("not a HAR file: " + e.getMessage(), e);
        }
        Map<?, ?> log = map(map(root).get("log"));
        if (!(log.get("entries") instanceof List<?> entries)) throw new IOException("not a HAR file: no log.entries");
        List<RecordedExchange> out = new ArrayList<>();
        for (Object e : entries) {
            try {
                out.add(harEntry(map(e)));
            } catch (RuntimeException ex) {
                throw new IOException("invalid HAR entry " + out.size() + ": " + ex.getMessage(), ex);
            }
        }
        return out;
    }

    private static RecordedExchange harEntry(Map<?, ?> entry) {
        Map<?, ?> request = map(entry.get("request"));
        Map<?, ?> response = entry.get("response") instanceof Map<?, ?> r ? r : Map.of();
        Instant started = null;
        if (entry.get("startedDateTime") instanceof String s) {
            try {
                started = OffsetDateTime.parse(s).toInstant();
            } catch (DateTimeParseException ignored) {
                // Some tools write other formats; the time only refreshes replayed dates.
            }
        }
        List<Map.Entry<String, String>> requestHeaders = harHeaders(request.get("headers"));
        byte[] requestBody = new byte[0];
        if (request.get("postData") instanceof Map<?, ?> post && post.get("text") instanceof String text) {
            requestBody = "base64".equals(post.get("encoding")) ? Base64.getMimeDecoder().decode(text)
                    : text.getBytes(charset(str(post.get("mimeType")), UTF_8));
        }
        int status = response.get("status") instanceof Number n ? n.intValue() : 0;
        List<Map.Entry<String, String>> responseHeaders = harHeaders(response.get("headers"));
        byte[] responseBody = new byte[0];
        boolean complete = true;
        boolean stillEncoded = false;
        if (response.get("content") instanceof Map<?, ?> content) {
            if (content.get("text") instanceof String text) {
                String type = first(responseHeaders, "Content-Type");
                responseBody = "base64".equals(content.get("encoding")) ? Base64.getMimeDecoder().decode(text)
                        : text.getBytes(charset(type != null ? type : str(content.get("mimeType")), UTF_8));
            }
            complete = !Boolean.TRUE.equals(content.get("_truncated"));
            stillEncoded = Boolean.TRUE.equals(content.get("_contentEncoded"));
        }
        List<Map.Entry<String, String>> kept = new ArrayList<>();
        for (Map.Entry<String, String> h : responseHeaders) {
            if (h.getKey().equalsIgnoreCase("Content-Encoding") && !stillEncoded) continue;
            if (framing(h.getKey())) continue;
            kept.add(h);
        }
        return new RecordedExchange(started, str(request.get("method")), str(request.get("url")),
                requestHeaders, requestBody, status, str(response.get("statusText")), kept, responseBody, complete);
    }

    /** HAR headers: {@code {"name":..,"value":..}} objects, or {@code [name, value]} pairs. */
    private static List<Map.Entry<String, String>> harHeaders(Object headers) {
        List<Map.Entry<String, String>> out = new ArrayList<>();
        if (!(headers instanceof List<?> list)) return out;
        for (Object h : list) {
            String name;
            String value;
            if (h instanceof Map<?, ?> m) {
                name = str(m.get("name"));
                value = str(m.get("value"));
            } else if (h instanceof List<?> pair && pair.size() >= 2) {
                name = str(pair.get(0));
                value = str(pair.get(1));
            } else {
                continue;
            }
            // HTTP/2 pseudo-headers (Chrome writes them) are not headers.
            if (name.isEmpty() || name.startsWith(":")) continue;
            out.add(Map.entry(name, value));
        }
        return out;
    }

    /**
     * Reads the exchanges of a WARC file: each {@code response} record with its {@code request}
     * record (linked by {@code WARC-Concurrent-To}). Responses without a request record get a
     * {@code GET} of their target URI; responses cut short ({@code WARC-Truncated}) are marked
     * incomplete.
     *
     * @param file a {@code .warc} or {@code .warc.gz} file
     * @return the exchanges, in the order of their responses
     * @throws IOException if the file cannot be read or is not WARC
     */
    public static List<RecordedExchange> readWarc(Path file) throws IOException {
        List<WarcReader.Record> responses = new ArrayList<>();
        Map<String, WarcReader.Record> requestsById = new HashMap<>();
        Map<String, WarcReader.Record> requestsByResponse = new HashMap<>();
        try (WarcReader reader = WarcReader.open(file)) {
            for (WarcReader.Record r; (r = reader.next()) != null; ) {
                String contentType = String.valueOf(r.field("Content-Type")).toLowerCase(Locale.ROOT);
                if (!contentType.startsWith("application/http")) continue;
                switch (r.type()) {
                    case "response" -> responses.add(r);
                    case "request" -> {
                        if (r.id() != null) requestsById.put(r.id(), r);
                        String to = r.field("WARC-Concurrent-To");
                        if (to != null) requestsByResponse.put(to.strip(), r);
                    }
                    default -> {
                        // warcinfo, metadata, resource, revisit...: nothing to replay.
                    }
                }
            }
        }
        List<RecordedExchange> out = new ArrayList<>();
        for (WarcReader.Record response : responses) {
            WarcReader.Record request = requestsByResponse.get(response.id());
            String to = response.field("WARC-Concurrent-To");
            if (request == null && to != null) request = requestsById.get(to.strip());
            out.add(warcExchange(response, request));
        }
        return out;
    }

    private static RecordedExchange warcExchange(WarcReader.Record response, WarcReader.Record request) {
        String target = String.valueOf(response.field("WARC-Target-URI")).strip();
        if (target.startsWith("<") && target.endsWith(">")) target = target.substring(1, target.length() - 1);
        Instant started = null;
        String date = response.field("WARC-Date");
        if (date != null) {
            try {
                started = Instant.parse(date.strip());
            } catch (DateTimeParseException ignored) {
                // Not needed to replay.
            }
        }
        Message res = Message.parse(response.block());
        String method = "GET";
        List<Map.Entry<String, String>> requestHeaders = List.of();
        byte[] requestBody = new byte[0];
        if (request != null) {
            Message req = Message.parse(request.block());
            String[] line = req.startLine.split(" ", 3);
            method = line[0];
            requestHeaders = req.headers;
            requestBody = req.body;
        }
        String[] status = res.startLine.split(" ", 3);
        int code;
        try {
            code = Integer.parseInt(status.length > 1 ? status[1] : "");
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("WARC response record " + response.id() + " has no status line");
        }
        List<Map.Entry<String, String>> headers = res.headers.stream().filter(h -> !framing(h.getKey())).toList();
        return new RecordedExchange(started, method, target, requestHeaders, requestBody, code,
                status.length > 2 ? status[2] : "", headers, res.body, response.field("WARC-Truncated") == null);
    }

    /** An HTTP message from a WARC block: start line, headers, and the body (de-chunked). */
    private record Message(String startLine, List<Map.Entry<String, String>> headers, byte[] body) {

        static Message parse(byte[] block) {
            int end = indexOf(block, "\r\n\r\n".getBytes(ISO_8859_1));
            int bodyStart = end + 4;
            if (end < 0) {
                end = indexOf(block, "\n\n".getBytes(ISO_8859_1));
                bodyStart = end + 2;
            }
            if (end < 0) {
                end = block.length;
                bodyStart = block.length;
            }
            String[] lines = new String(block, 0, end, ISO_8859_1).split("\r?\n");
            List<Map.Entry<String, String>> headers = new ArrayList<>();
            for (int i = 1; i < lines.length; i++) {
                String l = lines[i];
                int colon = l.indexOf(':');
                if (colon <= 0) continue;
                headers.add(Map.entry(l.substring(0, colon).strip(), l.substring(colon + 1).strip()));
            }
            byte[] body = java.util.Arrays.copyOfRange(block, Math.min(bodyStart, block.length), block.length);
            boolean chunked = headers.stream().anyMatch(h -> h.getKey().equalsIgnoreCase("Transfer-Encoding")
                    && h.getValue().toLowerCase(Locale.ROOT).contains("chunked"));
            return new Message(lines[0], headers, chunked ? dechunk(body) : body);
        }
    }

    /** Removes chunked transfer coding, keeping what can be read of a damaged body. */
    static byte[] dechunk(byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(body.length);
        int pos = 0;
        while (pos < body.length) {
            int eol = indexOf(body, pos, (byte) '\n');
            if (eol < 0) break;
            String size = new String(body, pos, eol - pos, ISO_8859_1).strip();
            int semi = size.indexOf(';');
            if (semi >= 0) size = size.substring(0, semi).strip();
            int n;
            try {
                n = Integer.parseInt(size, 16);
            } catch (NumberFormatException e) {
                break;
            }
            if (n <= 0) break;
            int start = eol + 1;
            int take = Math.min(n, body.length - start);
            out.write(body, start, take);
            pos = start + take;
            while (pos < body.length && (body[pos] == '\r' || body[pos] == '\n')) pos++;
        }
        return out.toByteArray();
    }

    private static int indexOf(byte[] data, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static int indexOf(byte[] data, int from, byte b) {
        for (int i = from; i < data.length; i++) {
            if (data[i] == b) return i;
        }
        return -1;
    }

    /** Whether a header describes framing, which the proxy sets itself. */
    static boolean framing(String name) {
        return name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase("Transfer-Encoding");
    }

    private static Charset charset(String contentType, Charset fallback) {
        if (contentType == null) return fallback;
        DefaultHttpResponse probe = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        try {
            probe.headers().set("Content-Type", contentType);
        } catch (IllegalArgumentException e) {
            return fallback;
        }
        return HttpBodies.charset(probe, fallback);
    }

    private static Map<?, ?> map(Object o) {
        if (o instanceof Map<?, ?> m) return m;
        throw new IllegalArgumentException("expected an object, got " + (o == null ? "null" : o.getClass().getSimpleName()));
    }

    private static String str(Object o) {
        return o == null ? "" : o instanceof String s ? s : String.valueOf(o);
    }

    @Override
    public String toString() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("method", method);
        m.put("url", url);
        m.put("status", status);
        m.put("requestBody", requestBody.length);
        m.put("responseBody", responseBody.length);
        return "RecordedExchange" + m;
    }
}
