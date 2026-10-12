/*
 * Ported from mitmproxy (https://github.com/mitmproxy/mitmproxy),
 * mitmproxy/contentviews/_view_urlencoded.py, _view_query.py, _view_multipart.py and the
 * merge_repeated_keys helper of _utils.py: form fields and query parameters as YAML, with
 * repeated names merged into lists; and mitmproxy/net/http/multipart.py for splitting
 * multipart/form-data. Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.contentviews;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Views of form data: URL-encoded bodies, query strings and multipart/form-data. */
final class FormViews {

    private FormViews() {}

    /** Name-value pairs as a mapping; a name given more than once maps to a list of its values. */
    static Yaml.Mapping merged(List<Map.Entry<String, Yaml.Node>> pairs) {
        Map<String, List<Yaml.Node>> byName = new LinkedHashMap<>();
        for (Map.Entry<String, Yaml.Node> p : pairs) byName.computeIfAbsent(p.getKey(), k -> new ArrayList<>()).add(p.getValue());
        Yaml.Mapping out = new Yaml.Mapping();
        for (Map.Entry<String, List<Yaml.Node>> e : byName.entrySet()) {
            List<Yaml.Node> values = e.getValue();
            out.put(Yaml.string(e.getKey()), values.size() == 1 ? values.getFirst() : new Yaml.Sequence(values));
        }
        return out;
    }

    /** {@code a=1&b=2&a=3} as pairs, percent- and plus-decoded. */
    static List<Map.Entry<String, Yaml.Node>> urlEncoded(String text, Charset charset) {
        List<Map.Entry<String, Yaml.Node>> pairs = new ArrayList<>();
        for (String pair : text.split("[&;]")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = decode(eq >= 0 ? pair.substring(0, eq) : pair, charset);
            String value = eq >= 0 ? decode(pair.substring(eq + 1), charset) : "";
            pairs.add(Map.entry(name, new Yaml.Scalar(Yaml.string(value))));
        }
        return pairs;
    }

    private static String decode(String s, Charset charset) {
        try {
            return URLDecoder.decode(s, charset);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    /** {@code application/x-www-form-urlencoded} bodies. */
    static final class UrlEncoded implements ContentView {
        @Override
        public String name() {
            return "urlencoded";
        }

        @Override
        public double priority(byte[] data, Metadata metadata) {
            return data.length > 0 && metadata.mediaType().equals("application/x-www-form-urlencoded") ? 1 : 0;
        }

        @Override
        public String render(byte[] data, Metadata metadata) throws DecodeException {
            Charset charset = JsonView.charset(metadata);
            List<Map.Entry<String, Yaml.Node>> pairs = urlEncoded(new String(data, charset).strip(), charset);
            if (pairs.isEmpty()) throw new DecodeException("no form fields");
            return Yaml.emit(merged(pairs));
        }
    }

    /** A request's query string, for requests without a body. */
    static final class Query implements ContentView {
        @Override
        public String name() {
            return "query";
        }

        @Override
        public double priority(byte[] data, Metadata metadata) {
            return data.length == 0 && metadata.request() && query(metadata) != null ? 0.3 : 0;
        }

        private static String query(Metadata metadata) {
            String path = metadata.path();
            int q = path == null ? -1 : path.indexOf('?');
            if (q < 0) return null;
            int hash = path.indexOf('#', q);
            String query = path.substring(q + 1, hash < 0 ? path.length() : hash);
            return query.isEmpty() ? null : query;
        }

        @Override
        public String render(byte[] data, Metadata metadata) throws DecodeException {
            String query = query(metadata);
            if (query == null) throw new DecodeException("no query string");
            return Yaml.emit(merged(urlEncoded(query, StandardCharsets.UTF_8)));
        }
    }

    /** {@code multipart/form-data} bodies: each field's value, and for files their name, type and size. */
    static final class Multipart implements ContentView {
        private static final int MAX_TEXT = 1 << 16;

        @Override
        public String name() {
            return "multipart";
        }

        @Override
        public double priority(byte[] data, Metadata metadata) {
            return data.length > 0 && metadata.mediaType().equals("multipart/form-data") ? 1 : 0;
        }

        @Override
        public String render(byte[] data, Metadata metadata) throws DecodeException {
            String boundary = metadata.parameter("boundary");
            if (boundary == null || boundary.isEmpty()) throw new DecodeException("multipart without a boundary");
            List<Map.Entry<String, Yaml.Node>> pairs = new ArrayList<>();
            for (Part part : parts(data, boundary)) {
                String disposition = part.header("content-disposition");
                String name = disposition == null ? null : param(disposition, "name");
                String filename = disposition == null ? null : param(disposition, "filename");
                String type = part.header("content-type");
                String text = part.body().length <= MAX_TEXT ? ProtoDecoder.text(part.body(), 0, part.body().length) : null;
                Yaml.Node value;
                if (filename == null && text != null) {
                    value = new Yaml.Scalar(Yaml.string(text));
                } else {
                    Yaml.Mapping file = new Yaml.Mapping();
                    if (filename != null) file.put("filename", new Yaml.Scalar(Yaml.string(filename)));
                    if (type != null) file.put("content-type", new Yaml.Scalar(Yaml.string(type)));
                    file.put("size", new Yaml.Scalar(String.valueOf(part.body().length)));
                    if (text != null && !text.isEmpty()) file.put("content", new Yaml.Scalar(Yaml.string(text)));
                    value = file;
                }
                pairs.add(Map.entry(name != null ? name : "", value));
            }
            if (pairs.isEmpty()) throw new DecodeException("multipart without parts");
            return Yaml.emit(merged(pairs));
        }

        /** One part: its header fields (names in lower case) and body. */
        record Part(Map<String, String> headers, byte[] body) {
            String header(String name) {
                return headers.get(name);
            }
        }

        /** Splits a body at {@code --boundary} lines; the preamble and epilogue are dropped. */
        static List<Part> parts(byte[] data, String boundary) throws DecodeException {
            byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
            List<Part> parts = new ArrayList<>();
            int at = indexOf(data, delimiter, 0);
            if (at < 0) throw new DecodeException("multipart without the boundary " + boundary);
            while (true) {
                int pos = at + delimiter.length;
                if (pos + 1 < data.length && data[pos] == '-' && data[pos + 1] == '-') break;
                pos = skipLine(data, pos);
                int next = indexOf(data, delimiter, pos);
                if (next < 0) throw new DecodeException("multipart part without a closing boundary");
                int end = next;
                if (end > pos && data[end - 1] == '\n') end--;
                if (end > pos && data[end - 1] == '\r') end--;
                parts.add(part(Arrays.copyOfRange(data, pos, end)));
                at = next;
            }
            return parts;
        }

        private static Part part(byte[] raw) {
            Map<String, String> headers = new LinkedHashMap<>();
            int pos = 0;
            while (pos < raw.length) {
                int eol = pos;
                while (eol < raw.length && raw[eol] != '\n') eol++;
                String line = new String(raw, pos, eol - pos, StandardCharsets.UTF_8).stripTrailing();
                pos = Math.min(raw.length, eol + 1);
                if (line.isEmpty()) {
                    return new Part(headers, Arrays.copyOfRange(raw, pos, raw.length));
                }
                int colon = line.indexOf(':');
                if (colon > 0) {
                    headers.put(line.substring(0, colon).strip().toLowerCase(Locale.ROOT), line.substring(colon + 1).strip());
                }
            }
            return new Part(headers, new byte[0]);
        }

        private static int skipLine(byte[] data, int pos) {
            while (pos < data.length && data[pos] != '\n') pos++;
            return Math.min(data.length, pos + 1);
        }

        private static int indexOf(byte[] data, byte[] needle, int from) {
            outer:
            for (int i = from; i <= data.length - needle.length; i++) {
                for (int j = 0; j < needle.length; j++) {
                    if (data[i + j] != needle[j]) continue outer;
                }
                return i;
            }
            return -1;
        }

        /** A parameter of a header value such as {@code form-data; name="a"; filename="b.txt"}. */
        static String param(String value, String name) {
            for (String part : value.split(";")) {
                int eq = part.indexOf('=');
                if (eq < 0 || !part.substring(0, eq).strip().equalsIgnoreCase(name)) continue;
                String v = part.substring(eq + 1).strip();
                if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length() - 1);
                return v;
            }
            return null;
        }
    }
}
