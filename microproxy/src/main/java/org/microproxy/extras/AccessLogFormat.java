package org.microproxy.extras;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.FlowRecord;
import org.microproxy.FlowTimings;
import org.microproxy.ResponseFlag;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * An access-log line format, compatible with Envoy's access-log command operators: a format string
 * such as {@code [%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
 * %RESPONSE_CODE% %RESPONSE_FLAGS%}, or a JSON dictionary whose values are format strings. The
 * format is parsed once, into an array of pieces that each render one literal or one operator, so
 * rendering a {@link FlowRecord} needs no parsing and no regular expressions.
 *
 * <p>An operator whose value is not available (a missing header, no upstream, a tunnel's response
 * code details before it has any) renders {@code -}, as does an operator this class does not know.
 * {@code %OPERATOR(...):N%} truncates the value to {@code N} characters. In text formats, control
 * characters in values are escaped ({@code \n}, {@code \t}, {@code \u0001}), so a value cannot
 * break a line; {@code %%} is a literal {@code %}. In the JSON form, a value that is a single
 * operator keeps the operator's type: numbers for codes, sizes and durations, {@code true} or
 * {@code false} for flags, {@code null} when unavailable; other values are strings.
 *
 * <p>See the README's "Access logs (Envoy-compatible)" section for the operators.
 */
public final class AccessLogFormat {

    /** Envoy's default access-log format. */
    public static final String ENVOY_DEFAULT = "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
            + " %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION%"
            + " %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" \"%REQ(USER-AGENT)%\""
            + " \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n";

    /** How operator values are escaped in a text format. */
    enum Escape {
        /** Control characters escaped. */
        TEXT,
        /** As {@link #TEXT}, and spaces become {@code _}, for space-separated columns. */
        NO_SPACES,
        /** Every value a quoted RFC 4180 field. */
        CSV
    }

    private static final HexFormat HEX = HexFormat.of();
    private static final Strftime DEFAULT_TIME = Strftime.compile("%Y-%m-%dT%H:%M:%S.%3fZ");

    private final String source;
    private final Part[] parts;
    private final Node json;
    private final Escape escape;

    private AccessLogFormat(String source, Part[] parts, Node json, Escape escape) {
        this.source = source;
        this.parts = parts;
        this.json = json;
        this.escape = escape;
    }

    /**
     * Parses an Envoy format string. A trailing newline (Envoy's formats end with one) is dropped:
     * the logger writes each line on its own.
     *
     * @param format the format string
     * @return the format
     */
    public static AccessLogFormat envoy(String format) {
        return envoy(format, Escape.TEXT);
    }

    static AccessLogFormat envoy(String format, Escape escape) {
        Objects.requireNonNull(format);
        String text = format.endsWith("\n") ? format.substring(0, format.length() - 1) : format;
        return new AccessLogFormat(format, parse(text), null, escape);
    }

    /**
     * A JSON format: one JSON object per line, whose keys are those of {@code dictionary} (in its
     * iteration order) and whose values are rendered from its values: a format string, a nested
     * map, or a number, boolean or {@code null} written as it is.
     *
     * @param dictionary the keys and their format strings
     * @return the format
     */
    public static AccessLogFormat envoyJson(Map<String, ?> dictionary) {
        return new AccessLogFormat(String.valueOf(dictionary), null, node(dictionary), Escape.TEXT);
    }

    /**
     * {@link #envoyJson(Map)} from the JSON text of the dictionary, as the command line passes it:
     * {@code {"status":"%RESPONSE_CODE%","path":"%REQ(:PATH)%"}}.
     *
     * @param dictionary a JSON object
     * @return the format
     * @throws IllegalArgumentException if the text is not a JSON object
     */
    public static AccessLogFormat envoyJson(String dictionary) {
        Object parsed = Json.parse(dictionary.strip());
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("an access-log JSON format must be a JSON object: " + dictionary);
        }
        Map<String, Object> keys = new LinkedHashMap<>();
        map.forEach((k, v) -> keys.put(String.valueOf(k), v));
        return new AccessLogFormat(dictionary, null, node(keys), Escape.TEXT);
    }

    /** {@return whether this is a JSON format} */
    public boolean isJson() {
        return json != null;
    }

    /**
     * Renders one line for {@code record}.
     *
     * @param record the finished exchange or flow
     * @return the line, without a line terminator
     */
    public String format(FlowRecord record) {
        StringBuilder sb = new StringBuilder(256);
        formatTo(record, sb);
        return sb.toString();
    }

    /**
     * Appends one line for {@code record} to {@code out}.
     *
     * @param record the finished exchange or flow
     * @param out where the line goes
     */
    public void formatTo(FlowRecord record, StringBuilder out) {
        if (json != null) {
            json.render(record, out);
            return;
        }
        for (Part part : parts) {
            if (part instanceof Literal literal) {
                out.append(literal.text);
            } else {
                Operation op = (Operation) part;
                int start = out.length();
                if (!op.operator.append(record, out)) {
                    out.setLength(start);
                    out.append('-');
                } else {
                    op.truncate(out, start);
                }
                escape(out, start, escape);
            }
        }
    }

    @Override
    public String toString() {
        return source;
    }

    // ---------------------------------------------------------------------------------------
    // Parsing
    // ---------------------------------------------------------------------------------------

    /** A piece of a text format. */
    private sealed interface Part permits Literal, Operation {}

    private record Literal(String text) implements Part {}

    /** An operator with its truncation ({@code :N}), or -1. */
    private record Operation(Operator operator, int maxLength) implements Part {
        void truncate(StringBuilder out, int start) {
            if (maxLength >= 0 && out.length() - start > maxLength) out.setLength(start + maxLength);
        }
    }

    private static Part[] parse(String format) {
        List<Part> parts = new ArrayList<>();
        StringBuilder literal = new StringBuilder();
        int i = 0;
        while (i < format.length()) {
            char c = format.charAt(i);
            if (c != '%') {
                literal.append(c);
                i++;
                continue;
            }
            if (i + 1 < format.length() && format.charAt(i + 1) == '%') {
                literal.append('%');
                i += 2;
                continue;
            }
            int end = operatorEnd(format, i);
            if (end < 0) {
                literal.append(c);
                i++;
                continue;
            }
            if (!literal.isEmpty()) {
                parts.add(new Literal(literal.toString()));
                literal.setLength(0);
            }
            parts.add(operation(format.substring(i + 1, end)));
            i = end + 1;
        }
        if (!literal.isEmpty()) parts.add(new Literal(literal.toString()));
        return parts.toArray(Part[]::new);
    }

    /**
     * Where the operator starting with the {@code %} at {@code start} ends (its closing {@code
     * %}), or -1 if none starts there: {@code NAME}, then optionally {@code (args)} (which may
     * hold {@code %}, as times do) and {@code :N}.
     */
    private static int operatorEnd(String format, int start) {
        int i = start + 1;
        while (i < format.length() && (Character.isUpperCase(format.charAt(i)) || Character.isDigit(format.charAt(i))
                || format.charAt(i) == '_')) {
            i++;
        }
        if (i == start + 1) return -1;
        if (i < format.length() && format.charAt(i) == '(') {
            int close = format.indexOf(')', i);
            if (close < 0) return -1;
            i = close + 1;
        }
        if (i < format.length() && format.charAt(i) == ':') {
            int digits = i + 1;
            while (digits < format.length() && Character.isDigit(format.charAt(digits))) digits++;
            if (digits == i + 1) return -1;
            i = digits;
        }
        return i < format.length() && format.charAt(i) == '%' ? i : -1;
    }

    /** {@code text} is what is between the {@code %}s: {@code NAME}, {@code NAME(args)}, with {@code :N} or not. */
    private static Operation operation(String text) {
        int maxLength = -1;
        int close = text.lastIndexOf(')');
        int colon = text.indexOf(':', close < 0 ? 0 : close);
        String head = text;
        if (colon >= 0) {
            maxLength = Integer.parseInt(text.substring(colon + 1));
            head = text.substring(0, colon);
        }
        String name = head;
        String arg = null;
        int open = head.indexOf('(');
        if (open >= 0) {
            name = head.substring(0, open);
            arg = head.substring(open + 1, head.length() - 1);
        }
        return new Operation(Operators.of(name, arg), maxLength);
    }

    // ---------------------------------------------------------------------------------------
    // Escaping
    // ---------------------------------------------------------------------------------------

    private static void escape(StringBuilder out, int start, Escape escape) {
        if (escape == Escape.CSV) {
            out.insert(start, '"');
            for (int i = start + 1; i < out.length(); i++) {
                if (out.charAt(i) == '"') out.insert(i++, '"');
            }
            out.append('"');
            return;
        }
        int i = start;
        while (i < out.length() && !needsEscape(out.charAt(i), escape)) i++;
        if (i == out.length()) return;
        String tail = out.substring(i);
        out.setLength(i);
        for (int j = 0; j < tail.length(); j++) {
            char c = tail.charAt(j);
            if (c == ' ' && escape == Escape.NO_SPACES) {
                out.append('_');
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '\r') {
                out.append("\\r");
            } else if (c == '\t') {
                out.append("\\t");
            } else if (c < 0x20 || c == 0x7f) {
                out.append("\\u00").append(HEX.toHexDigits((byte) c));
            } else {
                out.append(c);
            }
        }
    }

    private static boolean needsEscape(char c, Escape escape) {
        return c < 0x20 || c == 0x7f || (c == ' ' && escape == Escape.NO_SPACES);
    }

    /** Escapes what was appended from {@code start} on as the inside of a JSON string. */
    private static void jsonEscape(StringBuilder out, int start) {
        int i = start;
        while (i < out.length()) {
            char c = out.charAt(i);
            if (c == '"' || c == '\\' || c < 0x20 || c == 0x7f) break;
            i++;
        }
        if (i == out.length()) return;
        String tail = out.substring(i);
        out.setLength(i);
        out.append(Json.escape(tail));
    }

    // ---------------------------------------------------------------------------------------
    // The JSON form
    // ---------------------------------------------------------------------------------------

    /** A value of the JSON form. */
    private sealed interface Node permits ObjectNode, TemplateNode, RawNode {
        void render(FlowRecord record, StringBuilder out);
    }

    private record ObjectNode(String[] keys, Node[] values) implements Node {
        @Override
        public void render(FlowRecord record, StringBuilder out) {
            out.append('{');
            for (int i = 0; i < keys.length; i++) {
                if (i > 0) out.append(',');
                out.append(keys[i]).append(':');
                values[i].render(record, out);
            }
            out.append('}');
        }
    }

    /** A literal number, boolean or null, written as it is. */
    private record RawNode(String json) implements Node {
        @Override
        public void render(FlowRecord record, StringBuilder out) {
            out.append(json);
        }
    }

    /** A format string: typed when it is a single operator, else a string. */
    private record TemplateNode(Part[] parts) implements Node {
        @Override
        public void render(FlowRecord record, StringBuilder out) {
            if (parts.length == 1 && parts[0] instanceof Operation op) {
                int start = out.length();
                Type type = op.operator.type();
                if (type != Type.STRING) {
                    if (!op.operator.append(record, out)) {
                        out.setLength(start);
                        out.append("null");
                    }
                    return;
                }
                out.append('"');
                if (!op.operator.append(record, out)) {
                    out.setLength(start);
                    out.append("null");
                    return;
                }
                op.truncate(out, start + 1);
                jsonEscape(out, start + 1);
                out.append('"');
                return;
            }
            out.append('"');
            for (Part part : parts) {
                int start = out.length();
                if (part instanceof Literal literal) {
                    out.append(literal.text);
                } else {
                    Operation op = (Operation) part;
                    if (!op.operator.append(record, out)) {
                        out.setLength(start);
                        out.append('-');
                    } else {
                        op.truncate(out, start);
                    }
                }
                jsonEscape(out, start);
            }
            out.append('"');
        }
    }

    private static Node node(Object value) {
        if (value instanceof Map<?, ?> map) {
            String[] keys = new String[map.size()];
            Node[] values = new Node[map.size()];
            int i = 0;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                keys[i] = "\"" + Json.escape(String.valueOf(e.getKey())) + "\"";
                values[i++] = node(e.getValue());
            }
            return new ObjectNode(keys, values);
        }
        if (value instanceof String s) return new TemplateNode(parse(s));
        if (value == null) return new RawNode("null");
        if (value instanceof Number || value instanceof Boolean) return new RawNode(String.valueOf(value));
        throw new IllegalArgumentException("an access-log JSON value must be a format string, a map, a number, a"
                + " boolean or null, not " + value.getClass().getSimpleName());
    }

    // ---------------------------------------------------------------------------------------
    // Operators
    // ---------------------------------------------------------------------------------------

    /** How the JSON form writes an operator's value. */
    enum Type {
        STRING,
        NUMBER,
        BOOLEAN
    }

    /** Renders one operator's value. */
    abstract static class Operator {
        private final Type type;

        Operator(Type type) {
            this.type = type;
        }

        Type type() {
            return type;
        }

        /**
         * Appends the value; returns false when it is not available (anything appended is then
         * discarded).
         */
        abstract boolean append(FlowRecord record, StringBuilder out);
    }

    /** A string-valued operator. */
    @FunctionalInterface
    interface TextValue {
        /** The value, or null when unavailable. */
        String get(FlowRecord record);
    }

    /** A number-valued operator. */
    @FunctionalInterface
    interface NumberValue {
        /** The value, or a negative number when unavailable. */
        long get(FlowRecord record);
    }

    static Operator text(TextValue value) {
        return new Operator(Type.STRING) {
            @Override
            boolean append(FlowRecord record, StringBuilder out) {
                String v = value.get(record);
                if (v == null) return false;
                out.append(v);
                return true;
            }
        };
    }

    static Operator number(NumberValue value) {
        return new Operator(Type.NUMBER) {
            @Override
            boolean append(FlowRecord record, StringBuilder out) {
                long v = value.get(record);
                if (v < 0) return false;
                out.append(v);
                return true;
            }
        };
    }

    static Operator bool(java.util.function.Predicate<FlowRecord> value) {
        return new Operator(Type.BOOLEAN) {
            @Override
            boolean append(FlowRecord record, StringBuilder out) {
                out.append(value.test(record));
                return true;
            }
        };
    }

    /** Never available: an operator this class does not know, or with arguments it cannot use. */
    static final Operator UNKNOWN = new Operator(Type.STRING) {
        @Override
        boolean append(FlowRecord record, StringBuilder out) {
            return false;
        }
    };

    /** The operators, by name. */
    static final class Operators {

        private Operators() {}

        static Operator of(String name, String arg) {
            return switch (name) {
                case "START_TIME" -> startTime(arg);
                case "REQ", "REQUEST_HEADER" -> header(arg, Operators::requestHeader);
                case "RESP", "RESPONSE_HEADER" -> header(arg, Operators::responseHeader);
                case "TRAILER", "RESPONSE_TRAILER" -> header(arg, (r, h) -> r.trailers() == null ? null : r.trailers().get(h));
                case "PROTOCOL" -> text(Operators::protocol);
                case "RESPONSE_CODE" -> number(FlowRecord::responseCode);
                case "RESPONSE_CODE_DETAILS" -> text(FlowRecord::responseCodeDetails);
                case "RESPONSE_FLAGS" -> new Operator(Type.STRING) {
                    @Override
                    boolean append(FlowRecord record, StringBuilder out) {
                        out.append(ResponseFlag.render(record.responseFlags(), false));
                        return true;
                    }
                };
                case "RESPONSE_FLAGS_LONG" -> new Operator(Type.STRING) {
                    @Override
                    boolean append(FlowRecord record, StringBuilder out) {
                        out.append(ResponseFlag.render(record.responseFlags(), true));
                        return true;
                    }
                };
                case "DURATION" -> number(r -> millis(r.durationNanos()));
                case "REQUEST_DURATION" -> number(r -> millis(r.timings().requestSentNanos()));
                case "RESPONSE_DURATION" -> number(r -> millis(r.timings().firstResponseByteNanos()));
                case "RESPONSE_TX_DURATION" -> number(r -> {
                    FlowTimings t = r.timings();
                    return t.firstResponseByteNanos() < 0 || t.responseCompleteNanos() < t.firstResponseByteNanos() ? -1
                            : millis(t.responseCompleteNanos() - t.firstResponseByteNanos());
                });
                case "COMMON_DURATION" -> commonDuration(arg);
                case "DOWNSTREAM_HANDSHAKE_DURATION" -> number(r -> millis(r.timings().clientTlsHandshakeNanos()));
                case "BYTES_RECEIVED" -> number(FlowRecord::bytesReceived);
                case "BYTES_SENT" -> number(FlowRecord::bytesSent);
                case "UPSTREAM_WIRE_BYTES_SENT" -> number(FlowRecord::upstreamBytesSent);
                case "UPSTREAM_WIRE_BYTES_RECEIVED" -> number(FlowRecord::upstreamBytesReceived);
                case "UPSTREAM_HOST", "UPSTREAM_REMOTE_ADDRESS" -> text(r -> address(r.upstreamAddress(), true));
                case "UPSTREAM_REMOTE_ADDRESS_WITHOUT_PORT" -> text(r -> address(r.upstreamAddress(), false));
                case "UPSTREAM_CLUSTER" -> text(FlowRecord::upstreamCluster);
                case "UPSTREAM_LOCAL_ADDRESS" -> text(r -> address(r.upstreamLocalAddress(), true));
                case "UPSTREAM_LOCAL_ADDRESS_WITHOUT_PORT" -> text(r -> address(r.upstreamLocalAddress(), false));
                case "UPSTREAM_TRANSPORT_FAILURE_REASON" -> text(FlowRecord::upstreamTransportFailureReason);
                case "UPSTREAM_TLS_VERSION" -> text(r -> r.upstreamSslSession() == null ? null
                        : r.upstreamSslSession().getProtocol());
                case "UPSTREAM_TLS_CIPHER" -> text(r -> r.upstreamSslSession() == null ? null
                        : r.upstreamSslSession().getCipherSuite());
                case "UPSTREAM_PEER_SUBJECT" -> text(r -> peer(r.upstreamSslSession(), false));
                case "UPSTREAM_PEER_ISSUER" -> text(r -> peer(r.upstreamSslSession(), true));
                case "DOWNSTREAM_REMOTE_ADDRESS", "DOWNSTREAM_DIRECT_REMOTE_ADDRESS" ->
                        text(r -> address(r.context().getClientAddress(), true));
                case "DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT", "DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT" ->
                        text(r -> address(r.context().getClientAddress(), false));
                case "DOWNSTREAM_REMOTE_PORT" -> number(r -> r.context().getClientAddress() == null ? -1
                        : r.context().getClientAddress().getPort());
                case "DOWNSTREAM_LOCAL_ADDRESS" -> text(r -> address(r.downstreamLocalAddress(), true));
                case "DOWNSTREAM_LOCAL_ADDRESS_WITHOUT_PORT" -> text(r -> address(r.downstreamLocalAddress(), false));
                case "DOWNSTREAM_LOCAL_PORT" -> number(r -> r.downstreamLocalAddress() == null ? -1
                        : r.downstreamLocalAddress().getPort());
                case "DOWNSTREAM_TLS_VERSION" -> text(r -> clientSession(r) == null ? null : clientSession(r).getProtocol());
                case "DOWNSTREAM_TLS_CIPHER" -> text(r -> clientSession(r) == null ? null
                        : clientSession(r).getCipherSuite());
                case "DOWNSTREAM_PEER_SUBJECT" -> text(r -> peer(clientSession(r), false));
                case "DOWNSTREAM_PEER_ISSUER" -> text(r -> peer(clientSession(r), true));
                case "DOWNSTREAM_PEER_FINGERPRINT_256" -> text(r -> fingerprint(clientSession(r)));
                case "REQUESTED_SERVER_NAME" -> text(Operators::serverName);
                case "CONNECTION_ID" -> number(r -> r.context().getConnectionId());
                case "STREAM_ID" -> number(r -> r.context().getStreamId());
                case "UNIQUE_ID" -> text(FlowRecord::uniqueId);
                case "HOSTNAME" -> text(r -> Hostname.NAME);
                case "TLS_JA3_FINGERPRINT" -> text(r -> r.context().getClientHello() == null ? null
                        : TlsFingerprints.ja3(r.context().getClientHello()));
                case "TLS_JA4_FINGERPRINT" -> text(r -> r.context().getClientHello() == null ? null
                        : TlsFingerprints.ja4(r.context().getClientHello(), r.context().isTransparentQuic()));
                case "MP_RESPONSE_SOURCE" -> text(r -> r.source() == null ? null : r.source().name());
                case "MP_EARLY_DATA" -> bool(r -> r.context().isEarlyData());
                case "MP_TRANSPARENT_QUIC" -> bool(r -> r.context().isTransparentQuic());
                case "MP_SOCKS_VERSION" -> number(r -> r.context().socksVersion().orElse(-1));
                case "MP_FORWARDED_VIA" -> text(r -> r.context().forwardedVia().orElse(null));
                case "MP_FLOW" -> text(r -> r.kind().label());
                case "MP_USER" -> text(r -> r.context().getClientDetails().getUserName());
                case "MP_URL" -> text(Operators::url);
                case "MP_UPSTREAM_STATUS" -> number(r -> r.context().upstreamStatus().orElse(-1));
                case "MP_TIMING" -> timing(arg);
                default -> UNKNOWN;
            };
        }

        /** Whole milliseconds of {@code nanos}, or -1 for a negative (unknown) value. */
        private static long millis(long nanos) {
            return nanos < 0 ? -1 : nanos / 1_000_000;
        }

        private static Operator startTime(String arg) {
            Strftime time = arg == null || arg.isEmpty() ? DEFAULT_TIME : Strftime.compile(arg);
            return new Operator(Type.STRING) {
                @Override
                boolean append(FlowRecord record, StringBuilder out) {
                    if (record.startEpochMillis() == 0) return false;
                    time.format(record.startEpochMillis(), out);
                    return true;
                }
            };
        }

        /** A header operator: {@code NAME} or {@code NAME?ALTERNATIVE}. */
        private static Operator header(String arg, java.util.function.BiFunction<FlowRecord, String, String> lookup) {
            if (arg == null || arg.isEmpty()) return UNKNOWN;
            int q = arg.indexOf('?');
            String first = (q < 0 ? arg : arg.substring(0, q)).strip().toLowerCase(Locale.ROOT);
            String second = q < 0 ? null : arg.substring(q + 1).strip().toLowerCase(Locale.ROOT);
            return text(r -> {
                String v = lookup.apply(r, first);
                return v != null || second == null ? v : lookup.apply(r, second);
            });
        }

        private static String requestHeader(FlowRecord record, String name) {
            HttpRequest request = record.request();
            if (request == null) return null;
            if (name.isEmpty() || name.charAt(0) != ':') return request.headers().get(name);
            String uri = request.uri();
            return switch (name) {
                case ":method" -> request.method().name();
                case ":path" -> HttpMethod.CONNECT.equals(request.method()) ? null : path(uri);
                case ":authority" -> {
                    if (HttpMethod.CONNECT.equals(request.method())) yield uri;
                    String host = request.headers().get(HttpHeaderNames.HOST);
                    yield host != null ? host : authority(uri);
                }
                case ":scheme" -> {
                    int colon = uri.indexOf("://");
                    if (colon > 0) yield uri.substring(0, colon).toLowerCase(Locale.ROOT);
                    if (HttpMethod.CONNECT.equals(request.method())) yield null;
                    yield record.context().getClientSslSession() != null ? "https" : "http";
                }
                case ":protocol" -> request.headers().get(HttpHeaderNames.UPGRADE);
                default -> null;
            };
        }

        private static String responseHeader(FlowRecord record, String name) {
            HttpResponse response = record.response();
            if (response == null) return null;
            if (":status".equals(name)) return Integer.toString(response.status().code());
            return response.headers().get(name);
        }

        /** The path and query of a request-target: as it is in origin-form, without scheme and authority in absolute-form. */
        static String path(String uri) {
            int scheme = uri.indexOf("://");
            if (scheme < 0 || uri.startsWith("/")) return uri;
            int slash = uri.indexOf('/', scheme + 3);
            int query = uri.indexOf('?', scheme + 3);
            if (slash < 0 && query < 0) return "/";
            if (slash < 0 || (query >= 0 && query < slash)) return "/" + uri.substring(query);
            return uri.substring(slash);
        }

        private static String authority(String uri) {
            int scheme = uri.indexOf("://");
            if (scheme < 0) return null;
            int end = scheme + 3;
            while (end < uri.length() && "/?#".indexOf(uri.charAt(end)) < 0) end++;
            return uri.substring(scheme + 3, end);
        }

        private static String protocol(FlowRecord record) {
            FlowRecord.Kind kind = record.kind();
            if (kind == FlowRecord.Kind.QUIC || kind == FlowRecord.Kind.QUIC_RELAY) return null;
            FlowContext context = record.context();
            int major = context.getHttpVersion().majorVersion();
            if (major >= 2) return "HTTP/" + major;
            HttpRequest request = record.request();
            return request == null ? "HTTP/1.1" : request.protocolVersion().text();
        }

        /**
         * The absolute URL of the request: as received for absolute-form and {@code CONNECT}
         * requests, otherwise rebuilt from the {@code Host} field ({@code https} inside a TLS session).
         */
        static String url(FlowRecord record) {
            HttpRequest request = record.request();
            if (request == null) return null;
            String uri = request.uri();
            if (uri.regionMatches(true, 0, "http://", 0, 7) || uri.regionMatches(true, 0, "https://", 0, 8)
                    || HttpMethod.CONNECT.equals(request.method())) {
                return uri;
            }
            String host = request.headers().get(HttpHeaderNames.HOST);
            if (host == null || host.isEmpty()) return uri;
            String scheme = record.context().getClientSslSession() != null
                    || record.kind() == FlowRecord.Kind.HTTP3 ? "https" : "http";
            return scheme + "://" + host + (uri.startsWith("/") ? uri : "/" + uri);
        }

        static String address(InetSocketAddress address, boolean withPort) {
            if (address == null) return null;
            String host = address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
            if (!withPort) return host;
            return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + address.getPort();
        }

        private static SSLSession clientSession(FlowRecord record) {
            return record.context().getClientSslSession();
        }

        private static X509Certificate peerCertificate(SSLSession session) {
            if (session == null) return null;
            try {
                Certificate[] chain = session.getPeerCertificates();
                return chain.length > 0 && chain[0] instanceof X509Certificate x509 ? x509 : null;
            } catch (SSLPeerUnverifiedException e) {
                return null;
            }
        }

        private static String peer(SSLSession session, boolean issuer) {
            X509Certificate cert = peerCertificate(session);
            if (cert == null) return null;
            return (issuer ? cert.getIssuerX500Principal() : cert.getSubjectX500Principal()).getName();
        }

        private static String fingerprint(SSLSession session) {
            X509Certificate cert = peerCertificate(session);
            if (cert == null) return null;
            try {
                return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
                return null;
            }
        }

        private static String serverName(FlowRecord record) {
            ClientHello hello = record.context().getClientHello();
            if (hello != null && hello.sni() != null) return hello.sni();
            if (record.context().getClientSslSession() instanceof ExtendedSSLSession session) {
                for (SNIServerName name : session.getRequestedServerNames()) {
                    if (name instanceof SNIHostName host) return host.getAsciiName();
                }
            }
            return null;
        }

        /** {@code %COMMON_DURATION(START:END:PRECISION)%}, between two of the points the proxy records. */
        private static Operator commonDuration(String arg) {
            if (arg == null) return UNKNOWN;
            String[] p = arg.split(":", -1);
            if (p.length != 3) return UNKNOWN;
            Point start = Point.of(p[0].strip());
            Point end = Point.of(p[1].strip());
            long divisor = switch (p[2].strip()) {
                case "ms" -> 1_000_000;
                case "us" -> 1_000;
                case "ns" -> 1;
                default -> 0;
            };
            if (start == null || end == null || divisor == 0) return UNKNOWN;
            return number(r -> {
                long a = start.offset(r);
                long b = end.offset(r);
                return a < 0 || b < a ? -1 : (b - a) / divisor;
            });
        }

        /** A time point of {@code COMMON_DURATION}, as an offset in nanoseconds from the start. */
        private enum Point {
            START, DS_RX_END, US_CX_BEG, US_CX_END, US_HS_END, US_TX_END, US_RX_BEG, US_RX_END, DS_TX_END;

            static Point of(String name) {
                return switch (name) {
                    case "START_TIME", "DS_RX_BEG" -> START;
                    case "DS_RX_END" -> DS_RX_END;
                    case "US_CX_BEG" -> US_CX_BEG;
                    case "US_CX_END" -> US_CX_END;
                    case "US_HS_END" -> US_HS_END;
                    case "US_TX_END" -> US_TX_END;
                    case "US_RX_BEG" -> US_RX_BEG;
                    case "US_RX_END" -> US_RX_END;
                    case "DS_TX_END" -> DS_TX_END;
                    default -> null;
                };
            }

            long offset(FlowRecord r) {
                FlowTimings t = r.timings();
                return switch (this) {
                    case START -> 0;
                    case DS_RX_END, US_TX_END -> t.requestSentNanos();
                    case US_CX_BEG -> t.connectStartNanos();
                    case US_CX_END -> t.connectEndNanos();
                    case US_HS_END -> t.tlsEndNanos();
                    case US_RX_BEG -> t.firstResponseByteNanos();
                    case US_RX_END -> r.source() == org.microproxy.ResponseSource.SERVER ? t.responseCompleteNanos() : -1;
                    case DS_TX_END -> r.durationNanos();
                };
            }
        }

        /**
         * {@code %MP_TIMING(phase)%}: a phase of {@link FlowTimings} in milliseconds with three
         * decimals: {@code dns}, {@code connect}, {@code tls}, {@code client_tls}, {@code ttfb} or
         * {@code total}.
         */
        private static Operator timing(String arg) {
            if (arg == null) return UNKNOWN;
            NumberValue nanos = switch (arg.strip()) {
                case "dns" -> r -> between(r.timings().dnsStartNanos(), r.timings().dnsEndNanos());
                case "connect" -> r -> between(r.timings().connectStartNanos(), r.timings().connectEndNanos());
                case "tls" -> r -> between(r.timings().tlsStartNanos(), r.timings().tlsEndNanos());
                case "client_tls" -> r -> r.timings().clientTlsHandshakeNanos();
                case "ttfb" -> r -> r.timings().firstResponseByteNanos();
                case "total" -> r -> r.timings().responseCompleteNanos();
                default -> null;
            };
            if (nanos == null) return UNKNOWN;
            return new Operator(Type.NUMBER) {
                @Override
                boolean append(FlowRecord record, StringBuilder out) {
                    long n = nanos.get(record);
                    if (n < 0) return false;
                    long micros = n / 1000;
                    out.append(micros / 1000).append('.');
                    long fraction = micros % 1000;
                    if (fraction < 100) out.append('0');
                    if (fraction < 10) out.append('0');
                    out.append(fraction);
                    return true;
                }
            };
        }

        private static long between(long start, long end) {
            return start < 0 || end < start ? -1 : end - start;
        }
    }

    /** This host's name, looked up once. */
    private static final class Hostname {
        static final String NAME = lookup();

        private static String lookup() {
            try {
                return InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                String env = System.getenv("HOSTNAME");
                return env != null ? env : "localhost";
            }
        }
    }

    /** Reads the request headers of a record: for tests and for filters in this package. */
    static String requestHeader(FlowRecord record, String name) {
        return Operators.requestHeader(record, name.toLowerCase(Locale.ROOT));
    }
}
