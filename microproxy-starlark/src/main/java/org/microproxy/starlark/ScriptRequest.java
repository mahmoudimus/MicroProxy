package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.util.Locale;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * A request as scripts see it. {@code method}, {@code uri}, {@code body} and {@code text} can be
 * assigned; {@code url}, {@code scheme}, {@code host}, {@code port}, {@code path} and {@code
 * query} are derived from the request target and the {@code Host} header. For {@code CONNECT},
 * {@code url} is the {@code host:port} authority and {@code scheme} is empty. {@code http_version}
 * is the HTTP version the client used: {@code "HTTP/1.1"}, {@code "HTTP/1.0"} or {@code "HTTP/2"}
 * (requests reach servers as HTTP/1.1 either way).
 */
@StarlarkBuiltin(name = "request", doc = "An HTTP request.")
public final class ScriptRequest extends ScriptMessage {

    private static final ImmutableList<String> FIELDS = ImmutableList.of(
            "method", "uri", "url", "scheme", "host", "port", "path", "query", "headers", "body", "text", "http_version");

    private final HttpRequest request;
    private final boolean secure;
    /** The version the client used, kept as it was: the proxy forwards HTTP/2 requests as HTTP/1.1. */
    private final String httpVersion;

    /**
     * @param secure whether an origin-form request arrived over TLS (an intercepted HTTPS request)
     */
    ScriptRequest(HttpRequest request, boolean secure, boolean readOnly) {
        super(request, readOnly);
        this.request = request;
        this.secure = secure;
        this.httpVersion = versionLabel(request.protocolVersion());
    }

    /** {@code HTTP/2} rather than {@code HTTP/2.0}, as HTTP/2 has no minor version. */
    static String versionLabel(org.microproxy.http.HttpVersion version) {
        return version.majorVersion() >= 2 && version.minorVersion() == 0
                ? "HTTP/" + version.majorVersion() : version.text();
    }

    HttpRequest request() {
        return request;
    }

    /**
     * Types the builtins that return this class (see {@link ScriptType}).
     *
     * @return the Starlark type constructor for a request value
     */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.REQUEST_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.REQUEST;
    }

    @Override
    public Object getValue(String name) throws EvalException {
        return switch (name) {
            case "method" -> request.method().name();
            case "uri" -> request.uri();
            case "url" -> target().url();
            case "scheme" -> target().scheme;
            case "host" -> target().host;
            case "port" -> StarlarkInt.of(target().port);
            case "path" -> target().path;
            case "query" -> target().query;
            case "headers" -> headers();
            case "body" -> body();
            case "text" -> text();
            case "http_version" -> httpVersion;
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public void setField(String field, Object value) throws EvalException {
        switch (field) {
            case "method" -> {
                checkWritable(field);
                try {
                    request.setMethod(HttpMethod.valueOf(string(field, value).toUpperCase(Locale.ROOT)));
                } catch (IllegalArgumentException e) {
                    throw Starlark.errorf("%s", e.getMessage());
                }
            }
            case "uri" -> {
                checkWritable(field);
                String uri = string(field, value);
                if (uri.isEmpty() || uri.chars().anyMatch(c -> c <= ' ' || c == 0x7f)) {
                    throw Starlark.errorf("invalid uri %s", uri);
                }
                request.setUri(uri);
            }
            case "body" -> setBody(value);
            case "text" -> setText(value);
            default -> throw Starlark.errorf(FIELDS.contains(field)
                    ? "request." + field + " is read-only; change uri or headers instead"
                    : getErrorMessageForUnknownField(field));
        }
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<request ").append(request.method().name()).append(' ').append(request.uri()).append('>');
    }

    private static String string(String field, Object value) throws EvalException {
        if (value instanceof String s) return s;
        throw Starlark.errorf("%s must be a string, not %s", field, Starlark.type(value));
    }

    private Target target() {
        String uri = request.uri();
        if (request.method().equals(HttpMethod.CONNECT)) {
            Target t = Target.authority("", uri, 443);
            t.path = "";
            return t;
        }
        int sep = uri.indexOf("://");
        if (sep > 0 && uri.indexOf('/') > sep) {
            String scheme = uri.substring(0, sep).toLowerCase(Locale.ROOT);
            int start = sep + 3;
            int end = start;
            while (end < uri.length() && uri.charAt(end) != '/' && uri.charAt(end) != '?' && uri.charAt(end) != '#') end++;
            Target t = Target.authority(scheme, uri.substring(start, end), scheme.equals("https") ? 443 : 80);
            t.pathAndQuery(end < uri.length() ? uri.substring(end) : "/");
            return t;
        }
        String scheme = secure ? "https" : "http";
        String host = request.headers().get(HttpHeaderNames.HOST);
        Target t = Target.authority(scheme, host == null ? "" : host, secure ? 443 : 80);
        t.pathAndQuery(uri);
        return t;
    }

    private static final class Target {
        String scheme;
        String authority;
        String host;
        int port;
        String path = "/";
        String query = "";

        static Target authority(String scheme, String authority, int defaultPort) {
            Target t = new Target();
            t.scheme = scheme;
            int at = authority.lastIndexOf('@');
            t.authority = at >= 0 ? authority.substring(at + 1) : authority;
            String hostPort = t.authority;
            int colon = hostPort.lastIndexOf(':');
            int bracket = hostPort.lastIndexOf(']');
            if (colon > bracket) {
                t.host = hostPort.substring(0, colon);
                try {
                    t.port = Integer.parseInt(hostPort.substring(colon + 1));
                } catch (NumberFormatException e) {
                    t.port = defaultPort;
                }
            } else {
                t.host = hostPort;
                t.port = defaultPort;
            }
            if (t.host.startsWith("[") && t.host.endsWith("]")) {
                t.host = t.host.substring(1, t.host.length() - 1);
            }
            t.host = t.host.toLowerCase(Locale.ROOT);
            return t;
        }

        void pathAndQuery(String s) {
            int hash = s.indexOf('#');
            if (hash >= 0) s = s.substring(0, hash);
            int q = s.indexOf('?');
            path = q >= 0 ? s.substring(0, q) : s;
            query = q >= 0 ? s.substring(q + 1) : "";
            if (path.isEmpty()) path = "/";
        }

        String url() {
            if (scheme.isEmpty()) return authority;
            return scheme + "://" + authority + path + (query.isEmpty() ? "" : "?" + query);
        }
    }
}
