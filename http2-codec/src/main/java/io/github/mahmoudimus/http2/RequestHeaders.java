package io.github.mahmoudimus.http2;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A validated HTTP/2 request header section: the control data from the pseudo-header fields and
 * the remaining fields, as {@link Http2Headers#toRequest} produces it.
 *
 * @param method {@code :method}
 * @param scheme {@code :scheme}, or null for ordinary CONNECT
 * @param authority {@code :authority}, or the {@code host} field when that is absent; null if
 *     neither is present
 * @param path {@code :path}, or null for ordinary CONNECT
 * @param fields the regular fields in order (lower-case names; cookie crumbs joined into one field)
 * @param contentLength the {@code content-length}, or -1 if absent
 * @param protocol RFC 8441 {@code :protocol}, or null without extended CONNECT
 */
public record RequestHeaders(String method, String scheme, String authority, String path, List<HeaderField> fields,
        long contentLength, String protocol) {

    /**
     * Creates request headers without extended CONNECT metadata.
     *
     * @param method the non-null request method
     * @param scheme the URI scheme, or null for ordinary CONNECT
     * @param authority the target authority, or null if unavailable
     * @param path the request path, or null for ordinary CONNECT
     * @param fields the regular fields in order, copied into an immutable list
     * @param contentLength the declared content length, or -1 if absent
     */
    public RequestHeaders(String method, String scheme, String authority, String path, List<HeaderField> fields,
            long contentLength) {
        this(method, scheme, authority, path, fields, contentLength, null);
    }

    /**
     * Creates request headers and takes an immutable copy of the regular fields.
     *
     * @param method the non-null request method
     * @param scheme the URI scheme, or null for ordinary CONNECT
     * @param authority the target authority, or null if unavailable
     * @param path the request path, or null for ordinary CONNECT
     * @param fields the regular fields in order, copied into an immutable list
     * @param contentLength the declared content length, or -1 if absent
     * @param protocol the extended CONNECT protocol, or null if absent
     */
    public RequestHeaders {
        Objects.requireNonNull(method, "method");
        fields = List.copyOf(fields);
    }

    /**
     * Checks the request method.
     *
     * @return whether the method is CONNECT
     */
    public boolean isConnect() {
        return method.equals("CONNECT");
    }

    /**
     * The value of the first field with this (lower-case) name, or null.
     *
     * @param name the lower-case field name
     * @return the first matching value, or null if absent
     */
    public String get(String name) {
        return Http2Headers.first(fields, name);
    }

    /**
     * The values of every field with this (lower-case) name.
     *
     * @param name the lower-case field name
     * @return the matching values in field order, or an empty list
     */
    public List<String> getAll(String name) {
        List<String> values = new ArrayList<>();
        for (HeaderField f : fields) {
            if (f.name().equals(name)) values.add(f.value());
        }
        return values;
    }
}
