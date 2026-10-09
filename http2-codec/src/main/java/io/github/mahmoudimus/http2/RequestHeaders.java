package io.github.mahmoudimus.http2;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A validated HTTP/2 request header section: the control data from the pseudo-header fields and
 * the remaining fields, as {@link Http2Headers#toRequest} produces it.
 *
 * @param method {@code :method}
 * @param scheme {@code :scheme}, or null for CONNECT
 * @param authority {@code :authority}, or the {@code host} field when that is absent; null if
 *     neither is present
 * @param path {@code :path}, or null for CONNECT
 * @param fields the regular fields in order (lower-case names; cookie crumbs joined into one field)
 * @param contentLength the {@code content-length}, or -1 if absent
 */
public record RequestHeaders(String method, String scheme, String authority, String path, List<HeaderField> fields, long contentLength) {

    public RequestHeaders {
        Objects.requireNonNull(method, "method");
        fields = List.copyOf(fields);
    }

    public boolean isConnect() {
        return method.equals("CONNECT");
    }

    /** The value of the first field with this (lower-case) name, or null. */
    public String get(String name) {
        return Http2Headers.first(fields, name);
    }

    /** The values of every field with this (lower-case) name. */
    public List<String> getAll(String name) {
        List<String> values = new ArrayList<>();
        for (HeaderField f : fields) {
            if (f.name().equals(name)) values.add(f.value());
        }
        return values;
    }
}
