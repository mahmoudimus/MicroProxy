package io.github.mahmoudimus.http3;

import java.util.List;
import java.util.Objects;

/**
 * A validated HTTP/3 request header section: the control data from the pseudo-header fields and
 * the remaining fields, as {@link Http3Headers#toRequest} produces it.
 *
 * @param method {@code :method}
 * @param scheme {@code :scheme}, or null for CONNECT
 * @param authority {@code :authority}, or the {@code host} field when that is absent; null if
 *     neither is present
 * @param path {@code :path}, or null for CONNECT
 * @param protocol {@code :protocol} of an extended CONNECT (RFC 9220), such as {@code websocket}
 *     or {@code connect-udp}; null otherwise
 * @param fields the regular fields in order (lower-case names; cookie crumbs joined into one field)
 * @param contentLength the {@code content-length}, or -1 if absent
 */
public record RequestHeaders(
        String method, String scheme, String authority, String path, String protocol, List<HeaderField> fields, long contentLength) {

    public RequestHeaders {
        Objects.requireNonNull(method, "method");
        fields = List.copyOf(fields);
    }

    /** A CONNECT request, plain or extended. */
    public boolean isConnect() {
        return method.equals("CONNECT");
    }

    /** An extended CONNECT request: CONNECT with {@code :protocol}. */
    public boolean isExtendedConnect() {
        return protocol != null;
    }

    /** The value of the first field with this (lower-case) name, or null. */
    public String get(String name) {
        return Http3Headers.first(fields, name);
    }

    /** The values of every field with this (lower-case) name. */
    public List<String> getAll(String name) {
        return Http3Headers.all(fields, name);
    }
}
