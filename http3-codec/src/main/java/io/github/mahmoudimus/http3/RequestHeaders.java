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

    /**
     * Creates a request header section.
     *
     * @param method {@code :method}
     * @param scheme {@code :scheme}, or null
     * @param authority {@code :authority} (or {@code host}), or null
     * @param path {@code :path}, or null
     * @param protocol {@code :protocol}, or null
     * @param fields the regular fields, copied
     * @param contentLength the {@code content-length}, or -1
     */
    public RequestHeaders {
        Objects.requireNonNull(method, "method");
        fields = List.copyOf(fields);
    }

    /**
     * A CONNECT request, plain or extended.
     *
     * @return whether the method is CONNECT
     */
    public boolean isConnect() {
        return method.equals("CONNECT");
    }

    /**
     * An extended CONNECT request: CONNECT with {@code :protocol}.
     *
     * @return whether {@code :protocol} is present
     */
    public boolean isExtendedConnect() {
        return protocol != null;
    }

    /**
     * The value of the first field with this (lower-case) name, or null.
     *
     * @param name the field name
     * @return the value, or null
     */
    public String get(String name) {
        return Http3Headers.first(fields, name);
    }

    /**
     * The values of every field with this (lower-case) name.
     *
     * @param name the field name
     * @return the values, possibly none
     */
    public List<String> getAll(String name) {
        return Http3Headers.all(fields, name);
    }
}
