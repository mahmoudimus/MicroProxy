package org.microproxy.http;

import java.util.Map;
import java.util.Objects;

/** An HTTP request method. Well-known methods are interned, so {@code ==} works for them. */
public final class HttpMethod {

    /** The {@code GET} request method. */
    public static final HttpMethod GET = new HttpMethod("GET");
    /** The {@code HEAD} request method. */
    public static final HttpMethod HEAD = new HttpMethod("HEAD");
    /** The {@code POST} request method. */
    public static final HttpMethod POST = new HttpMethod("POST");
    /** The {@code PUT} request method. */
    public static final HttpMethod PUT = new HttpMethod("PUT");
    /** The {@code DELETE} request method. */
    public static final HttpMethod DELETE = new HttpMethod("DELETE");
    /** The {@code CONNECT} request method. */
    public static final HttpMethod CONNECT = new HttpMethod("CONNECT");
    /** The {@code OPTIONS} request method. */
    public static final HttpMethod OPTIONS = new HttpMethod("OPTIONS");
    /** The {@code TRACE} request method. */
    public static final HttpMethod TRACE = new HttpMethod("TRACE");
    /** The {@code PATCH} request method. */
    public static final HttpMethod PATCH = new HttpMethod("PATCH");

    private static final Map<String, HttpMethod> KNOWN =
            Map.of(
                    "GET", GET, "HEAD", HEAD, "POST", POST, "PUT", PUT, "DELETE", DELETE,
                    "CONNECT", CONNECT, "OPTIONS", OPTIONS, "TRACE", TRACE, "PATCH", PATCH);

    private final String name;

    private HttpMethod(String name) {
        this.name = name;
    }

    /**
     * Returns the method with the given (case-sensitive) name.
     * @param name method token
     * @return the interned well-known method or a new extension method
     * @throws IllegalArgumentException if the name is not a valid HTTP token
     */
    public static HttpMethod valueOf(String name) {
        HttpMethod known = KNOWN.get(name);
        if (known != null) {
            return known;
        }
        if (!HttpHeaders.isToken(name)) {
            throw new IllegalArgumentException("invalid method: " + name);
        }
        return new HttpMethod(name);
    }

    /** {@return the case-sensitive method name} */
    public String name() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof HttpMethod m && m.name.equals(name));
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(name);
    }

    @Override
    public String toString() {
        return name;
    }
}
