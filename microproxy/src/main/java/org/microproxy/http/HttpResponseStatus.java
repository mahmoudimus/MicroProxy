package org.microproxy.http;

/**
 * An HTTP status code and reason phrase. Equality considers only the code, so a response from a
 * server with a non-standard reason phrase still equals the corresponding constant.
 */
// @value-candidate: becomes a value class in the valhalla build profile
public record HttpResponseStatus(int code, String reasonPhrase) {

    public static final HttpResponseStatus CONTINUE = new HttpResponseStatus(100, "Continue");
    public static final HttpResponseStatus SWITCHING_PROTOCOLS =
            new HttpResponseStatus(101, "Switching Protocols");
    public static final HttpResponseStatus OK = new HttpResponseStatus(200, "OK");
    public static final HttpResponseStatus CREATED = new HttpResponseStatus(201, "Created");
    public static final HttpResponseStatus ACCEPTED = new HttpResponseStatus(202, "Accepted");
    public static final HttpResponseStatus NO_CONTENT = new HttpResponseStatus(204, "No Content");
    public static final HttpResponseStatus MOVED_PERMANENTLY =
            new HttpResponseStatus(301, "Moved Permanently");
    public static final HttpResponseStatus FOUND = new HttpResponseStatus(302, "Found");
    public static final HttpResponseStatus NOT_MODIFIED = new HttpResponseStatus(304, "Not Modified");
    public static final HttpResponseStatus BAD_REQUEST = new HttpResponseStatus(400, "Bad Request");
    public static final HttpResponseStatus UNAUTHORIZED = new HttpResponseStatus(401, "Unauthorized");
    public static final HttpResponseStatus FORBIDDEN = new HttpResponseStatus(403, "Forbidden");
    public static final HttpResponseStatus NOT_FOUND = new HttpResponseStatus(404, "Not Found");
    public static final HttpResponseStatus METHOD_NOT_ALLOWED =
            new HttpResponseStatus(405, "Method Not Allowed");
    public static final HttpResponseStatus PROXY_AUTHENTICATION_REQUIRED =
            new HttpResponseStatus(407, "Proxy Authentication Required");
    public static final HttpResponseStatus REQUEST_TIMEOUT =
            new HttpResponseStatus(408, "Request Timeout");
    public static final HttpResponseStatus REQUEST_ENTITY_TOO_LARGE =
            new HttpResponseStatus(413, "Request Entity Too Large");
    public static final HttpResponseStatus EXPECTATION_FAILED =
            new HttpResponseStatus(417, "Expectation Failed");
    public static final HttpResponseStatus TOO_MANY_REQUESTS =
            new HttpResponseStatus(429, "Too Many Requests");
    public static final HttpResponseStatus REQUEST_HEADER_FIELDS_TOO_LARGE =
            new HttpResponseStatus(431, "Request Header Fields Too Large");
    public static final HttpResponseStatus INTERNAL_SERVER_ERROR =
            new HttpResponseStatus(500, "Internal Server Error");
    public static final HttpResponseStatus NOT_IMPLEMENTED =
            new HttpResponseStatus(501, "Not Implemented");
    public static final HttpResponseStatus BAD_GATEWAY = new HttpResponseStatus(502, "Bad Gateway");
    public static final HttpResponseStatus SERVICE_UNAVAILABLE =
            new HttpResponseStatus(503, "Service Unavailable");
    public static final HttpResponseStatus GATEWAY_TIMEOUT =
            new HttpResponseStatus(504, "Gateway Timeout");

    private static final HttpResponseStatus[] KNOWN = {
        CONTINUE, SWITCHING_PROTOCOLS, OK, CREATED, ACCEPTED, NO_CONTENT, MOVED_PERMANENTLY, FOUND,
        NOT_MODIFIED, BAD_REQUEST, UNAUTHORIZED, FORBIDDEN, NOT_FOUND, METHOD_NOT_ALLOWED,
        PROXY_AUTHENTICATION_REQUIRED, REQUEST_TIMEOUT, REQUEST_ENTITY_TOO_LARGE, EXPECTATION_FAILED,
        TOO_MANY_REQUESTS, REQUEST_HEADER_FIELDS_TOO_LARGE, INTERNAL_SERVER_ERROR, NOT_IMPLEMENTED, BAD_GATEWAY,
        SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT
    };

    public HttpResponseStatus {
        if (code < 100 || code > 999) {
            throw new IllegalArgumentException("invalid status code: " + code);
        }
        if (reasonPhrase == null || reasonPhrase.indexOf('\r') >= 0 || reasonPhrase.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("invalid reason phrase: " + reasonPhrase);
        }
    }

    /** Returns the well-known status for {@code code}, or a new one with a generic phrase. */
    public static HttpResponseStatus valueOf(int code) {
        for (HttpResponseStatus s : KNOWN) {
            if (s.code == code) return s;
        }
        return new HttpResponseStatus(code, defaultReason(code));
    }

    /** Returns a status with {@code code} and {@code reasonPhrase}, reusing constants when equal. */
    public static HttpResponseStatus valueOf(int code, String reasonPhrase) {
        HttpResponseStatus known = valueOf(code);
        return known.reasonPhrase.equals(reasonPhrase) ? known : new HttpResponseStatus(code, reasonPhrase);
    }

    private static String defaultReason(int code) {
        return switch (code / 100) {
            case 1 -> "Informational";
            case 2 -> "Success";
            case 3 -> "Redirection";
            case 4 -> "Client Error";
            case 5 -> "Server Error";
            default -> "Unknown Status";
        };
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof HttpResponseStatus s && s.code == code;
    }

    @Override
    public int hashCode() {
        return code;
    }

    @Override
    public String toString() {
        return code + " " + reasonPhrase;
    }
}
