package org.microproxy.http;

/**
 * An HTTP protocol version such as {@code HTTP/1.1}.
 *
 * @param majorVersion non-negative major version number
 * @param minorVersion non-negative minor version number
 */
// @value-candidate: becomes a value class in the valhalla build profile
public record HttpVersion(int majorVersion, int minorVersion) {

    public static final HttpVersion HTTP_1_0 = new HttpVersion(1, 0);
    public static final HttpVersion HTTP_1_1 = new HttpVersion(1, 1);
    /**
     * HTTP/2: the version of requests that arrived on an HTTP/2 stream. HTTP/2 has no request
     * line; the proxy forwards such requests to servers as HTTP/1.1.
     */
    public static final HttpVersion HTTP_2_0 = new HttpVersion(2, 0);

    /**
     * Creates a protocol version.
     * @param majorVersion non-negative major version number
     * @param minorVersion non-negative minor version number
     * @throws IllegalArgumentException if either version number is negative
     */
    public HttpVersion {
        if (majorVersion < 0 || minorVersion < 0) {
            throw new IllegalArgumentException("negative version");
        }
    }

    /**
     * Parses {@code HTTP/x.y}, with one digit per version number.
     * @param text protocol version token
     * @return the parsed version, reusing well-known constants when possible
     * @throws IllegalArgumentException if the token does not have the required format
     */
    public static HttpVersion valueOf(String text) {
        if (text.length() == 8 && text.startsWith("HTTP/") && text.charAt(6) == '.') {
            char major = text.charAt(5);
            char minor = text.charAt(7);
            if (Character.isDigit(major) && Character.isDigit(minor)) {
                if (major == '1' && minor == '1') return HTTP_1_1;
                if (major == '1' && minor == '0') return HTTP_1_0;
                if (major == '2' && minor == '0') return HTTP_2_0;
                return new HttpVersion(major - '0', minor - '0');
            }
        }
        throw new IllegalArgumentException("invalid HTTP version: " + text);
    }

    /** {@return whether connections are persistent by default for this version (HTTP/1.1 and later)} */
    public boolean isKeepAliveDefault() {
        return majorVersion > 1 || (majorVersion == 1 && minorVersion >= 1);
    }

    /** {@return the protocol version token, such as {@code HTTP/1.1}} */
    public String text() {
        return "HTTP/" + majorVersion + '.' + minorVersion;
    }

    @Override
    public String toString() {
        return text();
    }
}
