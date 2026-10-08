package org.microproxy.http;

/** An HTTP protocol version such as {@code HTTP/1.1}. */
public record HttpVersion(int majorVersion, int minorVersion) {

    public static final HttpVersion HTTP_1_0 = new HttpVersion(1, 0);
    public static final HttpVersion HTTP_1_1 = new HttpVersion(1, 1);

    public HttpVersion {
        if (majorVersion < 0 || minorVersion < 0) {
            throw new IllegalArgumentException("negative version");
        }
    }

    /** Parses {@code HTTP/x.y}. */
    public static HttpVersion valueOf(String text) {
        if (text.length() == 8 && text.startsWith("HTTP/") && text.charAt(6) == '.') {
            char major = text.charAt(5);
            char minor = text.charAt(7);
            if (Character.isDigit(major) && Character.isDigit(minor)) {
                if (major == '1' && minor == '1') return HTTP_1_1;
                if (major == '1' && minor == '0') return HTTP_1_0;
                return new HttpVersion(major - '0', minor - '0');
            }
        }
        throw new IllegalArgumentException("invalid HTTP version: " + text);
    }

    /** Whether connections are persistent by default for this version (HTTP/1.1 and later). */
    public boolean isKeepAliveDefault() {
        return majorVersion > 1 || (majorVersion == 1 && minorVersion >= 1);
    }

    public String text() {
        return "HTTP/" + majorVersion + '.' + minorVersion;
    }

    @Override
    public String toString() {
        return text();
    }
}
