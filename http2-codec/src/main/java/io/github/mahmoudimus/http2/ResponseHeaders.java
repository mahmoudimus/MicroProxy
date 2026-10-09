package io.github.mahmoudimus.http2;

import java.util.ArrayList;
import java.util.List;

/**
 * A validated HTTP/2 response header section, as {@link Http2Headers#toResponse} produces it.
 *
 * @param status {@code :status}, 100 to 999
 * @param fields the regular fields in order, with lower-case names
 * @param contentLength the {@code content-length}, or -1 if absent
 */
public record ResponseHeaders(int status, List<HeaderField> fields, long contentLength) {

    /**
     * Creates response headers and takes an immutable copy of the regular fields.
     *
     * @param status the response status
     * @param fields the regular fields in order
     * @param contentLength the declared content length, or -1 if absent
     */
    public ResponseHeaders {
        fields = List.copyOf(fields);
    }

    /**
     * An interim (1xx) response; more header sections follow on the stream.
     *
     * @return whether the status is in the range 100 to 199
     */
    public boolean isInformational() {
        return status >= 100 && status < 200;
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
