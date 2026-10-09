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

    public ResponseHeaders {
        fields = List.copyOf(fields);
    }

    /** An interim (1xx) response; more header sections follow on the stream. */
    public boolean isInformational() {
        return status >= 100 && status < 200;
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
