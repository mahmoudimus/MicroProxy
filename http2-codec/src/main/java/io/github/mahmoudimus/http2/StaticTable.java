package io.github.mahmoudimus.http2;

import java.util.HashMap;
import java.util.Map;

/** The HPACK static table (RFC 7541 Appendix A), indexed from 1. */
final class StaticTable {

    static final HeaderField[] ENTRIES = {
        null,
        new HeaderField(":authority", ""),
        new HeaderField(":method", "GET"),
        new HeaderField(":method", "POST"),
        new HeaderField(":path", "/"),
        new HeaderField(":path", "/index.html"),
        new HeaderField(":scheme", "http"),
        new HeaderField(":scheme", "https"),
        new HeaderField(":status", "200"),
        new HeaderField(":status", "204"),
        new HeaderField(":status", "206"),
        new HeaderField(":status", "304"),
        new HeaderField(":status", "400"),
        new HeaderField(":status", "404"),
        new HeaderField(":status", "500"),
        new HeaderField("accept-charset", ""),
        new HeaderField("accept-encoding", "gzip, deflate"),
        new HeaderField("accept-language", ""),
        new HeaderField("accept-ranges", ""),
        new HeaderField("accept", ""),
        new HeaderField("access-control-allow-origin", ""),
        new HeaderField("age", ""),
        new HeaderField("allow", ""),
        new HeaderField("authorization", ""),
        new HeaderField("cache-control", ""),
        new HeaderField("content-disposition", ""),
        new HeaderField("content-encoding", ""),
        new HeaderField("content-language", ""),
        new HeaderField("content-length", ""),
        new HeaderField("content-location", ""),
        new HeaderField("content-range", ""),
        new HeaderField("content-type", ""),
        new HeaderField("cookie", ""),
        new HeaderField("date", ""),
        new HeaderField("etag", ""),
        new HeaderField("expect", ""),
        new HeaderField("expires", ""),
        new HeaderField("from", ""),
        new HeaderField("host", ""),
        new HeaderField("if-match", ""),
        new HeaderField("if-modified-since", ""),
        new HeaderField("if-none-match", ""),
        new HeaderField("if-range", ""),
        new HeaderField("if-unmodified-since", ""),
        new HeaderField("last-modified", ""),
        new HeaderField("link", ""),
        new HeaderField("location", ""),
        new HeaderField("max-forwards", ""),
        new HeaderField("proxy-authenticate", ""),
        new HeaderField("proxy-authorization", ""),
        new HeaderField("range", ""),
        new HeaderField("referer", ""),
        new HeaderField("refresh", ""),
        new HeaderField("retry-after", ""),
        new HeaderField("server", ""),
        new HeaderField("set-cookie", ""),
        new HeaderField("strict-transport-security", ""),
        new HeaderField("transfer-encoding", ""),
        new HeaderField("user-agent", ""),
        new HeaderField("vary", ""),
        new HeaderField("via", ""),
        new HeaderField("www-authenticate", ""),
    };

    /** The number of entries, 61. */
    static final int LENGTH = ENTRIES.length - 1;

    private static final Map<String, Integer> BY_NAME = new HashMap<>();
    private static final Map<String, Integer> BY_FIELD = new HashMap<>();

    static {
        for (int i = LENGTH; i >= 1; i--) { // the lowest index wins
            BY_NAME.put(ENTRIES[i].name(), i);
            BY_FIELD.put(key(ENTRIES[i].name(), ENTRIES[i].value()), i);
        }
    }

    private StaticTable() {}

    /** The index of an entry with this name and value, or 0. */
    static int indexOf(String name, String value) {
        Integer i = BY_FIELD.get(key(name, value));
        return i == null ? 0 : i;
    }

    /** The index of the first entry with this name, or 0. */
    static int indexOfName(String name) {
        Integer i = BY_NAME.get(name);
        return i == null ? 0 : i;
    }

    private static String key(String name, String value) {
        return name + '\n' + value; // '\n' cannot appear in a valid name
    }
}
