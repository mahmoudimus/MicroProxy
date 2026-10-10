package io.github.mahmoudimus.http3;

import java.util.HashMap;
import java.util.Map;

/**
 * The QPACK static table (RFC 9204 Appendix A): 99 entries, indexed from 0 (unlike HPACK's, which
 * starts at 1). Transcribed from the RFC text, where long values are wrapped across lines; the
 * line breaks are formatting only.
 */
final class QpackStaticTable {

    static final HeaderField[] ENTRIES = {
        new HeaderField(":authority", ""), // 0
        new HeaderField(":path", "/"), // 1
        new HeaderField("age", "0"), // 2
        new HeaderField("content-disposition", ""), // 3
        new HeaderField("content-length", "0"), // 4
        new HeaderField("cookie", ""), // 5
        new HeaderField("date", ""), // 6
        new HeaderField("etag", ""), // 7
        new HeaderField("if-modified-since", ""), // 8
        new HeaderField("if-none-match", ""), // 9
        new HeaderField("last-modified", ""), // 10
        new HeaderField("link", ""), // 11
        new HeaderField("location", ""), // 12
        new HeaderField("referer", ""), // 13
        new HeaderField("set-cookie", ""), // 14
        new HeaderField(":method", "CONNECT"), // 15
        new HeaderField(":method", "DELETE"), // 16
        new HeaderField(":method", "GET"), // 17
        new HeaderField(":method", "HEAD"), // 18
        new HeaderField(":method", "OPTIONS"), // 19
        new HeaderField(":method", "POST"), // 20
        new HeaderField(":method", "PUT"), // 21
        new HeaderField(":scheme", "http"), // 22
        new HeaderField(":scheme", "https"), // 23
        new HeaderField(":status", "103"), // 24
        new HeaderField(":status", "200"), // 25
        new HeaderField(":status", "304"), // 26
        new HeaderField(":status", "404"), // 27
        new HeaderField(":status", "503"), // 28
        new HeaderField("accept", "*/*"), // 29
        new HeaderField("accept", "application/dns-message"), // 30
        new HeaderField("accept-encoding", "gzip, deflate, br"), // 31
        new HeaderField("accept-ranges", "bytes"), // 32
        new HeaderField("access-control-allow-headers", "cache-control"), // 33
        new HeaderField("access-control-allow-headers", "content-type"), // 34
        new HeaderField("access-control-allow-origin", "*"), // 35
        new HeaderField("cache-control", "max-age=0"), // 36
        new HeaderField("cache-control", "max-age=2592000"), // 37
        new HeaderField("cache-control", "max-age=604800"), // 38
        new HeaderField("cache-control", "no-cache"), // 39
        new HeaderField("cache-control", "no-store"), // 40
        new HeaderField("cache-control", "public, max-age=31536000"), // 41
        new HeaderField("content-encoding", "br"), // 42
        new HeaderField("content-encoding", "gzip"), // 43
        new HeaderField("content-type", "application/dns-message"), // 44
        new HeaderField("content-type", "application/javascript"), // 45
        new HeaderField("content-type", "application/json"), // 46
        new HeaderField("content-type", "application/x-www-form-urlencoded"), // 47
        new HeaderField("content-type", "image/gif"), // 48
        new HeaderField("content-type", "image/jpeg"), // 49
        new HeaderField("content-type", "image/png"), // 50
        new HeaderField("content-type", "text/css"), // 51
        new HeaderField("content-type", "text/html; charset=utf-8"), // 52
        new HeaderField("content-type", "text/plain"), // 53
        new HeaderField("content-type", "text/plain;charset=utf-8"), // 54
        new HeaderField("range", "bytes=0-"), // 55
        new HeaderField("strict-transport-security", "max-age=31536000"), // 56
        new HeaderField("strict-transport-security", "max-age=31536000; includesubdomains"), // 57
        new HeaderField("strict-transport-security", "max-age=31536000; includesubdomains; preload"), // 58
        new HeaderField("vary", "accept-encoding"), // 59
        new HeaderField("vary", "origin"), // 60
        new HeaderField("x-content-type-options", "nosniff"), // 61
        new HeaderField("x-xss-protection", "1; mode=block"), // 62
        new HeaderField(":status", "100"), // 63
        new HeaderField(":status", "204"), // 64
        new HeaderField(":status", "206"), // 65
        new HeaderField(":status", "302"), // 66
        new HeaderField(":status", "400"), // 67
        new HeaderField(":status", "403"), // 68
        new HeaderField(":status", "421"), // 69
        new HeaderField(":status", "425"), // 70
        new HeaderField(":status", "500"), // 71
        new HeaderField("accept-language", ""), // 72
        new HeaderField("access-control-allow-credentials", "FALSE"), // 73
        new HeaderField("access-control-allow-credentials", "TRUE"), // 74
        new HeaderField("access-control-allow-headers", "*"), // 75
        new HeaderField("access-control-allow-methods", "get"), // 76
        new HeaderField("access-control-allow-methods", "get, post, options"), // 77
        new HeaderField("access-control-allow-methods", "options"), // 78
        new HeaderField("access-control-expose-headers", "content-length"), // 79
        new HeaderField("access-control-request-headers", "content-type"), // 80
        new HeaderField("access-control-request-method", "get"), // 81
        new HeaderField("access-control-request-method", "post"), // 82
        new HeaderField("alt-svc", "clear"), // 83
        new HeaderField("authorization", ""), // 84
        new HeaderField("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"), // 85
        new HeaderField("early-data", "1"), // 86
        new HeaderField("expect-ct", ""), // 87
        new HeaderField("forwarded", ""), // 88
        new HeaderField("if-range", ""), // 89
        new HeaderField("origin", ""), // 90
        new HeaderField("purpose", "prefetch"), // 91
        new HeaderField("server", ""), // 92
        new HeaderField("timing-allow-origin", "*"), // 93
        new HeaderField("upgrade-insecure-requests", "1"), // 94
        new HeaderField("user-agent", ""), // 95
        new HeaderField("x-forwarded-for", ""), // 96
        new HeaderField("x-frame-options", "deny"), // 97
        new HeaderField("x-frame-options", "sameorigin"), // 98
    };

    /** The number of entries, 99. */
    static final int LENGTH = ENTRIES.length;

    private static final Map<String, Integer> BY_FIELD = new HashMap<>();
    private static final Map<String, Integer> BY_NAME = new HashMap<>();

    static {
        for (int i = LENGTH - 1; i >= 0; i--) { // the lowest index wins
            HeaderField f = ENTRIES[i];
            BY_FIELD.put(f.name() + '\0' + f.value(), i);
            BY_NAME.put(f.name(), i);
        }
    }

    private QpackStaticTable() {}

    /** The index of the entry with this name and value, or -1. */
    static int indexOf(String name, String value) {
        Integer i = BY_FIELD.get(name + '\0' + value);
        return i == null ? -1 : i;
    }

    /** The lowest index of an entry with this name, or -1. */
    static int indexOfName(String name) {
        Integer i = BY_NAME.get(name);
        return i == null ? -1 : i;
    }
}
