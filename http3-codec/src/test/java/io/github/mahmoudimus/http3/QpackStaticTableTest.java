package io.github.mahmoudimus.http3;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The QPACK static table against RFC 9204 Appendix A. */
class QpackStaticTableTest {

    /**
     * SHA-256 of every entry as "index TAB name TAB value LF", computed by script from the RFC's
     * plain text with its wrapped lines rejoined (a break after '-' or '/' joins directly, any
     * other break is a space).
     */
    private static final String RFC_DIGEST = "bfff0ce1cd766d7a102be05b1530dfc2f394cc57e02c0037b7125183a204037a";

    @Test
    void hasTheRfcsNinetyNineEntries() throws NoSuchAlgorithmException {
        assertEquals(99, QpackStaticTable.LENGTH);
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < QpackStaticTable.LENGTH; i++) {
            HeaderField f = QpackStaticTable.ENTRIES[i];
            s.append(i).append('\t').append(f.name()).append('\t').append(f.value()).append('\n');
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(s.toString().getBytes(StandardCharsets.ISO_8859_1));
        assertEquals(RFC_DIGEST, HexFormat.of().formatHex(digest));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '"', value = {
        "0|:authority|\"\"",
        "1|:path|/",
        "2|age|0",
        "14|set-cookie|\"\"",
        "15|:method|CONNECT",
        "17|:method|GET",
        "21|:method|PUT",
        "23|:scheme|https",
        "24|:status|103",
        "25|:status|200",
        "28|:status|503",
        "29|accept|*/*",
        "30|accept|application/dns-message",
        "31|accept-encoding|gzip, deflate, br",
        "41|cache-control|public, max-age=31536000",
        "45|content-type|application/javascript",
        "47|content-type|application/x-www-form-urlencoded",
        "52|content-type|text/html; charset=utf-8",
        "54|content-type|text/plain;charset=utf-8",
        "55|range|bytes=0-",
        "57|strict-transport-security|max-age=31536000; includesubdomains",
        "58|strict-transport-security|max-age=31536000; includesubdomains; preload",
        "62|x-xss-protection|1; mode=block",
        "63|:status|100",
        "71|:status|500",
        "72|accept-language|\"\"",
        "73|access-control-allow-credentials|FALSE",
        "77|access-control-allow-methods|get, post, options",
        "83|alt-svc|clear",
        "85|content-security-policy|script-src 'none'; object-src 'none'; base-uri 'none'",
        "91|purpose|prefetch",
        "95|user-agent|\"\"",
        "98|x-frame-options|sameorigin",
    })
    void spotChecks(int index, String name, String value) {
        assertEquals(new HeaderField(name, value), QpackStaticTable.ENTRIES[index]);
        assertEquals(index, QpackStaticTable.indexOf(name, value));
    }

    @Test
    void lookups() {
        assertEquals(-1, QpackStaticTable.indexOf(":path", "/index.html"));
        assertEquals(1, QpackStaticTable.indexOfName(":path"));
        assertEquals(15, QpackStaticTable.indexOfName(":method")); // the lowest index with the name
        assertEquals(24, QpackStaticTable.indexOfName(":status"));
        assertEquals(44, QpackStaticTable.indexOfName("content-type"));
        assertEquals(-1, QpackStaticTable.indexOfName("x-custom"));
        assertEquals(-1, QpackStaticTable.indexOf("accept", ""));
    }
}
