package org.microproxy.cache;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpResponseStatus;

/**
 * A stored response: status, header fields and body as received, the request header values its
 * {@code Vary} named, and when it was requested and received (for the age calculation of RFC 9111
 * section 4.2.3). Instances are immutable.
 */
public final class CachedResponse {

    /** Fields not stored: they describe the connection, not the response. */
    static final Set<String> HOP_BY_HOP = Set.of("connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade");

    /** Fields a 304 must not change in the stored response (RFC 9111 section 3.2). */
    private static final Set<String> NOT_UPDATED = Set.of("content-length", "content-encoding", "content-range",
            "transfer-encoding");

    private final String key;
    private final Map<String, String> vary;
    private final int status;
    private final String reason;
    private final HttpHeaders headers;
    private final byte[] body;
    private final long requestTime;
    private final long responseTime;

    /**
     * @param key the URL the response was stored under
     * @param vary for each field named by {@code Vary} (lower-cased), the request's normalized value,
     *     or {@code null} if the request lacked it
     */
    public CachedResponse(String key, Map<String, String> vary, int status, String reason, HttpHeaders headers,
            byte[] body, long requestTime, long responseTime) {
        this.key = Objects.requireNonNull(key);
        this.vary = Collections.unmodifiableMap(new TreeMap<>(vary));
        this.status = status;
        this.reason = Objects.requireNonNull(reason);
        this.headers = headers.copy();
        for (String name : HOP_BY_HOP) this.headers.remove(name);
        this.body = body.clone();
        this.requestTime = requestTime;
        this.responseTime = responseTime;
    }

    public String key() {
        return key;
    }

    public Map<String, String> vary() {
        return vary;
    }

    public int status() {
        return status;
    }

    public String reason() {
        return reason;
    }

    /** A copy of the stored header fields. */
    public HttpHeaders headers() {
        return headers.copy();
    }

    String header(String name) {
        return headers.get(name);
    }

    /** A copy of the body. */
    public byte[] body() {
        return body.clone();
    }

    int bodyLength() {
        return body.length;
    }

    byte[] bodyUnsafe() {
        return body;
    }

    HttpHeaders headersUnsafe() {
        return headers;
    }

    public long requestTime() {
        return requestTime;
    }

    public long responseTime() {
        return responseTime;
    }

    /** Roughly how much memory or disk the entry takes. */
    public long weight() {
        long w = body.length + key.length() + 64;
        for (Map.Entry<String, String> e : headers.entries()) w += e.getKey().length() + e.getValue().length() + 4;
        return w;
    }

    /** The response to send: the stored one with an {@code Age} field, without a body for HEAD. */
    FullHttpResponse toResponse(long now, boolean head) {
        FullHttpResponse r = new HttpCache.Answer(HttpResponseStatus.valueOf(status, reason),
                head ? new byte[0] : body.clone());
        r.headers().set(headers);
        r.headers().set("Content-Length", String.valueOf(body.length));
        r.headers().set("Age", String.valueOf(currentAge(now) / 1000));
        return r;
    }

    /** This response with header fields updated by a {@code 304} from revalidation. */
    CachedResponse revalidated(HttpHeaders notModified, long newRequestTime, long newResponseTime) {
        HttpHeaders merged = headers.copy();
        for (String name : notModified.names()) {
            String lower = name.toLowerCase(Locale.ROOT);
            if (NOT_UPDATED.contains(lower) || HOP_BY_HOP.contains(lower)) continue;
            merged.set(name, notModified.getAll(name));
        }
        return new CachedResponse(key, vary, status, reason, merged, body, newRequestTime, newResponseTime);
    }

    // ---------------------------------------------------------------------------------------
    // Freshness (RFC 9111 section 4.2)
    // ---------------------------------------------------------------------------------------

    /** The age in milliseconds at {@code now}. */
    long currentAge(long now) {
        long date = date();
        long apparentAge = Math.max(0, responseTime - date);
        long ageValue = parseAge(headers.get("Age"));
        long responseDelay = Math.max(0, responseTime - requestTime);
        long correctedInitialAge = Math.max(apparentAge, ageValue * 1000 + responseDelay);
        long residentTime = Math.max(0, now - responseTime);
        return correctedInitialAge + residentTime;
    }

    /** How long the response is fresh for, in milliseconds. */
    long freshnessLifetime(boolean shared, double heuristicFraction, long maxHeuristic) {
        CacheControl cc = cacheControl();
        if (shared && cc.has("s-maxage")) return cc.seconds("s-maxage") * 1000;
        if (cc.has("max-age")) return cc.seconds("max-age") * 1000;
        String expires = headers.get("Expires");
        if (expires != null) {
            long e = parseDate(expires);
            return e < 0 ? 0 : Math.max(0, e - date());
        }
        String lastModified = headers.get("Last-Modified");
        if (lastModified != null && HttpCache.HEURISTIC_STATUSES.contains(status)) {
            long lm = parseDate(lastModified);
            if (lm >= 0 && lm < date()) {
                return Math.min(maxHeuristic, (long) ((date() - lm) * heuristicFraction));
            }
        }
        return 0;
    }

    CacheControl cacheControl() {
        return CacheControl.of(headers, false);
    }

    private long date() {
        long d = parseDate(headers.get("Date"));
        return d < 0 ? responseTime : d;
    }

    private static long parseAge(String age) {
        if (age == null || age.isBlank() || !age.strip().chars().allMatch(Character::isDigit)) return 0;
        try {
            return Long.parseLong(age.strip());
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE;
        }
    }

    /** Parses an HTTP date; -1 if absent or malformed. */
    static long parseDate(String value) {
        if (value == null) return -1;
        try {
            return ZonedDateTime.parse(value.strip(), DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli();
        } catch (DateTimeParseException e) {
            return -1;
        }
    }

    static String formatDate(long millis) {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(Instant.ofEpochMilli(millis).atZone(ZoneOffset.UTC));
    }

    @Override
    public String toString() {
        return "CachedResponse[" + status + " " + key + (vary.isEmpty() ? "" : " " + vary) + "]";
    }
}
