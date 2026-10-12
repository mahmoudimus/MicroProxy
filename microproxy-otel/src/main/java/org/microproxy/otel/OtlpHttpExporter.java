package org.microproxy.otel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

/**
 * Sends OTLP export requests to one signal's endpoint ({@code /v1/traces}, {@code /v1/metrics},
 * {@code /v1/logs}) with the JDK's {@link HttpClient}: a POST per batch, gzipped when asked, with
 * the configured headers, within a timeout per attempt. Answers that OTLP/HTTP says to retry
 * ({@code 429}, {@code 502}, {@code 503}, {@code 504}) and failed connections are retried with
 * exponential backoff and jitter, waiting at least what a {@code Retry-After} says; other answers
 * fail the batch. Called from one exporting thread at a time per signal.
 */
final class OtlpHttpExporter {

    private static final System.Logger LOG = System.getLogger(OtlpHttpExporter.class.getName());

    /** How long between two warnings about failing exports of one signal. */
    private static final long WARN_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();

    /** The longest {@code Retry-After} honoured, so that a collector cannot hold an export for hours. */
    private static final long MAX_RETRY_AFTER_NANOS = Duration.ofSeconds(30).toNanos();

    private final HttpClient client;
    private final URI endpoint;
    private final String contentType;
    private final Map<String, String> headers;
    private final boolean gzip;
    private final Duration timeout;
    private final int maxAttempts;
    private final Duration initialBackoff;
    private final Duration maxBackoff;
    private final String userAgent;
    final AtomicLong retries = new AtomicLong();
    final AtomicLong failures = new AtomicLong();
    private volatile long lastWarning = System.nanoTime() - WARN_INTERVAL_NANOS;

    OtlpHttpExporter(HttpClient client, URI endpoint, String contentType, Map<String, String> headers, boolean gzip,
            Duration timeout, int maxAttempts, Duration initialBackoff, Duration maxBackoff, String userAgent) {
        this.client = client;
        this.endpoint = endpoint;
        this.contentType = contentType;
        this.headers = Map.copyOf(headers);
        this.gzip = gzip;
        this.timeout = timeout;
        this.maxAttempts = Math.max(1, maxAttempts);
        this.initialBackoff = initialBackoff;
        this.maxBackoff = maxBackoff;
        this.userAgent = userAgent;
    }

    URI endpoint() {
        return endpoint;
    }

    /** Sends {@code body}; returns whether the collector accepted it, retrying as OTLP/HTTP says. */
    boolean export(byte[] body) {
        byte[] payload = gzip ? gzip(body) : body;
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", contentType)
                .header("User-Agent", userAgent)
                .POST(HttpRequest.BodyPublishers.ofByteArray(payload));
        if (gzip) builder.header("Content-Encoding", "gzip");
        headers.forEach(builder::header);
        HttpRequest request = builder.build();
        long backoff = initialBackoff.toNanos();
        for (int attempt = 1; ; attempt++) {
            long wait;
            String why;
            try {
                HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
                int status = response.statusCode();
                if (status / 100 == 2) return true;
                why = "status " + status;
                if (!retryable(status) || attempt >= maxAttempts) {
                    warn(why);
                    failures.incrementAndGet();
                    return false;
                }
                long after = retryAfterNanos(response.headers().firstValue("Retry-After").orElse(null));
                wait = Math.max(jitter(backoff), Math.min(after, MAX_RETRY_AFTER_NANOS));
            } catch (IOException e) {
                why = e.toString();
                if (attempt >= maxAttempts) {
                    warn(why);
                    failures.incrementAndGet();
                    return false;
                }
                wait = jitter(backoff);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                failures.incrementAndGet();
                return false;
            }
            retries.incrementAndGet();
            LOG.log(Level.DEBUG, "OTLP export to {0} failed ({1}); retrying in {2} ms", endpoint, why, wait / 1_000_000);
            try {
                Thread.sleep(Duration.ofNanos(wait));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                failures.incrementAndGet();
                return false;
            }
            backoff = Math.min(maxBackoff.toNanos(), (long) (backoff * 1.5));
        }
    }

    /** The statuses OTLP/HTTP says to retry. */
    static boolean retryable(int status) {
        return status == 429 || status == 502 || status == 503 || status == 504;
    }

    /** A random wait between half and all of {@code nanos}. */
    private static long jitter(long nanos) {
        return nanos <= 1 ? nanos : nanos / 2 + ThreadLocalRandom.current().nextLong(nanos / 2 + 1);
    }

    /** A {@code Retry-After} value, delta-seconds or an HTTP date, in nanoseconds from now; 0 for none. */
    static long retryAfterNanos(String value) {
        if (value == null || value.isBlank()) return 0;
        String v = value.strip();
        try {
            return Math.max(0, Duration.ofSeconds(Long.parseLong(v)).toNanos());
        } catch (NumberFormatException | ArithmeticException e) {
            try {
                ZonedDateTime at = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME);
                return Math.max(0, Duration.between(ZonedDateTime.now(at.getZone()), at).toNanos());
            } catch (DateTimeParseException | ArithmeticException e2) {
                return 0;
            }
        }
    }

    private void warn(String why) {
        long now = System.nanoTime();
        if (now - lastWarning >= WARN_INTERVAL_NANOS) {
            lastWarning = now;
            LOG.log(Level.WARNING, "OTLP export to {0} failed: {1}", endpoint, why);
        } else {
            LOG.log(Level.DEBUG, "OTLP export to {0} failed: {1}", endpoint, why);
        }
    }

    static byte[] gzip(byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, body.length / 4));
        try (GZIPOutputStream z = new GZIPOutputStream(out)) {
            z.write(body);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out.toByteArray();
    }

    @Override
    public String toString() {
        return "OtlpHttpExporter[" + endpoint + " " + contentType + (gzip ? " gzip" : "") + "]";
    }
}
