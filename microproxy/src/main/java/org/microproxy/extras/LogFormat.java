package org.microproxy.extras;

/** Access-log line formats supported by {@link ActivityLogger}. */
public enum LogFormat {
    /** NCSA Common Log Format: {@code host ident authuser [date] "request" status bytes}. */
    CLF,
    /** NCSA Combined (extended) format: CLF plus {@code "referer" "user-agent"}. */
    ELF,
    /** One JSON object per line. */
    JSON,
    /** Squid native: {@code time elapsed client code/status bytes method URL user hierarchy/peer type}. */
    SQUID,
    /** W3C extended: {@code date time c-ip cs-method cs-uri sc-status sc-bytes "cs(User-Agent)"}. */
    W3C,
    /** Labeled tab-separated values ({@code label:value<TAB>...}). */
    LTSV,
    /** RFC 4180 comma-separated values. */
    CSV,
    /** HAProxy-style HTTP log: {@code client [date] "request" status bytes duration}. */
    HAPROXY,
    /**
     * {@link #JSON} plus where the response came from and how long it took: {@code source}
     * ({@link org.microproxy.ResponseSource}), {@code upstream_status} (the server's status, or
     * {@code null}), and {@code ttfb_ms}, {@code total_ms}, {@code dns_ms}, {@code connect_ms} and
     * {@code tls_ms} (milliseconds, or {@code null} for phases that did not happen). Written when
     * the response is complete.
     */
    JSON_EXTENDED
}
