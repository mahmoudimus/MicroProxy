package org.microproxy.extras;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Named access-log formats for {@link ActivityLogger}, each a preset of {@link AccessLogFormat}:
 * an Envoy-compatible format string (or JSON dictionary) shown on each constant. Custom formats
 * come from {@link #envoy(String)} and {@link #envoyJson(Map)}.
 *
 * <p>The presets use a few operators of MicroProxy's own: {@code %MP_URL%} (the absolute URL),
 * {@code %MP_USER%} (the authenticated user), {@code %MP_RESPONSE_SOURCE%}, {@code
 * %MP_UPSTREAM_STATUS%} and {@code %MP_TIMING(phase)%}.
 */
public enum LogFormat {
    /**
     * NCSA Common Log Format: {@code host ident authuser [date] "request" status bytes}, as
     * {@code %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% - %MP_USER% [%START_TIME(%d/%b/%Y:%H:%M:%S %z)%]
     * "%REQ(:METHOD)% %MP_URL% %PROTOCOL%" %RESPONSE_CODE% %BYTES_SENT%}.
     */
    CLF(AccessLogFormat.envoy(LogFormat.CLF_FORMAT)),
    /** NCSA Combined (extended) format: CLF plus {@code "%REQ(REFERER)%" "%REQ(USER-AGENT)%"}. */
    ELF(AccessLogFormat.envoy(LogFormat.CLF_FORMAT + " \"%REQ(REFERER)%\" \"%REQ(USER-AGENT)%\"")),
    /**
     * One JSON object per line: {@code timestamp}, {@code client_ip}, {@code user}, {@code
     * method}, {@code uri}, {@code protocol}, {@code status}, {@code bytes}, {@code duration}
     * (milliseconds) and {@code user_agent}.
     */
    JSON(AccessLogFormat.envoyJson(LogFormat.jsonFields(false))),
    /**
     * Squid native: {@code time elapsed client code/status bytes method URL user hierarchy/peer
     * type}, as {@code %START_TIME(%s.%3f)% %DURATION% %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%
     * TCP_MISS/%RESPONSE_CODE% %BYTES_SENT% %REQ(:METHOD)% %MP_URL% %MP_USER%
     * DIRECT/%UPSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% %RESP(CONTENT-TYPE)%}; spaces in values become
     * {@code _}, so each value stays one column.
     */
    SQUID(AccessLogFormat.envoy("%START_TIME(%s.%3f)% %DURATION% %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
            + " TCP_MISS/%RESPONSE_CODE% %BYTES_SENT% %REQ(:METHOD)% %MP_URL% %MP_USER%"
            + " DIRECT/%UPSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% %RESP(CONTENT-TYPE)%", AccessLogFormat.Escape.NO_SPACES)),
    /**
     * W3C extended: {@code date time c-ip cs-method cs-uri sc-status sc-bytes "cs(User-Agent)"},
     * as {@code %START_TIME(%Y-%m-%d %H:%M:%S)% %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%
     * %REQ(:METHOD)% %MP_URL% %RESPONSE_CODE% %BYTES_SENT% "%REQ(USER-AGENT)%"}.
     */
    W3C(AccessLogFormat.envoy("%START_TIME(%Y-%m-%d %H:%M:%S)% %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
            + " %REQ(:METHOD)% %MP_URL% %RESPONSE_CODE% %BYTES_SENT% \"%REQ(USER-AGENT)%\"")),
    /** Labeled tab-separated values: {@code time}, {@code host}, {@code user}, {@code method}, {@code uri}, {@code status}, {@code size}, {@code duration}, {@code ua}. */
    LTSV(AccessLogFormat.envoy("time:" + LogFormat.ISO_TIME + "\thost:%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
            + "\tuser:%MP_USER%\tmethod:%REQ(:METHOD)%\turi:%MP_URL%\tstatus:%RESPONSE_CODE%\tsize:%BYTES_SENT%"
            + "\tduration:%DURATION%\tua:%REQ(USER-AGENT)%")),
    /** RFC 4180 comma-separated values, every field quoted: time, client, method, URL, status, bytes, duration, user agent. */
    CSV(AccessLogFormat.envoy(LogFormat.ISO_TIME + ",%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%,%REQ(:METHOD)%,%MP_URL%"
            + ",%RESPONSE_CODE%,%BYTES_SENT%,%DURATION%,%REQ(USER-AGENT)%", AccessLogFormat.Escape.CSV)),
    /**
     * HAProxy-style HTTP log: {@code client [date] "request" status bytes duration}, as {@code
     * %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% [%START_TIME(%d/%b/%Y:%H:%M:%S.%3f)%] "%REQ(:METHOD)%
     * %MP_URL% %PROTOCOL%" %RESPONSE_CODE% %BYTES_SENT% %DURATION%}.
     */
    HAPROXY(AccessLogFormat.envoy("%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% [%START_TIME(%d/%b/%Y:%H:%M:%S.%3f)%]"
            + " \"%REQ(:METHOD)% %MP_URL% %PROTOCOL%\" %RESPONSE_CODE% %BYTES_SENT% %DURATION%")),
    /**
     * {@link #JSON} plus where the response came from and how it went: {@code source} ({@link
     * org.microproxy.ResponseSource}), {@code upstream_status} (the server's status, or {@code
     * null}), {@code ttfb_ms}, {@code total_ms}, {@code dns_ms}, {@code connect_ms} and {@code
     * tls_ms} (milliseconds, or {@code null} for phases that did not happen), {@code
     * response_flags}, {@code response_code_details} and {@code flow} (the kind of exchange or
     * flow).
     */
    JSON_EXTENDED(AccessLogFormat.envoyJson(LogFormat.jsonFields(true))),
    /** Envoy's default format ({@link AccessLogFormat#ENVOY_DEFAULT}). */
    ENVOY(AccessLogFormat.envoy(AccessLogFormat.ENVOY_DEFAULT));

    private static final String CLF_FORMAT = "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT% - %MP_USER%"
            + " [%START_TIME(%d/%b/%Y:%H:%M:%S %z)%] \"%REQ(:METHOD)% %MP_URL% %PROTOCOL%\" %RESPONSE_CODE% %BYTES_SENT%";
    private static final String ISO_TIME = "%START_TIME(%Y-%m-%dT%H:%M:%S.%3f%z)%";

    private final AccessLogFormat formatter;

    LogFormat(AccessLogFormat formatter) {
        this.formatter = formatter;
    }

    /** {@return this preset as an {@link AccessLogFormat}} */
    public AccessLogFormat formatter() {
        return formatter;
    }

    /**
     * A custom format: an Envoy format string (see {@link AccessLogFormat#envoy}).
     *
     * @param format the format string
     * @return the format
     */
    public static AccessLogFormat envoy(String format) {
        return AccessLogFormat.envoy(format);
    }

    /**
     * A custom JSON format: keys and the format strings of their values (see {@link
     * AccessLogFormat#envoyJson(Map)}).
     *
     * @param dictionary the keys and their format strings
     * @return the format
     */
    public static AccessLogFormat envoyJson(Map<String, ?> dictionary) {
        return AccessLogFormat.envoyJson(dictionary);
    }

    /**
     * A preset by name ({@code clf}, {@code envoy}, ..., ignoring case), or else an Envoy format
     * string: what the command line's {@code --access-log-format} takes.
     *
     * @param presetOrFormat a preset name or a format string
     * @return the format
     * @throws IllegalArgumentException if it is neither a preset nor a format string with an operator
     */
    public static AccessLogFormat parse(String presetOrFormat) {
        String name = presetOrFormat.strip().toUpperCase(java.util.Locale.ROOT);
        for (LogFormat preset : values()) {
            if (preset.name().equals(name)) return preset.formatter();
        }
        if (presetOrFormat.indexOf('%') < 0) {
            throw new IllegalArgumentException("not an access-log format: " + presetOrFormat + "; expected one of "
                    + java.util.Arrays.toString(values()) + " or an Envoy format string such as"
                    + " '%START_TIME% %REQ(:METHOD)% %RESPONSE_CODE%'");
        }
        return AccessLogFormat.envoy(presetOrFormat);
    }

    private static Map<String, Object> jsonFields(boolean extended) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("timestamp", ISO_TIME);
        m.put("client_ip", "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%");
        m.put("user", "%MP_USER%");
        m.put("method", "%REQ(:METHOD)%");
        m.put("uri", "%MP_URL%");
        m.put("protocol", "%PROTOCOL%");
        m.put("status", "%RESPONSE_CODE%");
        m.put("bytes", "%BYTES_SENT%");
        m.put("duration", "%DURATION%");
        m.put("user_agent", "%REQ(USER-AGENT)%");
        if (extended) {
            m.put("source", "%MP_RESPONSE_SOURCE%");
            m.put("upstream_status", "%MP_UPSTREAM_STATUS%");
            m.put("ttfb_ms", "%MP_TIMING(ttfb)%");
            m.put("total_ms", "%MP_TIMING(total)%");
            m.put("dns_ms", "%MP_TIMING(dns)%");
            m.put("connect_ms", "%MP_TIMING(connect)%");
            m.put("tls_ms", "%MP_TIMING(tls)%");
            m.put("response_flags", "%RESPONSE_FLAGS%");
            m.put("response_code_details", "%RESPONSE_CODE_DETAILS%");
            m.put("flow", "%MP_FLOW%");
        }
        return m;
    }
}
