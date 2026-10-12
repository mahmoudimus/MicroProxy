package org.microproxy.quic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Which {@link MessageFramer} cuts the streams of an intercepted QUIC connection into messages, for
 * a {@link QuicInterceptor} that overrides {@link QuicInterceptor#streamMessage}; the limit on a
 * message's size; and the error code a stream is reset with when a message is too large or
 * malformed. Configure it with {@link org.microproxy.HttpProxyServerBootstrap#withQuicFraming}.
 *
 * <p>Rules map a key to a framer's name. A key is an ALPN protocol ({@code doq}), a host name
 * ({@code dns.example.com}, matched against the server's host and the SNI, ignoring case; {@code
 * *.example.com} also matches the names below it), or {@code *} for any connection. A host rule
 * wins over an ALPN rule, which wins over {@code *}. The framers' names: {@code u16}, {@code u32},
 * {@code varint}, {@code lf} and {@code crlf} (see {@link MessageFramer}), {@code none} for no
 * framing, and names given with {@link #withFramer} (a script's framer is {@code script}).
 *
 * <pre>{@code
 * QuicFraming framing = QuicFraming.parse("myproto=varint,dns.example.com=u16,*=none")   // --quic-framing
 *         .withRule("chat", MessageFramer.lines())
 *         .withMaxMessageSize(64 * 1024);                                               // --quic-max-message-size
 * }</pre>
 *
 * <p>{@link #defaults()} frames DNS over QUIC ({@code doq}) with {@code u16}, as RFC 9250 says;
 * every other connection is unframed. Framing applies only to an interceptor that overrides {@code
 * streamMessage}: other interceptors see each read through {@link QuicInterceptor#streamData}, and
 * nothing is kept. Instances are immutable; the {@code with} methods return changed copies.
 */
public final class QuicFraming {

    /** The default limit on a message's size, its prefix or delimiter included: 1 MiB. */
    public static final int DEFAULT_MAX_MESSAGE_SIZE = 1 << 20;
    /**
     * The default application error code of the resets for a message that is too large or
     * malformed: 0x2, DOQ_PROTOCOL_ERROR in DNS over QUIC (RFC 9250 section 8.4).
     */
    public static final long DEFAULT_ERROR_CODE = 0x2;
    /** The name of no framing. */
    public static final String NONE = "none";

    private static final QuicFraming DEFAULTS = new QuicFraming(Map.of("doq", "u16"), Map.of(),
            DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_ERROR_CODE);
    private static final QuicFraming EMPTY = new QuicFraming(Map.of(), Map.of(), DEFAULT_MAX_MESSAGE_SIZE,
            DEFAULT_ERROR_CODE);

    /** Key (lower case) to framer name (lower case), in the order given. */
    private final Map<String, String> rules;
    /** Framers given by name, beside the built-in ones. */
    private final Map<String, MessageFramer> framers;
    private final int maxMessageSize;
    private final long errorCode;

    private QuicFraming(Map<String, String> rules, Map<String, MessageFramer> framers, int maxMessageSize,
            long errorCode) {
        this.rules = Collections.unmodifiableMap(new LinkedHashMap<>(rules));
        this.framers = Collections.unmodifiableMap(new LinkedHashMap<>(framers));
        this.maxMessageSize = maxMessageSize;
        this.errorCode = errorCode;
    }

    /** {@return the default framing: {@code doq=u16}, with the default limit and error code} */
    public static QuicFraming defaults() {
        return DEFAULTS;
    }

    /** {@return no rules at all: every connection unframed, DNS over QUIC included} */
    public static QuicFraming none() {
        return EMPTY;
    }

    /**
     * The {@linkplain #defaults() defaults} with the rules of {@code spec} added, as {@code
     * --quic-framing} gives them.
     *
     * @param spec comma-separated {@code key=framer} rules, such as {@code doq=u16,myproto=varint,*=none}
     * @return the framing
     * @throws IllegalArgumentException if a rule is not {@code key=framer}
     */
    public static QuicFraming parse(String spec) {
        return DEFAULTS.withRules(spec);
    }

    /**
     * These rules with those of {@code spec} added; a rule for a key that has one replaces it.
     *
     * @param spec comma-separated {@code key=framer} rules
     * @return the copy
     * @throws IllegalArgumentException if a rule is not {@code key=framer}
     */
    public QuicFraming withRules(String spec) {
        Map<String, String> r = new LinkedHashMap<>(rules);
        for (String part : spec.split(",")) {
            String rule = part.strip();
            if (rule.isEmpty()) continue;
            int eq = rule.indexOf('=');
            if (eq <= 0 || eq == rule.length() - 1) {
                throw new IllegalArgumentException("a QUIC framing rule is key=framer, not " + rule);
            }
            put(r, rule.substring(0, eq), rule.substring(eq + 1));
        }
        return new QuicFraming(r, framers, maxMessageSize, errorCode);
    }

    /**
     * These rules with one more: {@code key} framed by the framer named {@code framer}.
     *
     * @param key an ALPN protocol, a host name ({@code *.example.com} for the names below it) or
     *     {@code *}
     * @param framer a framer's name, or {@value #NONE}
     * @return the copy
     */
    public QuicFraming withRule(String key, String framer) {
        Map<String, String> r = new LinkedHashMap<>(rules);
        put(r, key, framer);
        return new QuicFraming(r, framers, maxMessageSize, errorCode);
    }

    /**
     * These rules with one more: {@code key} framed by {@code framer}, which is given the name
     * {@code key} among the framers.
     *
     * @param key an ALPN protocol, a host name or {@code *}
     * @param framer the framer
     * @return the copy
     */
    public QuicFraming withRule(String key, MessageFramer framer) {
        String name = "rule:" + key.strip().toLowerCase(Locale.ROOT);
        return withFramer(name, framer).withRule(key, name);
    }

    /**
     * These rules with a framer that rules can name, replacing one of the same name.
     *
     * @param name the name (not a built-in framer's)
     * @param framer the framer
     * @return the copy
     * @throws IllegalArgumentException if {@code name} is a built-in framer's or {@value #NONE}
     */
    public QuicFraming withFramer(String name, MessageFramer framer) {
        Objects.requireNonNull(framer, "framer");
        String n = name.strip().toLowerCase(Locale.ROOT);
        if (n.isEmpty() || n.equals(NONE) || Framers.named(n) != null) {
            throw new IllegalArgumentException("a framer cannot be named " + name);
        }
        Map<String, MessageFramer> f = new LinkedHashMap<>(framers);
        f.put(n, framer);
        return new QuicFraming(rules, f, maxMessageSize, errorCode);
    }

    /**
     * These rules with another limit on a message's size.
     *
     * @param maxMessageSize the most bytes a message may have, its prefix or delimiter included
     * @return the copy
     * @throws IllegalArgumentException if the limit is not positive
     */
    public QuicFraming withMaxMessageSize(int maxMessageSize) {
        if (maxMessageSize <= 0) throw new IllegalArgumentException("the QUIC message size limit must be positive");
        return new QuicFraming(rules, framers, maxMessageSize, errorCode);
    }

    /**
     * These rules with another error code for the resets of a stream whose message is too large or
     * malformed.
     *
     * @param errorCode the application error code, below 2<sup>62</sup>
     * @return the copy
     * @throws IllegalArgumentException if the code is negative or too large for QUIC
     */
    public QuicFraming withErrorCode(long errorCode) {
        if (errorCode < 0 || errorCode >= (1L << 62)) {
            throw new IllegalArgumentException("a QUIC error code is between 0 and 2^62 - 1");
        }
        return new QuicFraming(rules, framers, maxMessageSize, errorCode);
    }

    /** {@return the rules, key to framer name, in lower case and in the order given} */
    public Map<String, String> rules() {
        return rules;
    }

    /** {@return the most bytes a message may have, its prefix or delimiter included} */
    public int maxMessageSize() {
        return maxMessageSize;
    }

    /** {@return the application error code of the resets for a message that is too large or malformed} */
    public long errorCode() {
        return errorCode;
    }

    /**
     * The framer for a connection: that of the first host rule matching {@code host} or {@code sni},
     * else that of the {@code alpn} rule, else that of {@code *}.
     *
     * @param alpn the negotiated ALPN protocol, or null
     * @param host the server's host name or address, or null
     * @param sni the SNI, or null
     * @return the framer, or null for none
     * @throws IllegalStateException if the rule names a framer there is none of
     */
    public MessageFramer framerFor(String alpn, String host, String sni) {
        String name = null;
        for (Map.Entry<String, String> rule : rules.entrySet()) {
            if (matchesHost(rule.getKey(), host) || matchesHost(rule.getKey(), sni)) {
                name = rule.getValue();
                break;
            }
        }
        if (name == null && alpn != null) name = rules.get(alpn.toLowerCase(Locale.ROOT));
        if (name == null) name = rules.get("*");
        return name == null ? null : framer(name);
    }

    /**
     * The framer for an intercepted connection, by its ALPN, host and SNI.
     *
     * @param connection the connection
     * @return the framer, or null for none
     * @throws IllegalStateException if the rule names a framer there is none of
     */
    public MessageFramer framerFor(QuicContext connection) {
        return framerFor(connection.alpn(), connection.host(), connection.sni());
    }

    /**
     * Checks that every rule names a framer there is.
     *
     * @throws IllegalArgumentException naming the first rule that does not
     */
    public void validate() {
        for (Map.Entry<String, String> rule : rules.entrySet()) {
            try {
                framer(rule.getValue());
            } catch (IllegalStateException e) {
                throw new IllegalArgumentException("QUIC framing " + rule.getKey() + "=" + rule.getValue() + ": "
                        + e.getMessage(), e);
            }
        }
    }

    private MessageFramer framer(String name) {
        if (name.equals(NONE)) return null;
        MessageFramer f = Framers.named(name);
        if (f == null) f = framers.get(name);
        if (f == null) {
            List<String> known = new ArrayList<>(List.of("u16", "u32", "varint", "lf", "crlf", NONE));
            known.addAll(framers.keySet());
            throw new IllegalStateException("no framer named " + name + "; there are " + String.join(", ", known));
        }
        return f;
    }

    private static boolean matchesHost(String key, String host) {
        if (host == null || host.isEmpty() || key.equals("*")) return false;
        String h = host.toLowerCase(Locale.ROOT);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (key.startsWith("*.")) return h.endsWith(key.substring(1)) || h.equals(key.substring(2));
        return h.equals(key);
    }

    private static void put(Map<String, String> rules, String key, String framer) {
        String k = key.strip().toLowerCase(Locale.ROOT);
        String f = framer.strip().toLowerCase(Locale.ROOT);
        if (k.isEmpty() || f.isEmpty()) throw new IllegalArgumentException("a QUIC framing rule needs a key and a framer");
        rules.remove(k);
        rules.put(k, f);
    }

    @Override
    public String toString() {
        List<String> parts = new ArrayList<>();
        rules.forEach((k, v) -> parts.add(k + "=" + v));
        return String.join(",", parts) + " (max " + maxMessageSize + " bytes, error code " + errorCode + ")";
    }
}
