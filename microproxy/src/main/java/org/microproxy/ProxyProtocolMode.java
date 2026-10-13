package org.microproxy;

/**
 * Whether client connections start with a PROXY protocol header (v1 or v2, as HAProxy defines
 * them), which names the client a load balancer in front of the proxy connected for. See {@link
 * HttpProxyServerBootstrap#withAcceptProxyProtocol(ProxyProtocolMode)}.
 */
public enum ProxyProtocolMode {
    /** No PROXY header is read: the connection's first bytes are the client's. The default. */
    OFF,
    /**
     * Every connection must start with a PROXY header; one that does not is closed. Use it when
     * every client reaches the proxy through a load balancer that sends the header.
     */
    REQUIRED,
    /**
     * A connection may start with a PROXY header: one that starts with a v1 ({@code "PROXY "}) or
     * v2 signature has it read, and any other is served as if PROXY protocol were off, its first
     * bytes left as they came. Any client that can reach the listener can then claim any source
     * address by sending a header, so use it only where the clients that can connect directly
     * are trusted, or with {@link HttpProxyServerBootstrap#withProxyProtocolTrustedSources} naming
     * the load balancers whose headers count.
     */
    OPTIONAL;

    /**
     * The mode a configuration value names: {@code off}, {@code required} or {@code optional}
     * (any case), or a boolean as LittleProxy's {@code allow_proxy_protocol} key takes it ({@code
     * true}, {@code on} or {@code 1} for {@link #REQUIRED}; {@code false}, {@code off}, {@code
     * 0}, {@code no} or nothing for {@link #OFF}).
     *
     * @param value the configuration value
     * @return the mode it names
     * @throws IllegalArgumentException for any other value
     */
    public static ProxyProtocolMode parse(String value) {
        String v = value.strip().toLowerCase(java.util.Locale.ROOT);
        return switch (v) {
            case "true", "on", "1", "required" -> REQUIRED;
            case "false", "off", "0", "no", "" -> OFF;
            case "optional" -> OPTIONAL;
            default -> throw new IllegalArgumentException(
                    "PROXY protocol mode must be off, required or optional (or true or false): " + value.strip());
        };
    }
}
