package org.microproxy;

/**
 * Which address a PROXY protocol header the proxy sends to a server ({@link
 * HttpProxyServerBootstrap#withSendProxyProtocol}) names as its destination, when the client's
 * connection did not bring a header of its own (whose destination is passed on as it is). A field
 * of a {@link ProtocolPolicy}.
 */
public enum ProxyProtocolDestination {
    /**
     * The address the client connected to: the proxy's end of the client connection ({@link
     * FlowContext#getLocalAddress()}), as HAProxy names it. The default.
     */
    LOCAL_ADDRESS,
    /**
     * The remote address of the proxy's connection to the server (or the chained proxy whose tunnel
     * carries the header), and no header at all when that address and the client's are of
     * different address families (IPv4 and IPv6), as LittleProxy does
     * ({@code ProxyToServerConnection.SendProxyProtocolHeader}).
     */
    SERVER_ADDRESS;

    /**
     * The value a configuration names: {@code local_address} or {@code server_address} (any
     * case, {@code -} for {@code _}).
     *
     * @param value the configuration value
     * @return the value it names
     * @throws IllegalArgumentException for any other value
     */
    public static ProxyProtocolDestination parse(String value) {
        return switch (ProtocolPolicy.token(value)) {
            case "local_address" -> LOCAL_ADDRESS;
            case "server_address" -> SERVER_ADDRESS;
            default -> throw new IllegalArgumentException(
                    "PROXY protocol destination must be local_address or server_address: " + value.strip());
        };
    }
}
