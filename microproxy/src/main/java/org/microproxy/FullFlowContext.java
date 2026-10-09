package org.microproxy;

import java.net.InetSocketAddress;

/** A {@link FlowContext} that also knows the server side of the flow. */
public class FullFlowContext extends FlowContext {

    private final String serverHostAndPort;
    private final ChainedProxy chainedProxy;
    private final InetSocketAddress remoteAddress;

    /**
     * Creates a server-side view of a client exchange.
     *
     * @param clientContext the client connection or exchange context
     * @param serverHostAndPort the requested server host and port
     * @param chainedProxy the upstream proxy in use, or {@code null} for direct routing
     * @param remoteAddress the connected server or upstream proxy address
     */
    public FullFlowContext(
            FlowContext clientContext,
            String serverHostAndPort,
            ChainedProxy chainedProxy,
            InetSocketAddress remoteAddress) {
        super(clientContext);
        this.serverHostAndPort = serverHostAndPort;
        this.chainedProxy = chainedProxy;
        this.remoteAddress = remoteAddress;
    }

    /** {@return the {@code host:port} the client asked for} */
    public String getServerHostAndPort() {
        return serverHostAndPort;
    }

    /** {@return the upstream proxy in use, or {@code null} for a direct connection} */
    public ChainedProxy getChainedProxy() {
        return chainedProxy;
    }

    /** {@return the address the proxy is connected to: the server, or the chained proxy} */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }
}
