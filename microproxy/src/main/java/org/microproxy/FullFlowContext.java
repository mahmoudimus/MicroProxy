package org.microproxy;

import java.net.InetSocketAddress;

/** A {@link FlowContext} that also knows the server side of the flow. */
public class FullFlowContext extends FlowContext {

    private final String serverHostAndPort;
    private final ChainedProxy chainedProxy;
    private final InetSocketAddress remoteAddress;

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

    /** The {@code host:port} the client asked for. */
    public String getServerHostAndPort() {
        return serverHostAndPort;
    }

    /** The upstream proxy in use, or {@code null} for a direct connection. */
    public ChainedProxy getChainedProxy() {
        return chainedProxy;
    }

    /** The address the proxy is connected to: the server, or the chained proxy. */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }
}
