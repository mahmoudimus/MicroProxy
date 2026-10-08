package org.microproxy;

import java.net.InetSocketAddress;

/** Base {@link ChainedProxy} implementation. */
public class ChainedProxyAdapter implements ChainedProxy {

    /**
     * Add this to the queue in {@link ChainedProxyManager#lookupChainedProxies} to connect
     * directly to the server.
     */
    public static final ChainedProxy FALLBACK_TO_DIRECT_CONNECTION = new ChainedProxyAdapter();

    @Override
    public InetSocketAddress getChainedProxyAddress() {
        return null;
    }
}
