package org.microproxy;

import java.net.InetSocketAddress;

/** Base {@link ChainedProxy} implementation. */
public class ChainedProxyAdapter implements ChainedProxy {

    /** Creates an adapter using the default HTTP upstream proxy behavior. */
    public ChainedProxyAdapter() {}

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
