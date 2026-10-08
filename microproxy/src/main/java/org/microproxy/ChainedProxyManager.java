package org.microproxy;

import java.util.Queue;
import org.microproxy.http.HttpRequest;

/** Chooses upstream proxies for each request. */
@FunctionalInterface
public interface ChainedProxyManager {

    /**
     * Adds the proxies to try, in order, to {@code chainedProxies}. Leave the queue empty to
     * reject the request with {@code 502}, or add {@link
     * ChainedProxyAdapter#FALLBACK_TO_DIRECT_CONNECTION} to connect directly.
     */
    void lookupChainedProxies(
            HttpRequest httpRequest, Queue<ChainedProxy> chainedProxies, ClientDetails clientDetails);
}
