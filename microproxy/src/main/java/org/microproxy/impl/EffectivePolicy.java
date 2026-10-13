package org.microproxy.impl;

import org.microproxy.ProtocolPolicy;
import org.microproxy.ProxyProtocolDestination;

/**
 * A {@link ProtocolPolicy} with every field resolved, as plain fields: what the exchanges of one
 * client protocol read, resolved once per server.
 */
record EffectivePolicy(
        ProtocolPolicy policy,
        boolean resolveBeforeProxyToServerRequest,
        boolean filterConnectAnswer,
        boolean servePlainHttpAfterConnect,
        ProxyProtocolDestination proxyProtocolDestination,
        boolean tlsRetryWithoutSni,
        boolean allowChunkedLength,
        org.microproxy.GeneratedResponses generatedResponses) {

    /** Resolves {@code policy}, which sets every field (but HTTP/1's for other protocols). */
    static EffectivePolicy of(ProtocolPolicy policy) {
        return new EffectivePolicy(policy,
                policy.resolveBeforeProxyToServerRequest().orElseThrow(),
                policy.filterConnectAnswer().orElseThrow(),
                policy.servePlainHttpAfterConnect().orElseThrow(),
                policy.proxyProtocolDestination().orElseThrow(),
                policy.tlsRetryWithoutSni().orElseThrow(),
                policy.allowChunkedLength().orElse(false),
                policy.generatedResponses().orElseThrow());
    }
}
