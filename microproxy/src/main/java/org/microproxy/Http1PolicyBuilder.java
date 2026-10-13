package org.microproxy;

/**
 * Builds the {@link ProtocolPolicy} of HTTP/1.x clients ({@link HttpProxyServerBootstrap#onHttp1}):
 * the fields every protocol has, and those only HTTP/1 has, such as {@link #allowChunkedLength}.
 */
public final class Http1PolicyBuilder extends ProtocolPolicy.Builder {

    /** An empty builder: every field left to what applies below the policy. */
    public Http1PolicyBuilder() {}

    @Override
    public Http1PolicyBuilder preset(ProtocolPolicy preset) {
        setAll(java.util.Objects.requireNonNull(preset, "preset"), true);
        return this;
    }

    @Override
    public Http1PolicyBuilder resolveBeforeProxyToServerRequest(boolean resolveFirst) {
        super.resolveBeforeProxyToServerRequest(resolveFirst);
        return this;
    }

    @Override
    public Http1PolicyBuilder filterConnectAnswer(boolean filter) {
        super.filterConnectAnswer(filter);
        return this;
    }

    @Override
    public Http1PolicyBuilder servePlainHttpAfterConnect(boolean serve) {
        super.servePlainHttpAfterConnect(serve);
        return this;
    }

    @Override
    public Http1PolicyBuilder proxyProtocolDestination(ProxyProtocolDestination destination) {
        super.proxyProtocolDestination(destination);
        return this;
    }

    @Override
    public Http1PolicyBuilder tlsRetryWithoutSni(boolean retry) {
        super.tlsRetryWithoutSni(retry);
        return this;
    }

    /**
     * Sets {@link ProtocolPolicy#allowChunkedLength()}: whether an HTTP/1.1 request with both
     * {@code Transfer-Encoding} and {@code Content-Length} is accepted, its {@code Content-Length}
     * dropped and the connection closed after the response, as {@link
     * HttpProxyServerBootstrap#withAllowChunkedLength} says for the whole server.
     *
     * @param allow whether such requests are accepted
     * @return this builder
     */
    public Http1PolicyBuilder allowChunkedLength(boolean allow) {
        allowChunkedLength = allow;
        return this;
    }

    /**
     * Sets a field by its configuration name, as {@link ProtocolPolicy.Builder#set} does, and
     * also {@code allow_chunked_length}.
     *
     * @param name the field's name
     * @param value its value
     * @return this builder
     * @throws IllegalArgumentException for an unknown field, or a value the field does not take
     */
    @Override
    public Http1PolicyBuilder set(String name, String value) {
        if (ProtocolPolicy.token(name).equals("allow_chunked_length")) {
            allowChunkedLength(bool(name, value));
        } else {
            super.set(name, value);
        }
        return this;
    }
}
