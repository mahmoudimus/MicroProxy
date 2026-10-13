package org.microproxy;

/**
 * How {@link HttpFilters#proxyToClientResponse} treats the responses the proxy answers with
 * itself, rather than relaying a server's: its own error responses (the {@code 502} for a server
 * it cannot reach, the {@code 504} for one that does not answer, a {@code 400} for a bad request,
 * the {@link FailureResponder}'s and {@link HttpFilters#proxyToServerFailure}'s answers, ...),
 * and the short-circuit responses a filter returned from an earlier hook ({@link
 * HttpFilters#clientToProxyRequest}, {@link HttpFilters#proxyToServerRequest}), the {@link
 * org.microproxy.cache.HttpCache}'s answers included. A field of a {@link ProtocolPolicy}
 * ({@link ProtocolPolicy#generatedResponses()}).
 *
 * <p>Those responses reach no other response hook: {@link HttpFilters#serverToProxyResponse}
 * sees only what comes from a server (and the {@code 200} that opens a {@code CONNECT} tunnel).
 * No filter sees the {@code 407} authentication challenge in any mode: it is sent before the
 * request's filters are made, as in LittleProxy. The {@code 200} that opens a {@code CONNECT}
 * tunnel and the {@code 101} that accepts a CONNECT-UDP flow are not answers in this sense but
 * the proxy's acceptance, which a filter may turn into a refusal ({@link
 * ProtocolPolicy#filterConnectAnswer()} decides whether filters see the {@code 200}).
 *
 * <p>To change the proxy's own error pages, use a {@link FailureResponder} (or {@link
 * HttpFilters#proxyToServerFailure}): it is asked for the answer to a failure, with the failure in
 * hand, whatever this setting says. Inside the hook, {@link FlowContext#responseSource()} tells
 * the proxy's and the filters' responses from the server's.
 */
public enum GeneratedResponses {
    /**
     * {@code proxyToClientResponse} sees generated responses as it sees the server's, and may
     * return another response to send instead, or {@code null} to close the connection without
     * an answer. The default, and LittleProxy 2.x's behaviour: {@code
     * ClientToProxyConnection.respondWithShortCircuitResponse} writes the response the hook
     * returns. Suits filters that brand every response the client gets: an error page of their
     * own, a {@code 503} with {@code Retry-After} in place of a {@code 502}, CORS or request-id
     * headers on every response.
     */
    REPLACEABLE,
    /**
     * {@code proxyToClientResponse} sees generated responses and may change them in place
     * (headers, status, content), or return {@code null} to close the connection without an
     * answer; a different object it returns is ignored (logged at {@code DEBUG}) and the
     * generated response, with the changes made to it, is sent. So a filter written for the
     * server's responses (one that answers some of them with a {@code 400}, say) cannot turn the
     * proxy's own {@code 502} for an unreachable server into something else. LittleProxy 1.x's
     * behaviour, kept by forks descended from it: its {@code
     * ClientToProxyConnection.respondWithShortCircuitResponse} runs the hook but writes the
     * response it was given.
     */
    IN_PLACE,
    /**
     * Generated responses never reach {@code proxyToClientResponse}: they are sent as made.
     * Trackers ({@link ActivityTracker#responseSentToClient}) and {@link
     * HttpFilters#proxyToClientResponseSent} still see them. For filters that must only ever see
     * the server's responses.
     */
    SKIP;

    /**
     * The value a configuration names: {@code replaceable}, {@code in_place} or {@code skip} (any
     * case, {@code -} for {@code _}).
     *
     * @param value the configuration value
     * @return the value it names
     * @throws IllegalArgumentException for any other value
     */
    public static GeneratedResponses parse(String value) {
        return switch (ProtocolPolicy.token(value)) {
            case "replaceable" -> REPLACEABLE;
            case "in_place" -> IN_PLACE;
            case "skip" -> SKIP;
            default -> throw new IllegalArgumentException(
                    "generated_responses must be replaceable, in_place or skip: " + value.strip());
        };
    }
}
