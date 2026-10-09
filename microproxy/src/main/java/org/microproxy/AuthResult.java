package org.microproxy;

import org.microproxy.http.HttpResponse;

/** What a {@link ProxyAuthenticator} decided about a request. */
public sealed interface AuthResult {

    /**
     * The client may use the proxy.
     *
     * @param userName who the client is, for {@link ClientDetails#getUserName()}; may be {@code
     *     null}
     */
    record Accepted(String userName) implements AuthResult {}

    /**
     * The client may not use the proxy.
     *
     * @param challenge the answer, typically {@code 407} with a {@code Proxy-Authenticate} header,
     *     or {@code 403}; {@code null} for the proxy's default {@code 407} with {@code
     *     Proxy-Authenticate: Basic realm="..."} ({@link ProxyAuthenticator#getRealm()}). Return
     *     a new response each time: the proxy adjusts its headers before sending it.
     */
    record Rejected(HttpResponse challenge) implements AuthResult {}

    static AuthResult accept(String userName) {
        return new Accepted(userName);
    }

    /** Rejects with the proxy's default {@code 407} challenge. */
    static AuthResult reject() {
        return new Rejected(null);
    }

    /** Rejects with {@code challenge}; see {@link Rejected}. */
    static AuthResult reject(HttpResponse challenge) {
        return new Rejected(challenge);
    }
}
