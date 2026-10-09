package org.microproxy;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Base64;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpRequest;

/**
 * Decides which clients may use the proxy. By default it validates {@code Proxy-Authorization:
 * Basic} credentials with {@link #authenticate(String, String)}; override {@link
 * #authenticate(HttpRequest, FlowContext)} for other schemes (Bearer tokens, API keys, ...) or
 * other answers.
 *
 * <p>Whatever the scheme, the proxy removes {@code Proxy-Authorization} from every request before
 * filters see it, so credentials are never forwarded.
 */
public interface ProxyAuthenticator {

    /**
     * Validates Basic credentials (for the default {@link #authenticate(HttpRequest, FlowContext)}).
     *
     * @param userName the authenticated user name, or {@code null} if unknown
     * @param password the client password
     * @return whether the credentials are accepted
     */
    boolean authenticate(String userName, String password);

    /** {@return the realm advertised in the default {@code Proxy-Authenticate}; {@code null} for the default} */
    default String getRealm() {
        return null;
    }

    /**
     * Decides whether {@code request} may proceed, and as which user. It sees the requests a client
     * sends to the proxy: plain requests and CONNECTs, not the requests inside an intercepted
     * session (they carry no proxy credentials; the session's CONNECT was authenticated). Unless
     * {@link #authenticateEveryRequest()}, only until one is accepted on each client connection.
     *
     * <p>The accepted user name becomes {@link ClientDetails#getUserName()}, which filters,
     * trackers and the {@link ChainedProxyManager} see. It runs on the client connection's thread
     * and may block, e.g. to ask an identity service.
     *
     * <p>The default reads {@code Proxy-Authorization: Basic}: it accepts the user when {@link
     * #authenticate(String, String)} agrees, and rejects with the default challenge otherwise
     * (without asking when the credentials are missing or malformed).
     *
     * @param flow the client connection, with its address and TLS session
     * @return {@link AuthResult#accept}, or {@link AuthResult#reject} with the answer to send
     *
     * @param request the request being handled
     */
    default AuthResult authenticate(HttpRequest request, FlowContext flow) {
        String value = request.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION);
        if (value == null) {
            return AuthResult.reject();
        }
        value = value.strip();
        if (!value.regionMatches(true, 0, "Basic ", 0, 6)) {
            return AuthResult.reject();
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(value.substring(6).strip()), UTF_8);
        } catch (IllegalArgumentException e) {
            return AuthResult.reject();
        }
        int colon = decoded.indexOf(':');
        if (colon < 0) {
            return AuthResult.reject();
        }
        String user = decoded.substring(0, colon);
        return authenticate(user, decoded.substring(colon + 1)) ? AuthResult.accept(user) : AuthResult.reject();
    }

    /**
     * Whether to authenticate every request rather than the first one accepted on each client
     * connection, e.g. because tokens expire. Requests inside an intercepted session are still
     * covered by their CONNECT. Off by default.
     *
     * @return whether to authenticate every request rather than the first one accepted on each client connection, e.g. because tokens expire
     */
    default boolean authenticateEveryRequest() {
        return false;
    }
}
