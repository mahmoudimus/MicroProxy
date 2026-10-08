package org.microproxy;

/** Validates {@code Proxy-Authorization: Basic} credentials. */
public interface ProxyAuthenticator {

    boolean authenticate(String userName, String password);

    /** The realm advertised in {@code Proxy-Authenticate}; {@code null} for the default. */
    default String getRealm() {
        return null;
    }
}
