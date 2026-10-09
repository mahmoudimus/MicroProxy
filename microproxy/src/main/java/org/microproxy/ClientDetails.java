package org.microproxy;

import java.net.InetSocketAddress;

/** What the proxy knows about a client: its address and, once authenticated, its user name. */
public final class ClientDetails {

    /** Creates client details with no address or authenticated user yet. */
    public ClientDetails() {}

    private volatile String userName;
    private volatile InetSocketAddress clientAddress;

    /** {@return the authenticated user name, or {@code null}} */
    public String getUserName() {
        return userName;
    }

    /**
     * Sets the authenticated user name.
     *
     * @param userName the authenticated user name, or {@code null} if unknown
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /** {@return the client socket address} */
    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    /**
     * Sets the client socket address.
     *
     * @param clientAddress the client socket address
     */
    public void setClientAddress(InetSocketAddress clientAddress) {
        this.clientAddress = clientAddress;
    }
}
