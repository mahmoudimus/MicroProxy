package org.microproxy;

import java.net.InetSocketAddress;

/** What the proxy knows about a client: its address and, once authenticated, its user name. */
public final class ClientDetails {

    private volatile String userName;
    private volatile InetSocketAddress clientAddress;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public InetSocketAddress getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(InetSocketAddress clientAddress) {
        this.clientAddress = clientAddress;
    }
}
