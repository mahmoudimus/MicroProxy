package org.microproxy;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

/** Resolves host names with {@link InetAddress#getByName}. */
public class DefaultHostResolver implements HostResolver {

    /** Creates a resolver using the JDK host-name lookup facilities. */
    public DefaultHostResolver() {}

    @Override
    public InetSocketAddress resolve(String host, int port) throws UnknownHostException {
        return new InetSocketAddress(InetAddress.getByName(host), port);
    }
}
