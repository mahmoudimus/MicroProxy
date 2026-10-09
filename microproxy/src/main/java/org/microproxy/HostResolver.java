package org.microproxy;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;

/** Resolves server host names. */
@FunctionalInterface
public interface HostResolver {

    /**
     * Resolves a host name and associates it with the requested port.
     *
     * @param host the destination host name
     * @param port the destination port
     * @return the resolved destination socket address
     * @throws UnknownHostException if the host cannot be resolved
     */
    InetSocketAddress resolve(String host, int port) throws UnknownHostException;
}
