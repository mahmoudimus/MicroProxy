package org.microproxy;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;

/** Resolves server host names. */
@FunctionalInterface
public interface HostResolver {

    InetSocketAddress resolve(String host, int port) throws UnknownHostException;
}
