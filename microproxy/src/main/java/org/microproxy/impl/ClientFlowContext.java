package org.microproxy.impl;

import java.net.InetSocketAddress;
import java.util.OptionalInt;
import java.util.function.Supplier;
import javax.net.ssl.SSLSession;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;

/**
 * The context of one client connection, which also records the exchange in progress (exchanges on
 * a connection run one at a time). {@link org.microproxy.FullFlowContext}s made from it read the
 * same record.
 */
final class ClientFlowContext extends FlowContext {

    // Written on the connection's thread; trackers on other threads may see a slightly stale value.
    /** Status of the server's final response for the current exchange; 0 for none. */
    private int upstreamStatus;

    ClientFlowContext(
            long connectionId,
            Supplier<InetSocketAddress> clientAddress,
            Supplier<SSLSession> clientSslSession,
            ClientDetails clientDetails) {
        super(connectionId, clientAddress, clientSslSession, clientDetails);
    }

    /** Forgets the previous exchange: a new request has started. */
    void startExchange() {
        upstreamStatus = 0;
    }

    void upstreamStatus(int status) {
        upstreamStatus = status;
    }

    @Override
    public OptionalInt upstreamStatus() {
        int status = upstreamStatus;
        return status == 0 ? OptionalInt.empty() : OptionalInt.of(status);
    }
}
