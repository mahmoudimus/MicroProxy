package org.microproxy;

import java.net.InetSocketAddress;
import javax.net.ssl.SSLSession;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Observes proxy activity, e.g. for metrics or access logs. Callbacks run on the connection's
 * virtual thread and should be quick; every method has a no-op default.
 */
public interface ActivityTracker {

    default void clientConnected(FlowContext flowContext) {}

    default void clientSSLHandshakeStarted(FlowContext flowContext) {}

    default void clientSSLHandshakeSucceeded(FlowContext flowContext, SSLSession sslSession) {}

    default void clientDisconnected(FlowContext flowContext, SSLSession sslSession) {}

    default void bytesReceivedFromClient(FlowContext flowContext, int numberOfBytes) {}

    default void requestReceivedFromClient(FlowContext flowContext, HttpRequest httpRequest) {}

    default void bytesSentToServer(FullFlowContext flowContext, int numberOfBytes) {}

    default void requestSentToServer(FullFlowContext flowContext, HttpRequest httpRequest) {}

    default void bytesReceivedFromServer(FullFlowContext flowContext, int numberOfBytes) {}

    default void responseReceivedFromServer(FullFlowContext flowContext, HttpResponse httpResponse) {}

    default void bytesSentToClient(FlowContext flowContext, int numberOfBytes) {}

    default void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse) {}

    default void serverConnected(FullFlowContext flowContext, InetSocketAddress serverAddress) {}

    default void serverDisconnected(FullFlowContext flowContext, InetSocketAddress serverAddress) {}

    default void connectionTimedOut(FlowContext flowContext) {}

    /**
     * Called when something failed on the client side of a flow: client I/O errors, and
     * unexpected exceptions while serving the connection (which is then closed).
     */
    default void connectionExceptionCaught(FlowContext flowContext, Throwable cause) {}

    /**
     * Called once for each failure on the server side of a flow: a failed connection attempt
     * (unresolved name, refused or timed-out connect, failed TLS handshake, a chained proxy that
     * refused; with several chained proxies, once per proxy tried), a server that timed out or
     * answered badly, or an unexpected exception while a server connection was in use (also
     * reported to {@link #connectionExceptionCaught}, as the client connection closes too).
     * {@code serverContext} names the server or chained proxy; its remote address is {@code null}
     * when the name did not resolve. A keep-alive connection that turned out to be closed, and is
     * retried transparently, is not reported.
     */
    default void serverConnectionExceptionCaught(FullFlowContext serverContext, Throwable cause) {}
}
