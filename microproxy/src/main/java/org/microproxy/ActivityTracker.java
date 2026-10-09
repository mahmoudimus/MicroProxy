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

    /**
     * Called when a TLS handshake failed or timed out, before the failure is handled.
     *
     * @param flowContext the client's context for a handshake with the client (the TLS listener or
     *     an intercepted session); for one with a server or a TLS chained proxy, a {@link
     *     FullFlowContext} naming it
     * @param clientSide whether the handshake was with the client
     * @param cause the handshake's error, e.g. an {@link javax.net.ssl.SSLHandshakeException} or a
     *     {@link java.net.SocketTimeoutException}
     */
    default void tlsHandshakeFailed(FlowContext flowContext, boolean clientSide, Throwable cause) {}

    default void clientDisconnected(FlowContext flowContext, SSLSession sslSession) {}

    default void bytesReceivedFromClient(FlowContext flowContext, int numberOfBytes) {}

    default void requestReceivedFromClient(FlowContext flowContext, HttpRequest httpRequest) {}

    default void bytesSentToServer(FullFlowContext flowContext, int numberOfBytes) {}

    default void requestSentToServer(FullFlowContext flowContext, HttpRequest httpRequest) {}

    default void bytesReceivedFromServer(FullFlowContext flowContext, int numberOfBytes) {}

    default void responseReceivedFromServer(FullFlowContext flowContext, HttpResponse httpResponse) {}

    default void bytesSentToClient(FlowContext flowContext, int numberOfBytes) {}

    default void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse) {}

    /**
     * Called when a response head has been sent to the client, with where the response came from.
     * The default calls {@link #responseSentToClient(FlowContext, HttpResponse)}, so override
     * one or the other. The status the server sent, if any, is {@link FlowContext#upstreamStatus()}.
     */
    default void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse, ResponseSource source) {
        responseSentToClient(flowContext, httpResponse);
    }

    /**
     * Called when the whole response to a request, body included, has been written to the client
     * (for a {@code CONNECT} or a protocol upgrade: once the response head has, before the tunnel
     * starts). {@link FlowContext#timings()} is complete then. Not called when the exchange is
     * abandoned half-way, e.g. because the server or the client failed.
     */
    default void responseCompleted(FlowContext flowContext, HttpResponse httpResponse) {}

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
