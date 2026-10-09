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

    /**
     * Called when the proxy accepts a client connection.
     *
     * @param flowContext the client connection or exchange context
     */
    default void clientConnected(FlowContext flowContext) {}

    /**
     * Called before the TLS handshake with the client starts.
     *
     * @param flowContext the client connection or exchange context
     */
    default void clientSSLHandshakeStarted(FlowContext flowContext) {}

    /**
     * Called after the TLS handshake with the client succeeds.
     *
     * @param flowContext the client connection or exchange context
     * @param sslSession the client TLS session, or {@code null} for a plaintext connection
     */
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

    /**
     * Called when the client connection closes.
     *
     * @param flowContext the client connection or exchange context
     * @param sslSession the client TLS session, or {@code null} for a plaintext connection
     */
    default void clientDisconnected(FlowContext flowContext, SSLSession sslSession) {}

    /**
     * Called after bytes are read from the client.
     *
     * @param flowContext the client connection or exchange context
     * @param numberOfBytes the number of bytes transferred
     */
    default void bytesReceivedFromClient(FlowContext flowContext, int numberOfBytes) {}

    /**
     * Called when a request head arrives from the client.
     *
     * @param flowContext the client connection or exchange context
     * @param httpRequest the request head
     */
    default void requestReceivedFromClient(FlowContext flowContext, HttpRequest httpRequest) {}

    /**
     * Called after bytes are written to the server.
     *
     * @param flowContext the server connection context
     * @param numberOfBytes the number of bytes transferred
     */
    default void bytesSentToServer(FullFlowContext flowContext, int numberOfBytes) {}

    /**
     * Called when a request head is sent to the server.
     *
     * @param flowContext the server connection context
     * @param httpRequest the request head
     */
    default void requestSentToServer(FullFlowContext flowContext, HttpRequest httpRequest) {}

    /**
     * Called after bytes are read from the server.
     *
     * @param flowContext the server connection context
     * @param numberOfBytes the number of bytes transferred
     */
    default void bytesReceivedFromServer(FullFlowContext flowContext, int numberOfBytes) {}

    /**
     * Called when a response head arrives from the server.
     *
     * @param flowContext the server connection context
     * @param httpResponse the response head
     */
    default void responseReceivedFromServer(FullFlowContext flowContext, HttpResponse httpResponse) {}

    /**
     * Called after bytes are written to the client.
     *
     * @param flowContext the client connection or exchange context
     * @param numberOfBytes the number of bytes transferred
     */
    default void bytesSentToClient(FlowContext flowContext, int numberOfBytes) {}

    /**
     * Called when a response head is sent to the client.
     *
     * @param flowContext the client connection or exchange context
     * @param httpResponse the response head
     */
    default void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse) {}

    /**
     * Called when a response head has been sent to the client, with where the response came from.
     * The default calls {@link #responseSentToClient(FlowContext, HttpResponse)}, so override
     * one or the other. The status the server sent, if any, is {@link FlowContext#upstreamStatus()}.
     *
     * @param flowContext the client connection or exchange context
     * @param httpResponse the response head
     * @param source where the response originated
     */
    default void responseSentToClient(FlowContext flowContext, HttpResponse httpResponse, ResponseSource source) {
        responseSentToClient(flowContext, httpResponse);
    }

    /**
     * Called when the whole response to a request, body included, has been written to the client
     * (for a {@code CONNECT} or a protocol upgrade: once the response head has, before the tunnel
     * starts). {@link FlowContext#timings()} is complete then. Not called when the exchange is
     * abandoned half-way, e.g. because the server or the client failed.
     *
     * @param flowContext the client connection or exchange context
     * @param httpResponse the response head
     */
    default void responseCompleted(FlowContext flowContext, HttpResponse httpResponse) {}

    /**
     * Called when the proxy connects to a server.
     *
     * @param flowContext the server connection context
     * @param serverAddress the connected server address
     */
    default void serverConnected(FullFlowContext flowContext, InetSocketAddress serverAddress) {}

    /**
     * Called when the server connection closes.
     *
     * @param flowContext the server connection context
     * @param serverAddress the connected server address
     */
    default void serverDisconnected(FullFlowContext flowContext, InetSocketAddress serverAddress) {}

    /**
     * Called when the client connection reaches its idle timeout.
     *
     * @param flowContext the client connection or exchange context
     */
    default void connectionTimedOut(FlowContext flowContext) {}

    /**
     * Called when something failed on the client side of a flow: client I/O errors, and
     * unexpected exceptions while serving the connection (which is then closed).
     *
     * @param flowContext the client connection or exchange context
     * @param cause the failure that triggered this event
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
     *
     * @param serverContext the server connection context
     * @param cause the failure that triggered this event
     */
    default void serverConnectionExceptionCaught(FullFlowContext serverContext, Throwable cause) {}
}
