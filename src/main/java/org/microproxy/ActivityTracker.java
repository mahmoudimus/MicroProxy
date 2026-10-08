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

    default void connectionExceptionCaught(FlowContext flowContext, Throwable cause) {}
}
