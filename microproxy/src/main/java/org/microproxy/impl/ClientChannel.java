package org.microproxy.impl;

import java.io.IOException;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;

/**
 * The client side of an exchange: how the request's body arrives and how the response goes back,
 * whatever the protocol between the client and the proxy.
 *
 * <p>The exchange logic in {@link ClientConnection} (filters, authentication, routing, server
 * connections and retries, the cache, failure answers, trackers and timings) talks to the client
 * only through this interface, so the same logic can serve any transport that carries requests:
 *
 * <ul>
 *   <li>{@link Http1ClientChannel}: an HTTP/1.x connection, which carries its exchanges one after
 *       another and so serves them all through one channel.
 *   <li>A future HTTP/2 stream: one channel per stream, many at once on one connection.
 * </ul>
 *
 * <p>The methods are called in exchange order: {@link #requestBody} once the request head has been
 * read; then interim responses; then the final response's head is adapted ({@link #adaptFraming},
 * then {@link #setKeepAlive} or {@link #setUpgrade}) before the {@code proxyToClientResponse}
 * filters see it; then it is written, either at once ({@link #writeComplete}) or as a head ({@link
 * #writeHead}) followed by its body ({@link #writeContent} pieces, or {@link #writeData} bytes
 * ending with {@link #writeEnd}). Write failures surface as {@link IOException}s, which the
 * exchange logic treats as the client having gone away.
 */
interface ClientChannel {

    /** The record of the exchange in progress: its timings and upstream status, for trackers and filters. */
    ClientFlowContext flowContext();

    // ---------------------------------------------------------------------------------------
    // The request
    // ---------------------------------------------------------------------------------------

    /**
     * Starts the exchange for {@code request}, whose head the client has just sent, and returns
     * its body as it arrives.
     *
     * @throws HttpParseException if the request's framing is invalid (HTTP/1: conflicting or
     *     malformed {@code Content-Length} / {@code Transfer-Encoding}); answer with {@link #reject}
     */
    MessageBody requestBody(HttpRequest request) throws HttpParseException;

    /**
     * Whether the client wants its connection kept after {@code request}: for HTTP/1, its version
     * and {@code Connection} / {@code Proxy-Connection} fields; always for a stream of a
     * multiplexed connection.
     */
    boolean clientKeepAlive(HttpRequest request);

    /**
     * Waits until {@link System#nanoTime()} reaches {@code deadline}, unless the client goes away
     * first (then throws {@link ClientConnection.ClientFailure}). Request bytes that arrive
     * meanwhile stay buffered.
     */
    void awaitUnlessClientLeaves(long deadline) throws IOException;

    // ---------------------------------------------------------------------------------------
    // Interim responses
    // ---------------------------------------------------------------------------------------

    /** Tells a client that sent {@code Expect: 100-continue} to send the body. */
    void writeContinue() throws IOException;

    /**
     * Forwards an informational (1xx, other than 101) response from the server, or drops it if
     * the client cannot receive one (HTTP/1.0).
     */
    void writeInformational(HttpResponse response) throws IOException;

    // ---------------------------------------------------------------------------------------
    // The final response's head, before proxyToClientResponse sees it
    // ---------------------------------------------------------------------------------------

    /**
     * Makes {@code response}'s head say how this transport delimits its body. For HTTP/1: a body
     * the server ends by closing its connection is re-chunked; a chunked body is de-chunked for
     * HTTP/1.0 clients, which then learn its end from the connection closing; and a chunked
     * response is labelled HTTP/1.1.
     *
     * @param streamed whether a body follows the head piece by piece (it may have one, is not a
     *     {@link FullHttpMessage}, and the connection is not switching protocols)
     * @return whether the client connection must close after the response, to end its body
     */
    boolean adaptFraming(HttpResponse response, boolean streamed);

    /**
     * Marks in {@code response} whether the client connection persists after it (HTTP/1: {@code
     * Connection: keep-alive} or {@code close}).
     */
    void setKeepAlive(HttpResponse response, boolean keepAlive);

    /** Marks {@code response} (a {@code 101}) as switching the connection to {@code upgrade}. */
    void setUpgrade(HttpResponse response, String upgrade);

    // ---------------------------------------------------------------------------------------
    // Writing the response
    // ---------------------------------------------------------------------------------------

    /**
     * Writes a response head; a {@link FullHttpMessage} is written with its body.
     *
     * @param bodyAllowed false for responses that never carry a body (to HEAD, 1xx, 204, 304, a
     *     CONNECT's 2xx)
     */
    void writeHead(HttpResponse response, boolean bodyAllowed) throws IOException;

    /**
     * Writes a response that has nothing more to follow: a {@link FullHttpMessage} with its body,
     * or a bare head, which is given an empty body.
     */
    void writeComplete(HttpResponse response, boolean bodyAllowed) throws IOException;

    /** Writes a body piece; a {@link org.microproxy.http.LastHttpContent} ends the body. */
    void writeContent(HttpContent content) throws IOException;

    /** Writes body bytes (the fast path for bodies no filter inspects); {@link #writeEnd} ends them. */
    void writeData(byte[] data, int off, int len) throws IOException;

    /** Sends what has been written so far. */
    void flush() throws IOException;

    /** Ends a body written with {@link #writeData}, with {@code trailers}, and flushes. */
    void writeEnd(HttpHeaders trailers) throws IOException;

    // ---------------------------------------------------------------------------------------
    // Ending
    // ---------------------------------------------------------------------------------------

    /**
     * Relays bytes both ways between the client and {@code server} until both sides are done, for
     * a {@code CONNECT} tunnel or a connection that switched protocols, parsing WebSocket frames
     * for {@code frames} when it is non-null. The client connection is used up afterwards.
     */
    void relay(ServerConnection server, Tunnel.FrameHandler frames, String name);

    /** Answers a request that cannot be served with a plain {@code status} error, then {@link #close}s. */
    void reject(HttpResponseStatus status);

    /**
     * Ends the client connection (for a stream of a multiplexed connection, the stream): after a
     * response that leaves it unusable, or when the exchange is abandoned.
     */
    void close();
}
