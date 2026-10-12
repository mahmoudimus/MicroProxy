package org.microproxy.quic;

/**
 * One stream of an intercepted QUIC connection, as a {@link QuicInterceptor} sees it: the
 * connection's details ({@link QuicContext}), which stream it is, who opened it, and a way to add
 * bytes. The same context is given to every hook call of the stream, so it can serve as a key for
 * per-stream state; {@link #connection()} is the key for per-connection state.
 */
public interface QuicStreamContext extends QuicContext {

    /**
     * The stream's ID on the client's connection (RFC 9000 section 2.1). Its two low bits say who
     * opened it and whether it is unidirectional.
     *
     * @return the client-side stream ID
     */
    long streamId();

    /**
     * The stream's ID on the proxy's connection to the server. Streams are opened on the other
     * connection in the order they arrive, so the two IDs are usually the same.
     *
     * @return the server-side stream ID
     */
    long serverStreamId();

    /**
     * Whether the stream is bidirectional; a unidirectional stream carries data only from the side
     * that opened it.
     *
     * @return true for a bidirectional stream
     */
    boolean bidirectional();

    /**
     * Whether the client opened the stream, rather than the server.
     *
     * @return true for a stream the client opened
     */
    boolean clientInitiated();

    /**
     * Adds bytes to the stream, as if one side had sent them: with {@code fromClient} they go to
     * the server, else to the client. They do not pass through {@link QuicInterceptor#streamData}.
     * Called from a {@code streamData} hook of the same direction, they follow that message (or
     * what replaced it); otherwise, from any hook or any thread while that direction is open, they
     * are written at once, between messages. The call may block while the destination's flow
     * control holds the data back.
     *
     * @param fromClient true to send to the server, false to send to the client
     * @param data the bytes, written as they are
     * @throws IllegalStateException if that direction has ended (finished, reset or stopped) or
     *     does not exist on a unidirectional stream
     * @throws NullPointerException if {@code data} is null
     */
    void send(boolean fromClient, byte[] data);
}
