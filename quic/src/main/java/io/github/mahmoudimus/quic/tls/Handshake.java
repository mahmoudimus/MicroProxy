// Ported from rustls src/conn.rs (State / StateMachine: one handshake message in, the next state
// out) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;

/** One side's handshake state machine, fed whole messages by its {@link TlsSession}. */
sealed interface Handshake permits ClientHandshake, ServerHandshake {

    /**
     * Processes the next message from the peer.
     *
     * @param message the decoded message
     * @param raw the whole encoded message, header included, as it enters the transcript
     */
    void handle(HandshakeMessage message, byte[] raw) throws QuicException;
}
