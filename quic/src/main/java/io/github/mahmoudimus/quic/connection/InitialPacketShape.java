package io.github.mahmoudimus.quic.connection;

/**
 * How a client's Initial packets look on the wire, the parts of a browser's QUIC fingerprint they
 * make: the first packet number, whether an Initial datagram is padded to the full datagram size
 * (the transport's {@code initialMtu}) or only to the 1200 bytes RFC 9000 requires, and whether
 * the frames of a packet that carries the ClientHello are laid out at random ({@link
 * ChaosProtector}, Chrome's "chaos protection").
 *
 * @param firstPacketNumber the number of the first Initial packet
 * @param padToDatagramSize whether Initial datagrams are padded to the datagram size
 * @param chaosProtection whether CRYPTO data is cut up and shuffled with PING and PADDING frames
 */
public record InitialPacketShape(long firstPacketNumber, boolean padToDatagramSize, boolean chaosProtection) {

    /**
     * Chrome 156's, as captured: packet numbers from 1, datagrams padded to their size (1250 bytes
     * with the transport's initial MTU set to 1250, as Chrome's is), chaos protection on.
     */
    public static final InitialPacketShape CHROME = new InitialPacketShape(1, true, true);

    public InitialPacketShape {
        if (firstPacketNumber < 0) throw new IllegalArgumentException("first packet number " + firstPacketNumber);
    }
}
