package io.github.mahmoudimus.quic.connection;

/**
 * How a client's Initial packets look on the wire, the parts of a browser's QUIC fingerprint they
 * make: the first packet number, how an Initial datagram is padded, and how the ClientHello's
 * CRYPTO data is laid out.
 *
 * @param firstPacketNumber the number of the first Initial packet, when not {@code randomFirstPacketNumber}
 * @param padToDatagramSize whether Initial datagrams are padded to the datagram size (the
 *     transport's {@code initialMtu}), not only to the 1200 bytes RFC 9000 requires
 * @param chaosProtection whether CRYPTO data is cut up and shuffled with PING and PADDING frames
 *     ({@link ChaosProtector}, Chrome's "chaos protection")
 * @param randomFirstPacketNumber whether the first packet number is random, as neqo (Firefox) makes
 *     it: 1 to 32, and one time in eight up to 1024 more
 * @param sniSlicing whether the ClientHello is cut in two at the middle of its server name and the
 *     halves sent in reverse order, spread over packets of about equal size (neqo's "SNI slicing")
 * @param padAfterPacket whether an Initial datagram is padded with zero bytes after its packets,
 *     as neqo pads it, rather than with PADDING frames inside the packet
 */
public record InitialPacketShape(long firstPacketNumber, boolean padToDatagramSize, boolean chaosProtection,
        boolean randomFirstPacketNumber, boolean sniSlicing, boolean padAfterPacket) {

    /**
     * Chrome 156's, as captured: packet numbers from 1, datagrams padded to their size (1250 bytes
     * with the transport's initial MTU set to 1250, as Chrome's is), chaos protection on.
     */
    public static final InitialPacketShape CHROME = new InitialPacketShape(1, true, true);

    /**
     * Firefox 159's (neqo), as captured: a random first packet number, SNI slicing, and datagrams
     * padded to their size (1252 bytes over IPv4) with zero bytes after the packet.
     */
    public static final InitialPacketShape FIREFOX = new InitialPacketShape(1, true, false, true, true, true);

    public InitialPacketShape {
        if (firstPacketNumber < 0) throw new IllegalArgumentException("first packet number " + firstPacketNumber);
    }

    /** A shape with a fixed first packet number, padded with PADDING frames, without SNI slicing. */
    public InitialPacketShape(long firstPacketNumber, boolean padToDatagramSize, boolean chaosProtection) {
        this(firstPacketNumber, padToDatagramSize, chaosProtection, false, false, false);
    }

    /**
     * The number of a connection's first Initial packet.
     *
     * @param random the source of a random one
     * @return the number
     */
    public long firstPacketNumber(java.util.random.RandomGenerator random) {
        if (!randomFirstPacketNumber) return firstPacketNumber;
        // neqo-transport's CryptoStates::init: a value from 0 to 31, plus 32 times a value from 0 to
        // 31 only when a second random byte is 224 or more, plus 1
        int r0 = random.nextInt(256);
        int r1 = random.nextInt(256);
        return (r0 & 0x1f) + ((long) Math.max(r1 - 224, 0) << 5) + 1;
    }
}
