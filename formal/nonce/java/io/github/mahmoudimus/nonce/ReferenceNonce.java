// Frozen pre-adoption implementation, copied from quic.PacketKey.nonce at
// main 30d7c3c. TEST ORACLE ONLY: this source is compiled by the formal nonce
// replay and is never part of the production quic artifact. It preserves the
// original clone/XOR algorithm so differential tests do not compare the
// generated implementation with itself.

package io.github.mahmoudimus.nonce;

/** Independent reference for the exact old PacketKey.nonce behavior. */
public final class ReferenceNonce {

    private ReferenceNonce() {}

    /**
     * The old nonce implementation: clone the IV, then XOR the last eight bytes with the
     * big-endian bytes of the full 64-bit packet number.
     */
    public static byte[] nonce(byte[] iv, long packetNumber) {
        byte[] nonce = iv.clone();
        for (int i = 0; i < 8; i++) {
            nonce[11 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        return nonce;
    }
}
