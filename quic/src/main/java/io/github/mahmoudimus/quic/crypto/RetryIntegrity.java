/*
 * Ported from quinn-proto src/crypto/rustls.rs (retry_tag and is_valid_retry) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.crypto;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicVersion;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The Retry Integrity Tag (RFC 9001 section 5.8, RFC 9369 section 3.3.3): AES-128-GCM with a
 * fixed per-version key and nonce over the Retry pseudo-packet, which is the original Destination
 * Connection ID (with its length byte) followed by the Retry packet without its tag.
 *
 * <p>All methods are static and thread-safe; each call makes its own {@link Cipher}.
 */
public final class RetryIntegrity {

    /** The tag length in bytes. */
    public static final int TAG_LENGTH = 16;

    private RetryIntegrity() {}

    /**
     * Computes the tag of a Retry packet.
     *
     * @param version the version of the Retry packet
     * @param originalDestinationId the Destination Connection ID of the client's Initial
     * @param retryWithoutTag the Retry packet up to its tag, between position and limit; the
     *     buffer is not changed
     * @return the 16-byte tag
     */
    public static byte[] tag(QuicVersion version, ConnectionId originalDestinationId, ByteBuffer retryWithoutTag) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(version.retryIntegrityKey(), "AES"),
                    new GCMParameterSpec(TAG_LENGTH * 8, version.retryIntegrityNonce()));
            cipher.updateAAD(new byte[] {(byte) originalDestinationId.length()});
            cipher.updateAAD(originalDestinationId.toByteArray());
            cipher.updateAAD(retryWithoutTag.duplicate());
            return cipher.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JDK lacks AES-GCM", e);
        }
    }

    /**
     * Computes the tag of a Retry packet held in an array.
     *
     * @param version the version of the Retry packet
     * @param originalDestinationId the Destination Connection ID of the client's Initial
     * @param packet the array
     * @param offset the first byte of the Retry packet
     * @param length the length of the Retry packet without its tag
     * @return the 16-byte tag
     */
    public static byte[] tag(QuicVersion version, ConnectionId originalDestinationId, byte[] packet, int offset, int length) {
        return tag(version, originalDestinationId, ByteBuffer.wrap(packet, offset, length));
    }

    /**
     * Checks the tag at the end of a received Retry packet, in constant time.
     *
     * @param version the version of the Retry packet
     * @param originalDestinationId the Destination Connection ID the client sent in its Initial
     * @param retryPacket the whole Retry packet, tag included, between position and limit; the
     *     buffer is not changed
     * @return true if the tag is valid
     */
    public static boolean verify(QuicVersion version, ConnectionId originalDestinationId, ByteBuffer retryPacket) {
        int len = retryPacket.remaining();
        if (len < TAG_LENGTH) {
            return false;
        }
        int tagStart = retryPacket.position() + len - TAG_LENGTH;
        byte[] expected = tag(version, originalDestinationId, retryPacket.duplicate().limit(tagStart));
        byte[] actual = new byte[TAG_LENGTH];
        retryPacket.get(tagStart, actual);
        return MessageDigest.isEqual(expected, actual);
    }
}
