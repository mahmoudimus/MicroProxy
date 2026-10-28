package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The TLS 1.3 record layer over a byte stream (RFC 8446 section 5): plaintext records until a
 * direction has keys, then AEAD-protected {@code TLSCiphertext} with the real content type inside,
 * per-record nonces from the IV and a sequence number, and fragments of at most 2^14 bytes.
 *
 * <p>Before the read keys are set records come back as they are; afterwards only protected records
 * and the compatibility {@code change_cipher_spec} (appendix D.4) are accepted.
 */
final class TlsRecordLayer {

    static final int CHANGE_CIPHER_SPEC = 20;
    static final int ALERT = 21;
    static final int HANDSHAKE = 22;
    static final int APPLICATION_DATA = 23;
    static final int MAX_FRAGMENT = 1 << 14;
    private static final int MAX_CIPHERTEXT = MAX_FRAGMENT + 256;
    private static final int TAG_LENGTH = 16;
    /** In the error for bytes that are not a TLS record at all: the peer is not a TLS server. */
    static final String NOT_TLS = "not a TLS record";

    /** A record's content type and its (decrypted) content. */
    record Record(int type, byte[] fragment) {}

    /** One direction's keys and its sequence number. */
    private static final class Protection {
        final CipherSuite suite;
        final SecretKeySpec key;
        final byte[] iv;
        long sequence;

        Protection(CipherSuite suite, byte[] secret) {
            this.suite = suite;
            byte[] k = suite.hkdf().expandLabel(secret, "key", new byte[0], suite.keyLength());
            this.key = new SecretKeySpec(k, suite.aes() ? "AES" : "ChaCha20");
            this.iv = suite.hkdf().expandLabel(secret, "iv", new byte[0], 12);
        }

        Cipher cipher(int mode) throws GeneralSecurityException {
            byte[] nonce = iv.clone();
            for (int i = 0; i < 8; i++) nonce[nonce.length - 1 - i] ^= (byte) (sequence >>> (8 * i));
            sequence++;
            Cipher c = Cipher.getInstance(suite.aead());
            c.init(mode, key, suite.aes() ? new GCMParameterSpec(128, nonce) : new IvParameterSpec(nonce));
            return c;
        }
    }

    private final InputStream in;
    private final OutputStream out;
    private Protection read;
    private Protection write;
    private int plaintextVersion = 0x0301;
    private int maxFragment = MAX_FRAGMENT;

    TlsRecordLayer(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    /** Protects every record written from now on with keys derived from {@code secret}. */
    void writeKeys(CipherSuite suite, byte[] secret) {
        write = new Protection(suite, secret);
    }

    /** Expects every record read from now on to be protected with keys derived from {@code secret}. */
    void readKeys(CipherSuite suite, byte[] secret) {
        read = new Protection(suite, secret);
    }

    /**
     * The {@code legacy_record_version} of plaintext records: 0x0301 for a ClientHello (the default),
     * 0x0303 for the rest.
     */
    void plaintextVersion(int version) {
        plaintextVersion = version;
    }

    /** Writes records of at most {@code n} bytes of content from now on (RFC 8449). */
    void maxFragment(int n) {
        maxFragment = n;
    }

    /** Writes {@code data} as records of {@code type}, without flushing. */
    void write(int type, byte[] data) throws IOException {
        int off = 0;
        do {
            int n = Math.min(maxFragment, data.length - off);
            writeRecord(type, data, off, n);
            off += n;
        } while (off < data.length);
    }

    /**
     * Writes the compatibility {@code change_cipher_spec} record, which is never protected
     * (RFC 8446 appendix D.4).
     */
    void writeChangeCipherSpec() throws IOException {
        out.write(new byte[] {CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1});
    }

    void flush() throws IOException {
        out.flush();
    }

    private void writeRecord(int type, byte[] data, int off, int len) throws IOException {
        if (write == null) {
            out.write(new byte[] {(byte) type, (byte) (plaintextVersion >> 8), (byte) plaintextVersion,
                (byte) (len >> 8), (byte) len});
            out.write(data, off, len);
            return;
        }
        // TLSInnerPlaintext: the content, then its real type, with no padding
        byte[] inner = Arrays.copyOfRange(data, off, off + len + 1);
        inner[len] = (byte) type;
        int length = inner.length + TAG_LENGTH;
        byte[] header = {APPLICATION_DATA, 3, 3, (byte) (length >> 8), (byte) length};
        byte[] sealed;
        try {
            Cipher c = write.cipher(Cipher.ENCRYPT_MODE);
            c.updateAAD(header);
            sealed = c.doFinal(inner);
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot protect a TLS record", e);
        }
        out.write(header);
        out.write(sealed);
    }

    /**
     * The next record, decrypted, or null if the stream ends between records.
     *
     * @throws EOFException if the stream ends inside a record
     * @throws QuicException with the alert to send for a record that is too long, does not
     *     decrypt, or is unprotected after the read keys are set
     */
    Record read() throws IOException, QuicException {
        int first = in.read();
        if (first < 0) return null;
        byte[] header = new byte[5];
        header[0] = (byte) first;
        readFully(header, 1, 4);
        int type = header[0] & 0xff;
        if (type < CHANGE_CIPHER_SPEC || type > APPLICATION_DATA || header[1] != 3) {
            throw TlsAlert.unexpectedMessage(NOT_TLS + " (it starts 0x" + HexFormat.of().formatHex(header) + ")");
        }
        int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
        int limit = read != null && type == APPLICATION_DATA ? MAX_CIPHERTEXT : MAX_FRAGMENT;
        if (length > limit) {
            throw TlsAlert.error(TlsAlert.RECORD_OVERFLOW, "a record of " + length + " bytes");
        }
        byte[] fragment = new byte[length];
        readFully(fragment, 0, length);
        if (read == null) return new Record(type, fragment);
        if (type == CHANGE_CIPHER_SPEC) return new Record(type, fragment);
        if (type != APPLICATION_DATA) {
            throw TlsAlert.unexpectedMessage("an unprotected record of type " + type + " after the keys");
        }
        byte[] inner;
        try {
            Cipher c = read.cipher(Cipher.DECRYPT_MODE);
            c.updateAAD(header);
            inner = c.doFinal(fragment);
        } catch (AEADBadTagException e) {
            throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record does not decrypt");
        } catch (GeneralSecurityException e) {
            throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record does not decrypt: " + e.getMessage());
        }
        int end = inner.length - 1;
        while (end >= 0 && inner[end] == 0) end--;
        if (end < 0) throw TlsAlert.unexpectedMessage("a protected record with no content type");
        if (end > MAX_FRAGMENT) {
            throw TlsAlert.error(TlsAlert.RECORD_OVERFLOW, "a protected record of " + end + " bytes");
        }
        return new Record(inner[end] & 0xff, Arrays.copyOf(inner, end));
    }

    private void readFully(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n < 0) throw new EOFException("the connection closed inside a TLS record");
            off += n;
            len -= n;
        }
    }
}
