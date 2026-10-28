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

    /** One direction's protection and its sequence number. */
    private abstract static sealed class Protection permits Tls13, Tls12Aead, Tls12Cbc {
        long sequence;

        /** The protected record, header included, for {@code len} bytes of {@code type}. */
        abstract byte[] seal(int type, byte[] data, int off, int len) throws GeneralSecurityException;

        /** The content of a protected record, or the alert to send. */
        abstract Record open(byte[] header, byte[] fragment) throws QuicException;

        /** Whether a record of {@code type} arriving under this protection must be protected. */
        abstract boolean protects(int type);

        byte[] sequenceBytes() {
            byte[] s = new byte[8];
            for (int i = 0; i < 8; i++) s[7 - i] = (byte) (sequence >>> (8 * i));
            return s;
        }

        static byte[] header(int type, int length) {
            return new byte[] {(byte) type, 3, 3, (byte) (length >> 8), (byte) length};
        }
    }

    /** TLS 1.3: AEAD with the real type inside, nonces from the IV and the sequence number. */
    private static final class Tls13 extends Protection {
        final CipherSuite suite;
        final SecretKeySpec key;
        final byte[] iv;

        Tls13(CipherSuite suite, byte[] secret) {
            this.suite = suite;
            byte[] k = suite.hkdf().expandLabel(secret, "key", new byte[0], suite.keyLength());
            this.key = new SecretKeySpec(k, suite.aes() ? "AES" : "ChaCha20");
            this.iv = suite.hkdf().expandLabel(secret, "iv", new byte[0], 12);
        }

        Cipher cipher(int mode) throws GeneralSecurityException {
            byte[] nonce = iv.clone();
            byte[] seq = sequenceBytes();
            for (int i = 0; i < 8; i++) nonce[4 + i] ^= seq[i];
            sequence++;
            Cipher c = Cipher.getInstance(suite.aead());
            c.init(mode, key, suite.aes() ? new GCMParameterSpec(128, nonce) : new IvParameterSpec(nonce));
            return c;
        }

        @Override
        byte[] seal(int type, byte[] data, int off, int len) throws GeneralSecurityException {
            // TLSInnerPlaintext: the content, then its real type, with no padding
            byte[] inner = Arrays.copyOfRange(data, off, off + len + 1);
            inner[len] = (byte) type;
            byte[] header = header(APPLICATION_DATA, inner.length + TAG_LENGTH);
            Cipher c = cipher(Cipher.ENCRYPT_MODE);
            c.updateAAD(header);
            return concat(header, c.doFinal(inner));
        }

        @Override
        Record open(byte[] header, byte[] fragment) throws QuicException {
            byte[] inner;
            try {
                Cipher c = cipher(Cipher.DECRYPT_MODE);
                c.updateAAD(header);
                inner = c.doFinal(fragment);
            } catch (GeneralSecurityException e) {
                throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record does not decrypt");
            }
            int end = inner.length - 1;
            while (end >= 0 && inner[end] == 0) end--;
            if (end < 0) throw TlsAlert.unexpectedMessage("a protected record with no content type");
            if (end > MAX_FRAGMENT) throw TlsAlert.error(TlsAlert.RECORD_OVERFLOW, "a protected record of " + end + " bytes");
            return new Record(inner[end] & 0xff, Arrays.copyOf(inner, end));
        }

        @Override
        boolean protects(int type) {
            // only the compatibility change_cipher_spec comes unprotected
            return type != CHANGE_CIPHER_SPEC;
        }
    }

    /**
     * TLS 1.2 AEAD (RFC 5288, RFC 7905): AES-GCM with the 4-byte implicit IV and an 8-byte explicit
     * nonce, the sequence number, sent before the ciphertext; ChaCha20-Poly1305 with the IV XORed
     * with the sequence number. The additional data is the sequence number, type, version and
     * plaintext length.
     */
    private static final class Tls12Aead extends Protection {
        final boolean gcm;
        final SecretKeySpec key;
        final byte[] iv;

        Tls12Aead(Tls12CipherSuite suite, byte[] key, byte[] iv) {
            this.gcm = suite.bulk != Tls12CipherSuite.Bulk.CHACHA20_POLY1305;
            this.key = new SecretKeySpec(key, gcm ? "AES" : "ChaCha20");
            this.iv = iv.clone();
        }

        private Cipher cipher(int mode, byte[] nonce) throws GeneralSecurityException {
            Cipher c = Cipher.getInstance(gcm ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
            c.init(mode, key, gcm ? new GCMParameterSpec(128, nonce) : new IvParameterSpec(nonce));
            return c;
        }

        private byte[] nonce(byte[] explicit) {
            if (gcm) return concat(iv, explicit);
            byte[] n = iv.clone();
            for (int i = 0; i < 8; i++) n[4 + i] ^= explicit[i];
            return n;
        }

        private byte[] aad(byte[] seq, int type, int length) {
            byte[] aad = Arrays.copyOf(seq, 13);
            aad[8] = (byte) type;
            aad[9] = 3;
            aad[10] = 3;
            aad[11] = (byte) (length >> 8);
            aad[12] = (byte) length;
            return aad;
        }

        @Override
        byte[] seal(int type, byte[] data, int off, int len) throws GeneralSecurityException {
            byte[] seq = sequenceBytes();
            sequence++;
            Cipher c = cipher(Cipher.ENCRYPT_MODE, nonce(seq));
            c.updateAAD(aad(seq, type, len));
            byte[] sealed = c.doFinal(data, off, len);
            byte[] body = gcm ? concat(seq, sealed) : sealed;
            return concat(header(type, body.length), body);
        }

        @Override
        Record open(byte[] header, byte[] fragment) throws QuicException {
            int explicit = gcm ? 8 : 0;
            if (fragment.length < explicit + TAG_LENGTH) throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record too short to decrypt");
            byte[] seq = sequenceBytes();
            sequence++;
            byte[] nonce = nonce(gcm ? Arrays.copyOf(fragment, 8) : seq);
            int type = header[0] & 0xff;
            try {
                Cipher c = cipher(Cipher.DECRYPT_MODE, nonce);
                c.updateAAD(aad(seq, type, fragment.length - explicit - TAG_LENGTH));
                return new Record(type, c.doFinal(fragment, explicit, fragment.length - explicit));
            } catch (GeneralSecurityException e) {
                throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record does not decrypt");
            }
        }

        @Override
        boolean protects(int type) {
            return true;
        }
    }

    /**
     * TLS 1.2 AES-CBC with HMAC-SHA1, MAC then encrypt (RFC 5246 section 6.2.3.2): a random explicit
     * IV per record, the MAC over the sequence number, header and content, and padding. The padding
     * and MAC are checked without branching on the padding, as Go's crypto/tls does (conn.go
     * extractPadding).
     */
    private static final class Tls12Cbc extends Protection {
        final SecretKeySpec key;
        final SecretKeySpec macKey;
        final java.security.SecureRandom random;

        Tls12Cbc(byte[] key, byte[] macKey, java.security.SecureRandom random) {
            this.key = new SecretKeySpec(key, "AES");
            this.macKey = new SecretKeySpec(macKey, "HmacSHA1");
            this.random = random;
        }

        private byte[] mac(byte[] seq, int type, byte[] data, int off, int len) throws GeneralSecurityException {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(macKey);
            mac.update(seq);
            mac.update(header(type, len));
            mac.update(data, off, len);
            return mac.doFinal();
        }

        @Override
        byte[] seal(int type, byte[] data, int off, int len) throws GeneralSecurityException {
            byte[] seq = sequenceBytes();
            sequence++;
            byte[] mac = mac(seq, type, data, off, len);
            int unpadded = len + mac.length + 1;
            int padding = (16 - unpadded % 16) % 16;
            byte[] plain = new byte[unpadded + padding];
            System.arraycopy(data, off, plain, 0, len);
            System.arraycopy(mac, 0, plain, len, mac.length);
            Arrays.fill(plain, len + mac.length, plain.length, (byte) padding);
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] body = concat(iv, c.doFinal(plain));
            return concat(header(type, body.length), body);
        }

        @Override
        Record open(byte[] header, byte[] fragment) throws QuicException {
            byte[] seq = sequenceBytes();
            sequence++;
            if (fragment.length % 16 != 0 || fragment.length < 16 + 32) {
                throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a CBC record of " + fragment.length + " bytes");
            }
            byte[] plain;
            try {
                Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
                c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(fragment, 0, 16));
                plain = c.doFinal(fragment, 16, fragment.length - 16);
            } catch (GeneralSecurityException e) {
                throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record does not decrypt");
            }
            int paddingLength = plain[plain.length - 1] & 0xff;
            int good = paddingGood(plain, paddingLength);
            int toRemove = (paddingLength + 1) & good;
            int contentLength = plain.length - 20 - toRemove;
            contentLength = contentLength < 0 ? 0 : contentLength;
            byte[] expected;
            try {
                expected = mac(seq, header[0] & 0xff, plain, 0, contentLength);
            } catch (GeneralSecurityException e) {
                throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "HMAC-SHA1: " + e.getMessage());
            }
            byte[] received = Arrays.copyOfRange(plain, contentLength, contentLength + 20);
            boolean macGood = java.security.MessageDigest.isEqual(expected, received);
            if (!macGood || good != -1) throw TlsAlert.error(TlsAlert.BAD_RECORD_MAC, "a record does not decrypt");
            return new Record(header[0] & 0xff, Arrays.copyOf(plain, contentLength));
        }

        /**
         * -1 if the last {@code paddingLength + 1} bytes of {@code plain} all equal {@code
         * paddingLength} and fit in it, 0 otherwise, computed with masks only (Go's extractPadding).
         */
        private static int paddingGood(byte[] plain, int paddingLength) {
            int good = ~((plain.length - 1 - paddingLength) >> 31) & 0xff;
            int check = Math.min(256, plain.length);
            for (int i = 0; i < check; i++) {
                int inPadding = ~((paddingLength - i) >> 31) & 0xff; // 0xff while i <= paddingLength
                int b = plain[plain.length - 1 - i] & 0xff;
                good &= ~(inPadding & (paddingLength ^ b)) & 0xff;
            }
            good &= (good << 4) & 0xff;
            good &= (good << 2) & 0xff;
            good &= (good << 1) & 0xff;
            return ((byte) good) >> 7;
        }

        @Override
        boolean protects(int type) {
            return true;
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
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

    /** Protects every record written from now on with TLS 1.3 keys derived from {@code secret}. */
    void writeKeys(CipherSuite suite, byte[] secret) {
        write = new Tls13(suite, secret);
    }

    /** Expects every record read from now on to be protected with TLS 1.3 keys derived from {@code secret}. */
    void readKeys(CipherSuite suite, byte[] secret) {
        read = new Tls13(suite, secret);
    }

    /** Protects every record written from now on with TLS 1.2 {@code suite}'s keys. */
    void writeKeys12(Tls12CipherSuite suite, byte[] macKey, byte[] key, byte[] iv, java.security.SecureRandom random) {
        write = suite.bulk.cbc() ? new Tls12Cbc(key, macKey, random) : new Tls12Aead(suite, key, iv);
    }

    /** Expects every record read from now on to be protected with TLS 1.2 {@code suite}'s keys. */
    void readKeys12(Tls12CipherSuite suite, byte[] macKey, byte[] key, byte[] iv) {
        read = suite.bulk.cbc() ? new Tls12Cbc(key, macKey, null) : new Tls12Aead(suite, key, iv);
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
        try {
            out.write(write.seal(type, data, off, len));
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot protect a TLS record", e);
        }
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
        boolean protectedRecord = read != null && read.protects(type);
        int limit = protectedRecord ? MAX_CIPHERTEXT + 2048 : MAX_FRAGMENT;
        if (length > limit) {
            throw TlsAlert.error(TlsAlert.RECORD_OVERFLOW, "a record of " + length + " bytes");
        }
        byte[] fragment = new byte[length];
        readFully(fragment, 0, length);
        if (!protectedRecord) return new Record(type, fragment);
        if (read instanceof Tls13 && type != APPLICATION_DATA) {
            throw TlsAlert.unexpectedMessage("an unprotected record of type " + type + " after the keys");
        }
        Record record = read.open(header, fragment);
        if (record.fragment().length > MAX_FRAGMENT) {
            throw TlsAlert.error(TlsAlert.RECORD_OVERFLOW, "a protected record of " + record.fragment().length + " bytes");
        }
        return record;
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
