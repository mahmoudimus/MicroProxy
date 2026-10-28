// Ported from Go src/crypto/tls/prf.go (BSD-3-Clause, Copyright 2009 The Go Authors): the TLS 1.2
// PRF (RFC 5246 section 5), the master secret and extended master secret (RFC 7627), the key
// block, and Finished's verify_data.
package io.github.mahmoudimus.quic.tls;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** The TLS 1.2 PRF and the secrets derived with it. */
final class Tls12Prf {

    static final int MASTER_SECRET_LENGTH = 48;
    static final int FINISHED_LENGTH = 12;

    private Tls12Prf() {}

    /** {@code PRF(secret, label, seed)} = {@code P_hash(secret, label || seed)}, {@code length} bytes. */
    static byte[] prf(Tls12CipherSuite suite, byte[] secret, String label, byte[] seed, int length) {
        try {
            Mac mac = Mac.getInstance(suite.prfMac());
            mac.init(new SecretKeySpec(secret, suite.prfMac()));
            byte[] labelSeed = concat(label.getBytes(StandardCharsets.US_ASCII), seed);
            byte[] out = new byte[length];
            byte[] a = mac.doFinal(labelSeed); // A(1)
            int filled = 0;
            while (filled < length) {
                mac.update(a);
                byte[] block = mac.doFinal(labelSeed);
                int n = Math.min(block.length, length - filled);
                System.arraycopy(block, 0, out, filled, n);
                filled += n;
                a = mac.doFinal(a);
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(suite.prfMac() + " is part of every Java runtime", e);
        }
    }

    static byte[] masterSecret(Tls12CipherSuite suite, byte[] preMaster, byte[] clientRandom, byte[] serverRandom) {
        return prf(suite, preMaster, "master secret", concat(clientRandom, serverRandom), MASTER_SECRET_LENGTH);
    }

    /** RFC 7627 section 4: over the hash of the handshake up to and including ClientKeyExchange. */
    static byte[] extendedMasterSecret(Tls12CipherSuite suite, byte[] preMaster, byte[] sessionHash) {
        return prf(suite, preMaster, "extended master secret", sessionHash, MASTER_SECRET_LENGTH);
    }

    /** The connection keys, in key-block order (RFC 5246 section 6.3). */
    record Keys(byte[] clientMac, byte[] serverMac, byte[] clientKey, byte[] serverKey, byte[] clientIv, byte[] serverIv) {}

    static Keys keys(Tls12CipherSuite suite, byte[] master, byte[] clientRandom, byte[] serverRandom) {
        Tls12CipherSuite.Bulk b = suite.bulk;
        int n = 2 * (b.macLength + b.keyLength + b.ivLength);
        byte[] block = prf(suite, master, "key expansion", concat(serverRandom, clientRandom), n);
        int at = 0;
        byte[] clientMac = Arrays.copyOfRange(block, at, at += b.macLength);
        byte[] serverMac = Arrays.copyOfRange(block, at, at += b.macLength);
        byte[] clientKey = Arrays.copyOfRange(block, at, at += b.keyLength);
        byte[] serverKey = Arrays.copyOfRange(block, at, at += b.keyLength);
        byte[] clientIv = Arrays.copyOfRange(block, at, at += b.ivLength);
        byte[] serverIv = Arrays.copyOfRange(block, at, at += b.ivLength);
        return new Keys(clientMac, serverMac, clientKey, serverKey, clientIv, serverIv);
    }

    /** Finished's verify_data (RFC 5246 section 7.4.9). */
    static byte[] finished(Tls12CipherSuite suite, byte[] master, boolean client, byte[] transcriptHash) {
        return prf(suite, master, client ? "client finished" : "server finished", transcriptHash, FINISHED_LENGTH);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
