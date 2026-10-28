package io.github.mahmoudimus.quic.tls;

import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Decompresses a server's certificate chain (RFC 8879) with one of the algorithms a client offers
 * in {@code compress_certificate}. zlib is built in ({@link #ZLIB}); Brotli and zstd come from the
 * caller, which has decoders for them.
 */
@FunctionalInterface
public interface CertificateDecompressor {

    /** zlib (RFC 1950) only, with the JDK's {@link Inflater}. */
    CertificateDecompressor ZLIB = (algorithm, data, length) -> {
        if (algorithm != ProfileExtensions.ZLIB) return null;
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(data);
            byte[] out = new byte[length];
            int n = 0;
            while (n < length && !inflater.finished()) {
                int got = inflater.inflate(out, n, length - n);
                if (got == 0 && (inflater.needsInput() || inflater.needsDictionary())) break;
                n += got;
            }
            if (n != length || !inflater.finished()) throw new IOException("zlib certificate is not " + length + " bytes");
            return out;
        } catch (DataFormatException e) {
            throw new IOException("zlib certificate does not decompress", e);
        } finally {
            inflater.end();
        }
    };

    /**
     * The chain's Certificate message body, decompressed.
     *
     * @param algorithm the {@code CertificateCompressionAlgorithm} the server used
     * @param data the compressed bytes
     * @param length the {@code uncompressed_length} the server announced, at most 2^24
     * @return exactly {@code length} bytes, or null if this decompressor has no such algorithm
     * @throws IOException if the data does not decompress to {@code length} bytes
     */
    byte[] decompress(int algorithm, byte[] data, int length) throws IOException;

    /** This decompressor, falling back to {@code other} for algorithms it does not have. */
    default CertificateDecompressor or(CertificateDecompressor other) {
        return (algorithm, data, length) -> {
            byte[] out = decompress(algorithm, data, length);
            return out != null ? out : other.decompress(algorithm, data, length);
        };
    }
}
