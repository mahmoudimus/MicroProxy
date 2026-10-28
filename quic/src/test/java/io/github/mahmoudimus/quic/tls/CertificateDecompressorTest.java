package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Arrays;
import java.util.zip.Deflater;
import org.junit.jupiter.api.Test;

class CertificateDecompressorTest {

    private static byte[] deflate(byte[] data) {
        Deflater d = new Deflater();
        d.setInput(data);
        d.finish();
        byte[] buf = new byte[data.length + 64];
        int n = d.deflate(buf);
        d.end();
        return Arrays.copyOf(buf, n);
    }

    @Test
    void zlibInflatesToTheAnnouncedLength() throws IOException {
        byte[] message = new byte[3000];
        for (int i = 0; i < message.length; i++) message[i] = (byte) (i % 7);
        assertArrayEquals(message, CertificateDecompressor.ZLIB.decompress(ProfileExtensions.ZLIB, deflate(message), 3000));
    }

    @Test
    void aWrongLengthOrCorruptDataIsAnError() {
        byte[] compressed = deflate(new byte[100]);
        assertThrows(IOException.class, () -> CertificateDecompressor.ZLIB.decompress(ProfileExtensions.ZLIB, compressed, 99));
        assertThrows(IOException.class, () -> CertificateDecompressor.ZLIB.decompress(ProfileExtensions.ZLIB, compressed, 101));
        assertThrows(IOException.class,
                () -> CertificateDecompressor.ZLIB.decompress(ProfileExtensions.ZLIB, new byte[] {1, 2, 3, 4}, 10));
    }

    @Test
    void otherAlgorithmsFallThrough() throws IOException {
        assertNull(CertificateDecompressor.ZLIB.decompress(ProfileExtensions.BROTLI, new byte[1], 1));
        CertificateDecompressor brotli = (algorithm, data, length) -> algorithm == ProfileExtensions.BROTLI ? new byte[] {42} : null;
        assertArrayEquals(new byte[] {42}, brotli.or(CertificateDecompressor.ZLIB).decompress(ProfileExtensions.BROTLI, new byte[1], 1));
        assertArrayEquals(new byte[5], brotli.or(CertificateDecompressor.ZLIB).decompress(ProfileExtensions.ZLIB, deflate(new byte[5]), 5));
    }
}
