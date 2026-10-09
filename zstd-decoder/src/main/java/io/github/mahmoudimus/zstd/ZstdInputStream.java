package io.github.mahmoudimus.zstd;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Decompresses Zstandard data read from another stream. Output is produced a block (at most 128
 * KiB) at a time, so reading a capped amount from a hostile stream costs no more than that much
 * work and memory, plus the frame's window.
 */
public final class ZstdInputStream extends InputStream {

    private final InputStream in;
    private final FrameDecoder decoder;
    private final byte[] one = new byte[1];
    private boolean closed;

    /**
     * Decodes {@code in} with default settings.
     *
     * @param in compressed input; closing this stream also closes the input
     */
    public ZstdInputStream(InputStream in) {
        this(in, ZstdDecompressor.create());
    }

    ZstdInputStream(InputStream in, ZstdDecompressor config) {
        this.in = Objects.requireNonNull(in);
        this.decoder = new FrameDecoder(in, config);
    }

    @Override
    public int read() throws IOException {
        return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        Objects.checkFromIndexSize(off, len, b.length);
        if (closed) throw new IOException("stream closed");
        if (len == 0) return 0;
        while (decoder.readPos == decoder.pos) {
            if (!advance()) return -1;
        }
        int n = Math.min(len, decoder.pos - decoder.readPos);
        System.arraycopy(decoder.buf, decoder.readPos, b, off, n);
        decoder.readPos += n;
        return n;
    }

    private boolean advance() throws IOException {
        try {
            return decoder.decodeMore();
        } catch (ZstdException e) {
            throw e;
        } catch (RuntimeException e) {
            // Every malformed input should be caught by an explicit check; this is a backstop.
            throw new ZstdException("corrupt zstd data (internal decoder error)", e);
        }
    }

    @Override
    public int available() {
        return closed ? 0 : decoder.pos - decoder.readPos;
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            closed = true;
            in.close();
        }
    }
}
