package org.microproxy.impl;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Like {@link java.io.BufferedOutputStream}, but the buffer is borrowed from a {@link BufferPool}
 * on the first write and given back on every flush, so an idle connection holds no buffer.
 * Writes at least as large as the buffer go straight through.
 */
final class PooledOutputStream extends FilterOutputStream {

    private final BufferPool pool;
    private byte[] buf;
    private int count;

    PooledOutputStream(OutputStream out, BufferPool pool) {
        super(out);
        this.pool = pool;
    }

    @Override
    public void write(int b) throws IOException {
        if (buf == null) buf = pool.take();
        if (count == buf.length) drain();
        buf[count++] = (byte) b;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (len >= pool.size()) {
            drain();
            out.write(b, off, len);
            return;
        }
        if (buf == null) buf = pool.take();
        if (len > buf.length - count) drain();
        System.arraycopy(b, off, buf, count, len);
        count += len;
    }

    private void drain() throws IOException {
        if (count > 0) {
            out.write(buf, 0, count);
            count = 0;
        }
    }

    @Override
    public void flush() throws IOException {
        drain();
        if (buf != null) {
            pool.give(buf);
            buf = null;
        }
        out.flush();
    }

    @Override
    public void close() throws IOException {
        try {
            flush();
        } finally {
            out.close();
        }
    }
}
