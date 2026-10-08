package org.microproxy.impl;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.IntConsumer;

/** Streams that report how many bytes pass through them. */
final class CountingStreams {

    private CountingStreams() {}

    static InputStream counting(InputStream in, IntConsumer onBytes) {
        return new FilterInputStream(in) {
            @Override
            public int read() throws IOException {
                int b = in.read();
                if (b >= 0) onBytes.accept(1);
                return b;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                int n = in.read(b, off, len);
                if (n > 0) onBytes.accept(n);
                return n;
            }
        };
    }

    static OutputStream counting(OutputStream out, IntConsumer onBytes) {
        return new FilterOutputStream(out) {
            @Override
            public void write(int b) throws IOException {
                out.write(b);
                onBytes.accept(1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                out.write(b, off, len);
                if (len > 0) onBytes.accept(len);
            }
        };
    }
}
