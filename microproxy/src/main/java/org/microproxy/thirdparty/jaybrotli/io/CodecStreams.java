/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.io;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.Decoder;
import org.microproxy.thirdparty.jaybrotli.Encoder;
import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Stream bridges own their supplied stream; decoded output buffers are bounded by decoder limits.
 */
public final class CodecStreams {
  private CodecStreams() {}

  public static OutputStream encoding(OutputStream output, EncoderOptions options) {
    Objects.requireNonNull(output);
    return new OutputStream() {
      boolean closed;
      final Encoder encoder =
          new Encoder(options)
              .onCompressed(
                  b -> {
                    byte[] bytes = new byte[b.remaining()];
                    b.get(bytes);
                    try {
                      output.write(bytes);
                    } catch (IOException e) {
                      throw new BrotliException("Write failed", e);
                    }
                  });

      public void write(int value) throws IOException {
        write(new byte[] {(byte) value});
      }

      public void write(byte[] bytes, int offset, int length) throws IOException {
        if (closed) throw new IOException("Stream closed");
        Objects.checkFromIndexSize(offset, length, bytes.length);
        try {
          encoder.receive(ByteBuffer.wrap(bytes, offset, length));
        } catch (BrotliException e) {
          throw new IOException(e);
        }
      }

      public void flush() throws IOException {
        if (closed) throw new IOException("Stream closed");
        try {
          encoder.flush();
          output.flush();
        } catch (BrotliException e) {
          throw new IOException(e);
        }
      }

      public void close() throws IOException {
        if (closed) return;
        closed = true;
        try {
          encoder.close();
        } catch (BrotliException e) {
          throw new IOException(e);
        } finally {
          output.close();
        }
      }
    };
  }

  public static InputStream decoding(InputStream input, DecoderOptions options) {
    Objects.requireNonNull(input);
    return new InputStream() {
      boolean closed, eof;
      final ArrayDeque<ByteBuffer> queue = new ArrayDeque<>();
      final byte[] compressed = new byte[8192];
      final Decoder decoder =
          new Decoder(options)
              .onContent(
                  (b, end) -> {
                    if (b.hasRemaining()) {
                      byte[] bytes = new byte[b.remaining()];
                      b.get(bytes);
                      queue.add(ByteBuffer.wrap(bytes));
                    }
                  });

      public int read() throws IOException {
        byte[] one = new byte[1];
        return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
      }

      public int read(byte[] bytes, int offset, int length) throws IOException {
        Objects.checkFromIndexSize(offset, length, bytes.length);
        if (closed) throw new IOException("Stream closed");
        if (length == 0) return 0;
        try {
          while (queue.isEmpty() && !eof) {
            int n = input.read(compressed);
            if (n < 0) {
              eof = true;
              decoder.close();
            } else if (n > 0) decoder.receive(ByteBuffer.wrap(compressed, 0, n));
            else throw new IOException("Input stream made no progress");
          }
          if (queue.isEmpty()) return -1;
          ByteBuffer head = queue.peek();
          int n = Math.min(length, head.remaining());
          head.get(bytes, offset, n);
          if (!head.hasRemaining()) queue.remove();
          return n;
        } catch (BrotliException e) {
          decoder.abort();
          throw new IOException(e);
        } catch (IOException | RuntimeException e) {
          decoder.abort();
          throw e;
        }
      }

      public void close() throws IOException {
        if (closed) return;
        closed = true;
        queue.clear();
        decoder.abort();
        input.close();
      }
    };
  }
}
