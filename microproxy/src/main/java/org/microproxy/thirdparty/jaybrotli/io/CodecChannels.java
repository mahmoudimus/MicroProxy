/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.io;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.Decoder;
import org.microproxy.thirdparty.jaybrotli.Encoder;
import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.Objects;

/** Blocking channel operations leave channels caller-owned and can run on virtual threads. */
public final class CodecChannels {
  private CodecChannels() {}

  public static void encode(
      ReadableByteChannel input, WritableByteChannel output, EncoderOptions options)
      throws IOException, BrotliException {
    check(input, output);
    Encoder encoder = new Encoder(options).onCompressed(new ChannelSink(output));
    ByteBuffer buffer = ByteBuffer.allocateDirect(65536);
    while (read(input, buffer) != -1) {
      buffer.flip();
      encoder.receive(buffer);
      buffer.clear();
    }
    encoder.close();
  }

  public static void decode(
      ReadableByteChannel input, WritableByteChannel output, DecoderOptions options)
      throws IOException, BrotliException {
    check(input, output);
    ChannelSink sink = new ChannelSink(output);
    Decoder decoder = new Decoder(options).onContent((buffer, end) -> sink.write(buffer));
    try {
      ByteBuffer buffer = ByteBuffer.allocateDirect(65536);
      while (read(input, buffer) != -1) {
        buffer.flip();
        decoder.receive(buffer);
        buffer.clear();
      }
      decoder.close();
    } finally {
      decoder.abort();
    }
  }

  private static void check(ReadableByteChannel input, WritableByteChannel output) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(output, "output");
    for (Object channel : new Object[] {input, output}) {
      if (channel instanceof SelectableChannel selectable && !selectable.isBlocking())
        throw new IllegalArgumentException("A blocking channel is required");
    }
  }

  private static int read(ReadableByteChannel input, ByteBuffer buffer) throws IOException {
    if (Thread.currentThread().isInterrupted())
      throw new InterruptedIOException("Brotli operation interrupted");
    int count = input.read(buffer);
    if (count == 0)
      throw new IOException("Input channel made no progress; a blocking channel is required");
    return count;
  }
}
