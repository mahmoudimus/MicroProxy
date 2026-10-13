/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;
import org.microproxy.thirdparty.jaybrotli.io.CodecStreams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * One-shot convenience for small, in-memory payloads.
 *
 * <p>{@link #compress(byte[])} and {@link #decompress(byte[])} buffer the whole result in memory,
 * which is convenient for short messages, configuration blobs, and tests. For large or unbounded
 * data prefer the streaming APIs: {@link org.microproxy.thirdparty.jaybrotli.io.CodecStreams}, {@link
 * org.microproxy.thirdparty.jaybrotli.io.CodecChannels}, or the incremental {@link Encoder}/{@link Decoder}.
 *
 * <p>Both methods throw {@link BrotliException} on failure and never return null.
 */
public final class Brotli {
  private Brotli() {}

  /** Compresses {@code input} with default options. */
  public static byte[] compress(byte[] input) throws BrotliException {
    return compress(input, EncoderOptions.defaults());
  }

  /** Compresses {@code input} with the supplied options. */
  public static byte[] compress(byte[] input, EncoderOptions options) throws BrotliException {
    if (input == null) throw new NullPointerException("input");
    if (options == null) throw new NullPointerException("options");
    ByteArrayOutputStream output = new ByteArrayOutputStream(Math.max(32, input.length / 2 + 16));
    try (var stream = CodecStreams.encoding(output, options)) {
      stream.write(input);
    } catch (IOException e) {
      throw new BrotliException("Compression failed", e);
    }
    return output.toByteArray();
  }

  /** Decompresses {@code input} with default options. */
  public static byte[] decompress(byte[] input) throws BrotliException {
    return decompress(input, DecoderOptions.defaults());
  }

  /** Decompresses {@code input} with the supplied options. */
  public static byte[] decompress(byte[] input, DecoderOptions options) throws BrotliException {
    if (input == null) throw new NullPointerException("input");
    if (options == null) throw new NullPointerException("options");
    ByteArrayOutputStream output = new ByteArrayOutputStream(Math.max(32, input.length * 4));
    try (var stream = CodecStreams.decoding(new ByteArrayInputStream(input), options)) {
      stream.transferTo(output);
    } catch (IOException e) {
      throw new BrotliException("Decompression failed", e);
    }
    return output.toByteArray();
  }
}
