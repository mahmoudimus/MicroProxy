/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.Limits;
import org.microproxy.thirdparty.jaybrotli.config.TrailingData;
import org.microproxy.thirdparty.jaybrotli.internal.codec.StreamDecoder;
import java.nio.ByteBuffer;

/**
 * NIO-first decoder facade over the internal streaming pipeline.
 *
 * <p>Constructor options supply initial settings; each successful setter replaces its corresponding
 * setting, so the last successful call wins. Options values themselves remain unchanged. Set
 * large-window mode before the first {@link #receive}; it rejects changes after decoding starts.
 * Limits and the content emit threshold may change between receive calls and affect subsequent
 * checks and emissions; previously accepted headers and output are not revalidated. {@link #reset}
 * preserves the latest settings and callbacks. Instances are single-owner and must not be
 * configured concurrently with decoding.
 *
 * <p>The decoder accepts exactly one stream. By default ({@link TrailingData#REJECT}) any byte
 * after the end of the stream, in the buffer that completes it or in a later {@link #receive}, is
 * a {@link CorruptStreamException}, as are non-zero bits padding the last byte of the stream. With
 * {@link TrailingData#ALLOW} decoding stops at the end of the stream and the buffer that completes
 * it is left positioned at the first byte after it; {@link #streamLength()} reports where the
 * stream ended in either mode.
 */
public final class Decoder implements AutoCloseable {
  private final StreamDecoder engine = new StreamDecoder();

  public Decoder() {}

  /**
   * Creates a decoder with the supplied initial settings.
   *
   * @param options initial configuration; later setters override individual settings
   */
  public Decoder(DecoderOptions options) {
    engine.setLargeWindow(options.largeWindow());
    engine.setLimits(options.limits());
    engine.setContentEmitThreshold(options.emitThreshold());
    engine.setOffHeap(options.offHeap());
    engine.setTrailingData(options.trailingData());
  }

  public void setHandler(BrotliHandler handler) {
    engine.setHandler(handler);
  }

  public Decoder onContent(BrotliContentHandler handler) {
    engine.onContent(handler);
    return this;
  }

  public Decoder onEndStream(BrotliEndStreamHandler handler) {
    engine.onEndStream(handler);
    return this;
  }

  public void setContentHandler(BrotliContentHandler handler) {
    engine.setContentHandler(handler);
  }

  /**
   * Overrides large-window opt-in before the first receive; survives reset. Limits are independent.
   *
   * @param enabled whether to accept large-window streams
   * @throws IllegalStateException if decoding started
   */
  public void setLargeWindow(boolean enabled) {
    engine.setLargeWindow(enabled);
  }

  /**
   * Replaces the initial or previous limits for subsequent checks, including between receive calls.
   * Already accepted headers and output are not revalidated. The setting survives reset.
   *
   * @param limits new limits, or null to restore {@link Limits#defaults()}, not constructor options
   */
  public void setLimits(Limits limits) {
    engine.setLimits(limits);
  }

  /**
   * Replaces the initial or previous emit threshold for subsequent emissions; survives reset.
   *
   * @param bytes literal accumulation threshold, at least 1
   * @throws IllegalArgumentException if bytes is less than 1
   */
  public void setContentEmitThreshold(int bytes) {
    engine.setContentEmitThreshold(bytes);
  }

  /**
   * Replaces the trailing-data policy; survives reset.
   *
   * @param policy what to do with bytes after the end of the stream, or null for {@link
   *     TrailingData#REJECT}
   * @since 1.2
   */
  public void setTrailingData(TrailingData policy) {
    engine.setTrailingData(policy);
  }

  /**
   * Returns whether the end of the stream has been decoded (the final meta-block and its zero
   * padding). Completion is reported before {@link #close()}; {@link #reset()} clears it.
   *
   * @return true once the stream is complete
   * @since 1.2
   */
  public boolean isFinished() {
    return engine.isFinished();
  }

  /**
   * Returns the number of compressed bytes, counted from the first byte passed to {@link #receive}
   * since construction or {@link #reset()}, that make up the stream. Any input from that offset on
   * is trailing data. Equals {@link BrotliLocator#getByteOffset()} at end-of-stream.
   *
   * @return stream length in bytes, or -1 until the end of the stream has been decoded
   * @since 1.2
   */
  public long streamLength() {
    return engine.streamLength();
  }

  public void receive(ByteBuffer input) throws BrotliException {
    engine.receive(input);
  }

  public void close() throws BrotliException {
    engine.close();
  }

  public void abort() {
    engine.abort();
  }

  public void reset() {
    engine.reset();
  }
}
