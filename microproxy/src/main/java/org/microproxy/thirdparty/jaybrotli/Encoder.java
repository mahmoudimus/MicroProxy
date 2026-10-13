/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli;

import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;
import org.microproxy.thirdparty.jaybrotli.internal.codec.StreamEncoder;
import java.nio.ByteBuffer;

/**
 * NIO-first encoder facade over the internal streaming pipeline.
 *
 * <p>Constructor options supply initial settings; each successful setter replaces its corresponding
 * setting, so the last successful call wins. Options values themselves remain unchanged. Configure
 * quality, window bits and large-window mode before the first {@link #receive}, {@link #flush}, or
 * {@link #close}, even for empty input. These setters reject changes after the stream starts.
 * {@link #reset} preserves the latest settings and callbacks and permits configuration for a new
 * stream. Instances are single-owner and must not be configured concurrently with encoding.
 *
 * <p>If compressed-output delivery throws, receive, flush and close reject further work until
 * reset. The partially delivered stream must be discarded; reset starts a new stream.
 */
public final class Encoder implements AutoCloseable {
  private final StreamEncoder engine;

  public Encoder() {
    this(EncoderOptions.defaults());
  }

  /**
   * Creates an encoder with the supplied initial settings.
   *
   * @param options initial configuration; later setters override individual settings
   */
  public Encoder(EncoderOptions options) {
    engine = new StreamEncoder();
    engine.configure(options);
  }

  public Encoder(BrotliSink sink) {
    engine = new StreamEncoder(sink);
  }

  public Encoder(BrotliSink sink, boolean direct) {
    engine = new StreamEncoder(sink, direct);
  }

  public Encoder onCompressed(BrotliSink sink) {
    engine.onCompressed(sink);
    return this;
  }

  public Encoder onEndStream(BrotliEndStreamHandler handler) {
    engine.onEndStream(handler);
    return this;
  }

  /**
   * Overrides large-window mode before the stream starts. Enable before selecting window bits above
   * 24; reduce window bits to 24 or less before disabling. The setting survives reset.
   *
   * @param enabled whether to emit the large-window format
   * @throws IllegalStateException if encoding started or disabling conflicts with window bits
   */
  public void setLargeWindow(boolean enabled) {
    engine.setLargeWindow(enabled);
  }

  /**
   * Overrides the initial or previous quality before the stream starts; survives reset.
   *
   * @param quality compression quality, 0..11
   * @throws IllegalStateException if encoding started
   * @throws IllegalArgumentException if quality is outside 0..11
   */
  public void setQuality(int quality) {
    engine.setQuality(quality);
  }

  /**
   * Overrides the initial or previous window bits before the stream starts; survives reset.
   *
   * @param bits window bits, 10..24 normally or 10..30 with large-window mode enabled
   * @throws IllegalStateException if encoding started
   * @throws IllegalArgumentException if bits are outside the currently allowed range
   */
  public void setWindowBits(int bits) {
    engine.setWindowBits(bits);
  }

  public void receive(ByteBuffer input) throws BrotliException {
    engine.receive(input);
  }

  /**
   * Delivers buffered input and encoded bytes at a legal nonterminal boundary.
   * Encoding can continue afterward. Each call adds a 6-bit metadata header plus 0–7
   * alignment bits, including when no input is pending.
   *
   * @throws BrotliException on encode failure
   */
  public void flush() throws BrotliException {
    engine.flush();
  }

  public void close() throws BrotliException {
    engine.close();
  }

  public void reset() {
    engine.reset();
  }
}
