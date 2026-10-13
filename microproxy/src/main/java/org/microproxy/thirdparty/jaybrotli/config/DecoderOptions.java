/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

/**
 * Immutable decoder settings.
 *
 * @param limits resource limits
 * @param largeWindow whether the RFC 9841 large-window format is accepted
 * @param emitThreshold bytes of output batched per content callback, at least 1
 * @param offHeap whether history lives off the heap (requires the {@code ffm} build)
 * @param trailingData what to do with bytes after the end of the stream; {@link
 *     TrailingData#REJECT} by default
 */
public record DecoderOptions(
    Limits limits,
    boolean largeWindow,
    int emitThreshold,
    boolean offHeap,
    TrailingData trailingData) {
  public DecoderOptions {
    java.util.Objects.requireNonNull(limits);
    java.util.Objects.requireNonNull(trailingData);
    if (emitThreshold < 1) throw new IllegalArgumentException("emitThreshold");
  }

  /**
   * Creates options that reject trailing data.
   *
   * @param limits resource limits
   * @param largeWindow whether the RFC 9841 large-window format is accepted
   * @param threshold bytes of output batched per content callback, at least 1
   * @param offHeap whether history lives off the heap (requires the {@code ffm} build)
   */
  public DecoderOptions(Limits limits, boolean largeWindow, int threshold, boolean offHeap) {
    this(limits, largeWindow, threshold, offHeap, TrailingData.REJECT);
  }

  /**
   * Creates on-heap options that reject trailing data.
   *
   * @param limits resource limits
   * @param largeWindow whether the RFC 9841 large-window format is accepted
   * @param threshold bytes of output batched per content callback, at least 1
   */
  public DecoderOptions(Limits limits, boolean largeWindow, int threshold) {
    this(limits, largeWindow, threshold, false);
  }

  public static DecoderOptions defaults() {
    return new DecoderOptions(Limits.defaults(), false, 8192);
  }

  public DecoderOptions withLimits(Limits l) {
    return new DecoderOptions(l, largeWindow, emitThreshold, offHeap, trailingData);
  }

  public DecoderOptions withLargeWindow(boolean l) {
    return new DecoderOptions(limits, l, emitThreshold, offHeap, trailingData);
  }

  public DecoderOptions withOffHeap(boolean off) {
    return new DecoderOptions(limits, largeWindow, emitThreshold, off, trailingData);
  }

  /**
   * Returns options with the given content emit threshold.
   *
   * @param bytes output bytes batched per content callback, at least 1
   * @return updated options
   * @since 1.2
   */
  public DecoderOptions withEmitThreshold(int bytes) {
    return new DecoderOptions(limits, largeWindow, bytes, offHeap, trailingData);
  }

  /**
   * Returns options with the given trailing-data policy.
   *
   * @param policy what to do with bytes after the end of the stream
   * @return updated options
   * @since 1.2
   */
  public DecoderOptions withTrailingData(TrailingData policy) {
    return new DecoderOptions(limits, largeWindow, emitThreshold, offHeap, policy);
  }
}
