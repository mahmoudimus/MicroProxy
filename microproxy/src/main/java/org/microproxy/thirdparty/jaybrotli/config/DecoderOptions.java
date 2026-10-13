/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

public record DecoderOptions(
    Limits limits, boolean largeWindow, int emitThreshold, boolean offHeap) {
  public DecoderOptions {
    java.util.Objects.requireNonNull(limits);
    if (emitThreshold < 1) throw new IllegalArgumentException("emitThreshold");
  }

  public DecoderOptions(Limits limits, boolean largeWindow, int threshold) {
    this(limits, largeWindow, threshold, false);
  }

  public static DecoderOptions defaults() {
    return new DecoderOptions(Limits.defaults(), false, 8192);
  }

  public DecoderOptions withLimits(Limits l) {
    return new DecoderOptions(l, largeWindow, emitThreshold, offHeap);
  }

  public DecoderOptions withLargeWindow(boolean l) {
    return new DecoderOptions(limits, l, emitThreshold, offHeap);
  }

  public DecoderOptions withOffHeap(boolean off) {
    return new DecoderOptions(limits, largeWindow, emitThreshold, off);
  }
}
