/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

import java.util.Objects;

public record EncoderOptions(
    Quality quality,
    WindowBits windowBits,
    boolean largeWindow,
    int metablockSize,
    String matchFinder,
    String parseStrategy,
    org.microproxy.thirdparty.jaybrotli.spi.LengthLimiter lengthLimiter) {
  public EncoderOptions {
    Objects.requireNonNull(quality);
    Objects.requireNonNull(windowBits);
    Objects.requireNonNull(matchFinder);
    Objects.requireNonNull(parseStrategy);
    if (windowBits.value() > 24 && !largeWindow)
      throw new IllegalArgumentException("large-window opt-in required");
    if (metablockSize < 0 || metablockSize > (1 << 24))
      throw new IllegalArgumentException("metablock size");
    if (matchFinder.equals("standard") != parseStrategy.equals("standard"))
      throw new IllegalArgumentException("select both strategies");
  }

  public EncoderOptions(
      Quality q, WindowBits w, boolean large, int size, String finder, String parser) {
    this(q, w, large, size, finder, parser, null);
  }

  public EncoderOptions(Quality q, WindowBits w, boolean large, int size) {
    this(q, w, large, size, "standard", "standard");
  }

  public static EncoderOptions defaults() {
    return new EncoderOptions(new Quality(0), new WindowBits(22), false, 0);
  }

  public EncoderOptions withQuality(int q) {
    return new EncoderOptions(
        new Quality(q),
        windowBits,
        largeWindow,
        metablockSize,
        matchFinder,
        parseStrategy,
        lengthLimiter);
  }

  public EncoderOptions withWindowBits(int w) {
    return new EncoderOptions(
        quality,
        new WindowBits(w),
        largeWindow,
        metablockSize,
        matchFinder,
        parseStrategy,
        lengthLimiter);
  }

  public EncoderOptions withLargeWindow(boolean large) {
    return new EncoderOptions(
        quality, windowBits, large, metablockSize, matchFinder, parseStrategy, lengthLimiter);
  }

  public EncoderOptions withMetablockSize(int size) {
    return new EncoderOptions(
        quality, windowBits, largeWindow, size, matchFinder, parseStrategy, lengthLimiter);
  }

  public EncoderOptions withStrategies(String finder, String parser) {
    return new EncoderOptions(
        quality, windowBits, largeWindow, metablockSize, finder, parser, lengthLimiter);
  }

  public EncoderOptions withLengthLimiter(org.microproxy.thirdparty.jaybrotli.spi.LengthLimiter limiter) {
    return new EncoderOptions(
        quality,
        windowBits,
        largeWindow,
        metablockSize,
        matchFinder,
        parseStrategy,
        java.util.Objects.requireNonNull(limiter));
  }
}
