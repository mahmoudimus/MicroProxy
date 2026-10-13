/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

public record Limits(
    int maxWindowBits,
    long maxTotalOutput,
    int maxMetablockLength,
    int maxMetadataLength,
    boolean enabled) {
  public static final int RFC_MAX_WINDOW_BITS = 24,
      LARGE_MAX_WINDOW_BITS = 30,
      RFC_MAX_METABLOCK_LENGTH = 1 << 24;

  public Limits {
    if (maxWindowBits < 10
        || maxWindowBits > 30
        || maxTotalOutput < 0
        || maxMetablockLength < 0
        || maxMetablockLength > RFC_MAX_METABLOCK_LENGTH
        || maxMetadataLength < 0) throw new IllegalArgumentException("limits");
  }

  public Limits() {
    this(24, 64L << 20, 1 << 24, 1 << 24, true);
  }

  public static Limits defaults() {
    return new Limits();
  }

  public Limits withoutLimits() {
    return new Limits(maxWindowBits, maxTotalOutput, maxMetablockLength, maxMetadataLength, false);
  }

  public Limits withMaxWindowBits(int value) {
    return new Limits(value, maxTotalOutput, maxMetablockLength, maxMetadataLength, enabled);
  }

  public Limits withMaxTotalOutput(long value) {
    return new Limits(maxWindowBits, value, maxMetablockLength, maxMetadataLength, enabled);
  }

  public Limits withMaxMetablockLength(int value) {
    return new Limits(maxWindowBits, maxTotalOutput, value, maxMetadataLength, enabled);
  }

  public Limits withMaxMetadataLength(int value) {
    return new Limits(maxWindowBits, maxTotalOutput, maxMetablockLength, value, enabled);
  }
}
