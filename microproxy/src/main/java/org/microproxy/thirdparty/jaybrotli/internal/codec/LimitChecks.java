/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.codec;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.LimitExceededException;
import org.microproxy.thirdparty.jaybrotli.config.Limits;

public final class LimitChecks {
  private LimitChecks() {}

  public static void checkWindowBits(Limits limits, int wbits) throws BrotliException {
    if (!limits.enabled()) {
      return;
    }
    if (wbits > limits.maxWindowBits()) {
      throw new LimitExceededException(
          "WBITS " + wbits + " exceeds limit " + limits.maxWindowBits());
    }
  }

  public static void checkMetablockLength(Limits limits, int mlen) throws BrotliException {
    if (!limits.enabled()) {
      return;
    }
    if (mlen > limits.maxMetablockLength()) {
      throw new LimitExceededException(
          "MLEN " + mlen + " exceeds limit " + limits.maxMetablockLength());
    }
  }

  public static void checkMetadataLength(Limits limits, int len) throws BrotliException {
    if (!limits.enabled()) {
      return;
    }
    if (len > limits.maxMetadataLength()) {
      throw new LimitExceededException(
          "Metadata length " + len + " exceeds limit " + limits.maxMetadataLength());
    }
  }

  public static void checkTotalOutput(Limits limits, long total) throws BrotliException {
    if (!limits.enabled()) {
      return;
    }
    if (total > limits.maxTotalOutput()) {
      throw new LimitExceededException(
          "Total output " + total + " exceeds limit " + limits.maxTotalOutput());
    }
  }
}
