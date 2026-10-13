/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.spi;

/**
 * Deterministic, side-effect-free selection of bounded prefix lengths. Zero-bit single-symbol trees
 * bypass this strategy.
 */
@FunctionalInterface
public interface LengthLimiter {
  byte[] limit(int[] lengths, int maxBits);
}
