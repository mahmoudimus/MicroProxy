/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.bits;

/** The wire bit order for Brotli integers. */
public enum LsbBitOrder {
  INSTANCE;

  public int reverse(int value, int bits) {
    if (bits < 0 || bits > 32) throw new IllegalArgumentException("bit width");
    if (bits == 0) return 0;
    return Integer.reverse(value) >>> (32 - bits);
  }
}
