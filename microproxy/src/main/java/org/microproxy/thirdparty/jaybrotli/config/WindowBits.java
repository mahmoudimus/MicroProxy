/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

public record WindowBits(int value) {
  public WindowBits {
    if (value < 10 || value > 30) throw new IllegalArgumentException("window bits must be 10..30");
  }
}
