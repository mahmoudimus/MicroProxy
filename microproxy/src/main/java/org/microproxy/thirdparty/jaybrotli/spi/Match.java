/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.spi;

public record Match(int distance, int length) {
  public Match {
    if (distance < 1 || length < 4) throw new IllegalArgumentException("match");
  }
}
