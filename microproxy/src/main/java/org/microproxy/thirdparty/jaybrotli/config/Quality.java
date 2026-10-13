/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.config;

public record Quality(int value) {
  public Quality {
    if (value < 0 || value > 11) throw new IllegalArgumentException("quality must be 0..11");
  }
}
