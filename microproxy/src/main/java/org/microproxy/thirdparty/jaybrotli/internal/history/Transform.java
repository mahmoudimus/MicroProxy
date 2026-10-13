/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

/** Dictionary transform descriptor; affix bytes remain shared immutable tables. */
public record Transform(int prefixId, int type, int suffixId) {
  public Transform {
    if (prefixId < 0 || type < 0 || suffixId < 0) throw new IllegalArgumentException("transform");
  }
}
