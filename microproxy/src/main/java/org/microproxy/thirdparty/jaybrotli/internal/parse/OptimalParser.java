/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

public final class OptimalParser extends DynamicParser {
  public OptimalParser() {
    super(1);
  }

  public String name() {
    return "optimal";
  }
}
