/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

public final class BeamParser extends DynamicParser {
  public BeamParser() {
    super(4);
  }

  public String name() {
    return "beam";
  }
}
