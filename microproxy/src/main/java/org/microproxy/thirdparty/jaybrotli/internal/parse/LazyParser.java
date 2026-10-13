/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.parse;

public final class LazyParser extends GreedyParser {
  public String name() {
    return "lazy";
  }

  @Override
  protected boolean lazy() {
    return true;
  }
}
