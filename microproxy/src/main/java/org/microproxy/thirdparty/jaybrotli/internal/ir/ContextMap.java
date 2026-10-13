/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.ir;

public record ContextMap(int[] trees) {
  public ContextMap {
    trees = trees.clone();
    for (int t : trees) if (t < 0) throw new IllegalArgumentException("tree");
  }

  @Override
  public int[] trees() {
    return trees.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof ContextMap b && java.util.Arrays.equals(trees, b.trees);
  }

  @Override
  public int hashCode() {
    return java.util.Arrays.hashCode(trees);
  }
}
