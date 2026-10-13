/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

public final class HashDictionaryIndex implements DictionaryIndex {
  public int tryFind(
      byte[] data,
      int offset,
      int available,
      boolean transforms,
      int[] wire,
      int[] covered,
      int[] transform,
      int[] index) {
    return Dictionary.findMatch(
        data, offset, available, transforms, wire, covered, transform, index);
  }

  @Override
  public int tryFind(
      byte[] data,
      int offset,
      int available,
      boolean transforms,
      int floor,
      int[] wire,
      int[] covered,
      int[] transform,
      int[] index) {
    return Dictionary.findMatch(
        data, offset, available, transforms, floor, wire, covered, transform, index);
  }
}
