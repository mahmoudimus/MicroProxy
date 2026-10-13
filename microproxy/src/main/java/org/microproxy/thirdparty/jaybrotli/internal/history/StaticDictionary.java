/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.history;

public final class StaticDictionary {
  private static final DictionaryIndex INDEX = new HashDictionaryIndex();

  private StaticDictionary() {}

  public static DictionaryIndex index() {
    return INDEX;
  }

  public static int lookup(int wordLength, int distance, int maxDistance, byte[] output)
      throws org.microproxy.thirdparty.jaybrotli.BrotliException {
    return Dictionary.lookup(wordLength, distance, maxDistance, output);
  }
}
