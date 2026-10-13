/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.ir;

/** Immutable semantic command view; dictionary wire length is distinct from output coverage. */
public sealed interface Command {
  record Insert(int offset, int length) implements Command {
    public Insert {
      if (offset < 0 || length < 0) throw new IllegalArgumentException("insert range");
    }
  }

  record Copy(int distance, int length) implements Command {
    public Copy {
      if (distance < 1 || length < 2) throw new IllegalArgumentException("copy range");
    }
  }

  record DictionaryCopy(int distance, int wordLength, int length) implements Command {
    public DictionaryCopy {
      if (distance < 1 || wordLength < 4 || wordLength > 24 || length < 0)
        throw new IllegalArgumentException("dictionary range");
    }
  }
}
