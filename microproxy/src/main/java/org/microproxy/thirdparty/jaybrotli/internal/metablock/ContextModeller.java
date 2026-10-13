/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.metablock;

/** Pure literal and distance context selection shared by packing and reconstruction. */
public interface ContextModeller {
  int literalContext(int mode, int previous, int previous2);

  int distanceContext(int copyLength);

  static ContextModeller standard() {
    return Standard.INSTANCE;
  }

  enum Standard implements ContextModeller {
    INSTANCE;

    public int literalContext(int mode, int p1, int p2) {
      return Context.literalContextId(mode, p1, p2);
    }

    public int distanceContext(int length) {
      return Context.distanceContextId(length);
    }
  }
}
