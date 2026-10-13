/*
 * Context.java
 *
 * SPDX-License-Identifier: Apache-2.0
 * Modified for jaybrotli: namespace and licensing.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.microproxy.thirdparty.jaybrotli.internal.metablock;

/**
 * Literal and distance context IDs (RFC 7932 §7).
 *
 * <p>Lookup tables match the RFC / reference decoder layout: for mode M, {@code context =
 * LOOKUP[(M<<9)+p1] | LOOKUP[(M<<9)+256+p2]}.
 */
public final class Context {

  public static final int LSB6 = 0;
  public static final int MSB6 = 1;
  public static final int UTF8 = 2;
  public static final int SIGNED = 3;

  /** Combined lookup: 4 modes × 512 entries (p1 then p2). */
  private static final int[] LOOKUP = new int[2048];

  private static final String UTF_MAP =
      "         !!  !                  \"#$##%#$&'##(#)#+++++++++"
          + "+((&*'##,---,---,-----,-----,-----&#'###.///.///./////./////./////&#'# ";
  private static final String UTF_RLE = "A/*  ':  & : $  \u0081 @";

  static {
    unpackLookupTable();
  }

  private Context() {}

  public static int literalContextId(int mode, int p1, int p2) {
    p1 &= 0xff;
    p2 &= 0xff;
    int base = mode << 9;
    return LOOKUP[base + p1] | LOOKUP[base + 256 + p2];
  }

  public static int distanceContextId(int copyLength) {
    if (copyLength == 2) {
      return 0;
    }
    if (copyLength == 3) {
      return 1;
    }
    if (copyLength == 4) {
      return 2;
    }
    return 3;
  }

  private static void unpackLookupTable() {
    for (int i = 0; i < 256; i++) {
      LOOKUP[i] = i & 0x3F;
      LOOKUP[512 + i] = i >> 2;
      LOOKUP[1792 + i] = 2 + (i >> 6);
    }
    for (int i = 0; i < 128; i++) {
      LOOKUP[1024 + i] = 4 * (UTF_MAP.charAt(i) - 32);
    }
    for (int i = 0; i < 64; i++) {
      LOOKUP[1152 + i] = i & 1;
      LOOKUP[1216 + i] = 2 + (i & 1);
    }
    int offset = 1280;
    for (int k = 0; k < 19; k++) {
      int value = k & 3;
      int rep = UTF_RLE.charAt(k) - 32;
      for (int i = 0; i < rep; i++) {
        LOOKUP[offset++] = value;
      }
    }
    for (int i = 0; i < 16; i++) {
      LOOKUP[1792 + i] = 1;
      LOOKUP[2032 + i] = 6;
    }
    LOOKUP[1792] = 0;
    LOOKUP[2047] = 7;
    for (int i = 0; i < 256; i++) {
      LOOKUP[1536 + i] = LOOKUP[1792 + i] << 3;
    }
  }
}
