/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.internal.bits;

public record BitCursor(
    Object owner,
    long generation,
    long accumulator,
    int bitCount,
    long bytesPulled,
    int inputPosition) {}
