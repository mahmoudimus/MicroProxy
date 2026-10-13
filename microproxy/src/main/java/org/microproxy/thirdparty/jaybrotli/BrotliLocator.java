/*
 * BrotliLocator.java
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

package org.microproxy.thirdparty.jaybrotli;

/**
 * Reports the current position in a Brotli bitstream during decoding.
 *
 * <p>Unlike text formats, Brotli has no line/column; this locator exposes the stream byte offset,
 * bit remainder within the current byte, and metablock index.
 */
public interface BrotliLocator {

  /**
   * Returns the number of complete bytes consumed from the compressed stream so far (not counting
   * bits still in the bit accumulator that belong to a partially-read byte).
   *
   * @return stream byte offset
   */
  long getByteOffset();

  /**
   * Returns how many bits of the current byte have already been consumed (0–7).
   *
   * @return bit remainder within the current byte
   */
  int getBitOffset();

  /**
   * Returns the zero-based index of the metablock currently being decoded.
   *
   * @return metablock index
   */
  int getMetablockIndex();
}
