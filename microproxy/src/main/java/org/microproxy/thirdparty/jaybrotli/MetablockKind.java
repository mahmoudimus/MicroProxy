/*
 * MetablockKind.java
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

/** Kind of metablock in a Brotli stream (RFC 7932 §9.2). */
public enum MetablockKind {

  /** Compressed metablock with Huffman-coded commands. */
  COMPRESSED,

  /** Uncompressed metablock: raw literal bytes on a byte boundary. */
  UNCOMPRESSED,

  /** Metadata metablock: bytes not added to the window or output. */
  METADATA
}
