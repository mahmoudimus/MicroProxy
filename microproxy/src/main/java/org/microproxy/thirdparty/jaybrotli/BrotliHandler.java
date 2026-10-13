/*
 * BrotliHandler.java
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

import java.nio.ByteBuffer;

/**
 * Callback interface for receiving Brotli decoding events.
 *
 * <p>Applications implement this interface and register it with {@link
 * Decoder#setHandler(BrotliHandler)}. Reconstructed output is delivered via {@link
 * #content(ByteBuffer, boolean)}. Buffer arguments are valid <strong>only during the
 * callback</strong>; copy if retention is needed.
 */
public interface BrotliHandler {

  /**
   * Receives a locator for the current decode position. Called once before other events.
   *
   * @param locator the locator
   */
  void setLocator(BrotliLocator locator);

  /**
   * Notifies of the stream window bits (WBITS) after the stream header.
   *
   * @param wbits window bits in [10..24], or [10..30] for large-window streams
   * @throws BrotliException if the handler aborts
   */
  void windowBits(int wbits) throws BrotliException;

  /**
   * Indicates the start of a metablock.
   *
   * @param length MLEN (uncompressed length); 0 for empty/metadata
   * @param last true if this is the last metablock
   * @param kind metablock kind
   * @throws BrotliException if the handler aborts
   */
  void startMetablock(int length, boolean last, MetablockKind kind) throws BrotliException;

  /**
   * Delivers reconstructed uncompressed output.
   *
   * <p>The buffer is a view into the decoder's ring buffer and is valid only during this call. Ring
   * wrap-around may produce two consecutive calls. {@code end} is true on the last slice of the
   * current write.
   *
   * @param data output bytes (read mode)
   * @param end true if this is the last slice of this write
   * @throws BrotliException if the handler aborts
   */
  void content(ByteBuffer data, boolean end) throws BrotliException;

  /**
   * Delivers metadata metablock bytes (not part of the sliding window or reconstructed content).
   *
   * @param data metadata bytes (valid only during this call)
   * @throws BrotliException if the handler aborts
   */
  void metadata(ByteBuffer data) throws BrotliException;

  /**
   * Notifies of an insert (literal run) when {@link #needsCommands()} is true.
   *
   * @param literals literal bytes (valid only during this call)
   * @throws BrotliException if the handler aborts
   */
  void insert(ByteBuffer literals) throws BrotliException;

  /**
   * Notifies of a backward copy when {@link #needsCommands()} is true.
   *
   * @param distance LZ77 distance
   * @param length copy length
   * @throws BrotliException if the handler aborts
   */
  void copy(int distance, int length) throws BrotliException;

  /**
   * Notifies of a static-dictionary reference when {@link #needsCommands()} is true.
   *
   * @param copyLength requested copy length
   * @param wordIndex dictionary word index
   * @param transformId transform id (0..120)
   * @throws BrotliException if the handler aborts
   */
  void dictionary(int copyLength, int wordIndex, int transformId) throws BrotliException;

  /**
   * Indicates the end of the current metablock.
   *
   * @throws BrotliException if the handler aborts
   */
  void endMetablock() throws BrotliException;

  /**
   * Indicates the end of the Brotli stream.
   *
   * @throws BrotliException if the handler aborts
   */
  void endStream() throws BrotliException;

  /**
   * Whether this handler needs LZ77 command events ({@link #insert}, {@link #copy}, {@link
   * #dictionary}). Default is false so the decoder can skip that work.
   *
   * @return true if command events are wanted
   */
  default boolean needsCommands() {
    return false;
  }
}
