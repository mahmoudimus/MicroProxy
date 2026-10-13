/*
 * BrotliDefaultHandler.java
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

/** Convenience base class with empty {@link BrotliHandler} implementations. */
public class BrotliDefaultHandler implements BrotliHandler {

  /** Constructs a new default handler. */
  public BrotliDefaultHandler() {}

  @Override
  public void setLocator(BrotliLocator locator) {}

  @Override
  public void windowBits(int wbits) throws BrotliException {}

  @Override
  public void startMetablock(int length, boolean last, MetablockKind kind) throws BrotliException {}

  @Override
  public void content(ByteBuffer data, boolean end) throws BrotliException {}

  @Override
  public void metadata(ByteBuffer data) throws BrotliException {}

  @Override
  public void insert(ByteBuffer literals) throws BrotliException {}

  @Override
  public void copy(int distance, int length) throws BrotliException {}

  @Override
  public void dictionary(int copyLength, int wordIndex, int transformId) throws BrotliException {}

  @Override
  public void endMetablock() throws BrotliException {}

  @Override
  public void endStream() throws BrotliException {}
}
