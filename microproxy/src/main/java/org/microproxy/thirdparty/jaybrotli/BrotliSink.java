/*
 * BrotliSink.java
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
 * Sink for compressed Brotli output produced by {@link Encoder}.
 *
 * <p>The buffer is valid <strong>only during the callback</strong>.
 */
public interface BrotliSink {

  /**
   * Receives a chunk of compressed bytes.
   *
   * @param data compressed bytes in read mode (valid only during this call)
   * @throws BrotliException if the sink aborts
   */
  void compressed(ByteBuffer data) throws BrotliException;
}
