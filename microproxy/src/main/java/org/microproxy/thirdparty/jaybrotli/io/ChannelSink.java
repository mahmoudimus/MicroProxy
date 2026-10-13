/*
 * ChannelSink.java
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

package org.microproxy.thirdparty.jaybrotli.io;

import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliSink;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

/** {@link BrotliSink} that writes compressed bytes to a {@link WritableByteChannel}. */
public final class ChannelSink implements BrotliSink, ByteSink {

  private final WritableByteChannel channel;

  /**
   * Creates a sink that writes to the given channel.
   *
   * @param channel destination channel
   */
  public ChannelSink(WritableByteChannel channel) {
    if (channel == null) {
      throw new NullPointerException("channel");
    }
    if (channel instanceof java.nio.channels.SelectableChannel selectable
        && !selectable.isBlocking()) {
      throw new IllegalArgumentException("A blocking channel is required");
    }
    this.channel = channel;
  }

  public void write(ByteBuffer data) throws BrotliException {
    compressed(data);
  }

  @Override
  public void compressed(ByteBuffer data) throws BrotliException {
    try {
      while (data.hasRemaining()) {
        if (Thread.currentThread().isInterrupted()) {
          throw new java.io.InterruptedIOException("Brotli operation interrupted");
        }
        int n = channel.write(data);
        if (n <= 0) {
          throw new BrotliException("Channel made no progress while writing");
        }
      }
    } catch (IOException e) {
      throw new BrotliException("Write failed", e);
    }
  }
}
