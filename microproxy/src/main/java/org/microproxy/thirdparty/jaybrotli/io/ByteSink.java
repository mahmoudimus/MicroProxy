/* SPDX-License-Identifier: Apache-2.0 */
package org.microproxy.thirdparty.jaybrotli.io;

import org.microproxy.thirdparty.jaybrotli.BrotliException;

@FunctionalInterface
public interface ByteSink {
  void write(java.nio.ByteBuffer data) throws BrotliException;
}
