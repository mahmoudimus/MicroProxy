/*
 * package-info.java
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

/**
 * Event-driven Brotli codec for Java (RFC 7932), with optional large-window support.
 *
 * <p>This package provides a pure-Java encoder and decoder for the Brotli compressed data format.
 * The name <em>brotli</em> is German for a small piece of bread.
 *
 * <h2>Design</h2>
 *
 * <ul>
 *   <li><b>NIO-first</b> — {@link java.nio.ByteBuffer} only;
 *       <p>import org.microproxy.thirdparty.jaybrotli.internal.bits.package-info; import
 *       org.microproxy.thirdparty.jaybrotli.internal.huffman.package-info; import
 *       org.microproxy.thirdparty.jaybrotli.internal.parse.package-info; import
 *       org.microproxy.thirdparty.jaybrotli.internal.metablock.package-info; import
 *       org.microproxy.thirdparty.jaybrotli.internal.history.package-info; import
 *       org.microproxy.thirdparty.jaybrotli.internal.match.package-info; no {@code InputStream}/{@code
 *       OutputStream}
 *   <li><b>Push model</b> — feed bytes via {@code receive(ByteBuffer)}; receive events via a
 *       handler/sink
 *   <li><b>Incremental</b> — chunk-invariant; resumes mid-symbol across buffer boundaries
 * </ul>
 *
 * <h2>Decoding</h2>
 *
 * <pre>{@code
 * Decoder decoder = new Decoder();
 * decoder.setHandler(handler);
 * while (channel.read(buf) > 0) {
 *     buf.flip();
 *     decoder.receive(buf);
 *     buf.compact();
 * }
 * decoder.close();
 * }</pre>
 *
 * <h2>Encoding</h2>
 *
 * <pre>{@code
 * Encoder encoder = new Encoder(sink);
 * encoder.setQuality(1);
 * encoder.receive(uncompressed);
 * encoder.close();
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7932">RFC 7932</a>
 */
package org.microproxy.thirdparty.jaybrotli;
