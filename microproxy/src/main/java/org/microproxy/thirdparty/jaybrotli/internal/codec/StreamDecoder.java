/*
 * StreamDecoder.java
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

package org.microproxy.thirdparty.jaybrotli.internal.codec;

import org.microproxy.thirdparty.jaybrotli.BrotliContentHandler;
import org.microproxy.thirdparty.jaybrotli.BrotliDefaultHandler;
import org.microproxy.thirdparty.jaybrotli.BrotliEndStreamHandler;
import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliHandler;
import org.microproxy.thirdparty.jaybrotli.CorruptStreamException;
import org.microproxy.thirdparty.jaybrotli.LimitExceededException;
import org.microproxy.thirdparty.jaybrotli.MetablockKind;
import org.microproxy.thirdparty.jaybrotli.TruncatedStreamException;
import org.microproxy.thirdparty.jaybrotli.config.Limits;
import java.nio.ByteBuffer;

/**
 * Event-driven Brotli decoder (RFC 7932), with optional large-window support.
 *
 * <p>Feed compressed bytes with {@link #receive(ByteBuffer)}; reconstructed output and optional
 * LZ77 events are delivered through a {@link BrotliHandler}. Decoding is incremental and resumes
 * mid-symbol across buffer boundaries.
 */
public final class StreamDecoder extends MetablockDecoder {
  /** Creates a decoder with default limits and a no-op handler. */
  public StreamDecoder() {
    reset();
  }

  /**
   * Sets the event handler. Must be called before {@link #receive}.
   *
   * @param handler event handler (null restores the default no-op)
   */
  public void setHandler(BrotliHandler handler) {
    this.handler = (handler != null) ? handler : new BrotliDefaultHandler();
    this.handlerBound = false;
    this.needsCommands = this.handler.needsCommands();
  }

  /**
   * Registers a decoded-content callback before receive, returning this decoder. Replaces only the
   * content callback; other handler events remain available. The callback runs synchronously on the
   * calling thread. Its buffer is valid only during the call. Registration survives {@link
   * #reset()}.
   *
   * @param callback callback, or null to use the full handler's content method
   * @return this decoder
   */
  public StreamDecoder onContent(BrotliContentHandler callback) {
    this.contentCallback = callback;
    return this;
  }

  /**
   * Registers a stream-completion callback before receive, returning this decoder. Called
   * synchronously after successful decoding of the complete stream. Replaces only the full
   * handler's endStream event. Registration survives reset.
   *
   * @param callback callback, or null to use the full handler's endStream method
   * @return this decoder
   */
  public StreamDecoder onEndStream(BrotliEndStreamHandler callback) {
    this.endStreamCallback = callback;
    return this;
  }

  /**
   * Alias for {@link #onContent(BrotliContentHandler)}.
   *
   * @param callback callback, or null to use the full handler's content method
   */
  public void setContentHandler(BrotliContentHandler callback) {
    onContent(callback);
  }

  /**
   * Allows the RFC 9841 large-window format (window bits 10..30). Disabled by default. Set before
   * receive; survives reset. Resource limits remain independent and default to a maximum of 24
   * window bits.
   *
   * @param enabled whether to accept large-window streams
   */
  public void setLargeWindow(boolean enabled) {
    if (handlerBound) {
      throw new IllegalStateException("large-window mode cannot change after decoding starts");
    }
    largeWindowAllowed = enabled;
  }

  /**
   * Sets resource limits.
   *
   * @param limits limits (null restores defaults)
   */
  public void setLimits(Limits limits) {
    this.limits = (limits != null) ? limits : new Limits();
  }

  /**
   * Sets how many literal bytes may accumulate in the ring before {@link BrotliHandler#content} is
   * invoked. Smaller values increase callback frequency; {@code 1} emits after every literal. The
   * default is 4096. Pending output is always flushed at literal-run boundaries, before copies, and
   * when decoding pauses for more input.
   *
   * @param bytes threshold in bytes (must be &gt;= 1)
   */
  public void setContentEmitThreshold(int bytes) {
    if (bytes < 1) {
      throw new IllegalArgumentException("contentEmitThreshold must be >= 1");
    }
    this.contentEmitThreshold = bytes;
  }

  /**
   * Feeds the next chunk of compressed data.
   *
   * @param data compressed bytes in read mode
   * @throws BrotliException on format or limit errors
   */
  public void receive(ByteBuffer data) throws BrotliException {
    if (data == null) {
      throw new NullPointerException("data");
    }
    if (state == DecoderState.DONE) {
      throw new BrotliException("Decoder already finished");
    }
    bindHandler();
    br.setInput(data);
    try {
      process();
      if (state != DecoderState.DONE) {
        flushContentEmit();
        br.savePending();
      }
    } catch (BrotliException e) {
      abort();
      throw located(e);
    } catch (RuntimeException | Error e) {
      abort();
      throw e;
    }
  }

  /**
   * Marks end of compressed input and finishes decoding.
   *
   * @throws BrotliException if the stream is incomplete or invalid
   */
  public void close() throws BrotliException {
    try {
      if (state == DecoderState.DONE) return;
      bindHandler();
      br.markEof();
      process();
      if (state != DecoderState.DONE)
        throw new TruncatedStreamException(
            "Unexpected end of Brotli stream", br.byteOffset(), br.bitOffset());
    } catch (BrotliException e) {
      throw located(e);
    } finally {
      abort();
    }
  }

  private BrotliException located(BrotliException e) {
    if (e instanceof LimitExceededException)
      return new LimitExceededException(e.getMessage(), br.byteOffset(), br.bitOffset());
    if (e instanceof CorruptStreamException)
      return new CorruptStreamException(e.getMessage(), br.byteOffset(), br.bitOffset());
    if (e instanceof TruncatedStreamException)
      return new TruncatedStreamException(e.getMessage(), br.byteOffset(), br.bitOffset());
    return e;
  }

  /** Resets the decoder for a new stream. */
  public void setOffHeap(boolean enabled) {
    if (ring != null || state != DecoderState.WINDOW_BITS)
      throw new IllegalStateException("Decoder already started");
    offHeap = enabled;
  }

  /** Releases resources without accepting an incomplete stream. */
  public void abort() {
    if (ring != null) ring.close();
    state = DecoderState.DONE;
  }

  public void reset() {
    if (ring != null) ring.close();
    br.reset();
    distRing.reset();
    state = DecoderState.WINDOW_BITS;
    wbits = 0;
    largeWindowStream = false;
    windowSize = 0;
    ring = null;
    metablockIndex = 0;
    isLast = false;
    isLastEmpty = false;
    mnibbles = 0;
    mlen = 0;
    metaSkipLen = 0;
    metaSkipRead = 0;
    metaBuf = null;
    uncompressedRead = 0;
    uncompressedBuf = null;
    metablockWritten = 0L;
    kind = MetablockKind.COMPRESSED;
    clearCompressedState();
    p1 = 0;
    p2 = 0;
    contentEmitPending = 0;
    handlerBound = false;
  }

  private void bindHandler() {
    if (!handlerBound) {
      handler.setLocator(locator);
      needsCommands = handler.needsCommands();
      handlerBound = true;
    }
  }

  protected void clearCompressedState() {
    npostfix = 0;
    ndirect = 0;
    distanceAlphabetSize = 0;
    for (int i = 0; i < 3; i++) {
      nbltypes[i] = 1;
      btype[i] = 0;
      btypePrev[i] = 1;
      blen[i] = 1 << 24;
      htreeBtype[i] = null;
      htreeBlen[i] = null;
    }
    contextModes = null;
    ntreesL = 1;
    ntreesD = 1;
    cmapL = null;
    cmapD = null;
    htreeL = null;
    htreeI = null;
    htreeD = null;
    headerCategory = 0;
    headerPhase = 0;
    treesRead = 0;
    contextMapIndex = 0;
    contextMapSize = 0;
    contextMapRleMax = -1;
    contextMapTree = null;
    contextMapTarget = null;
    contextMapNtrees = 0;
    readingLiteralContextMap = true;
    insertLen = 0;
    copyLen = 0;
    implicitDistance0 = false;
    literalsRemaining = 0;
    distance = 0;
    distanceCode = 0;
    distanceResolved = false;
    insertAccum = null;
    insertAccumLen = 0;
    insertView = null;
  }
}
