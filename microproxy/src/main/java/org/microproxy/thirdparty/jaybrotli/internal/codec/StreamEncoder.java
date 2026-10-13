/*
 * StreamEncoder.java
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

import org.microproxy.thirdparty.jaybrotli.BrotliEndStreamHandler;
import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.BrotliSink;
import org.microproxy.thirdparty.jaybrotli.internal.bits.ArrayBitSink;
import org.microproxy.thirdparty.jaybrotli.internal.parse.StrategyRegistry;
import java.nio.ByteBuffer;

/**
 * Push-model Brotli encoder.
 *
 * <p>Quality 0 emits uncompressed metablocks. Qualities 1–11 use LZ77 with Huffman coding. Quality
 * 2+ uses the static dictionary; 3+ deepens LZ search; 4+ matches transformed dictionary words; 5+
 * uses literal context maps; 6 adds a literal block split and distance context trees; 7 tunes
 * NPOSTFIX/NDIRECT; 8 uses up to four literal trees and an insert-and-copy block split; 9 uses
 * larger metablocks and a distance block split; 10 uses Zopfli command selection with bounded block
 * splits and context clustering; 11 adds a second Zopfli pass with refined costs and shorter length
 * samples.
 */
public final class StreamEncoder extends MetablockEncoder {
  private boolean failed;

  private void checkFailure() throws BrotliException {
    if (failed) throw new BrotliException("Encoder failed; reset before reuse");
  }
  public void configure(org.microproxy.thirdparty.jaybrotli.config.EncoderOptions options) {
    setLargeWindow(options.largeWindow());
    setWindowBits(options.windowBits().value());
    setQuality(options.quality().value());
    lengthLimiter = options.lengthLimiter();
    explicitMetablockSize = options.metablockSize();
    finderName = options.matchFinder();
    parserName = options.parseStrategy();
    if (!parserName.equals("standard")) {
      StrategyRegistry.finder(finderName);
      StrategyRegistry.parser(parserName);
    }
  }

  /**
   * Creates an encoder configured through {@link #onCompressed(BrotliSink)}. An output callback
   * must be registered before receive, flush, or close.
   */
  public StreamEncoder() {
    this.bw = new ArrayBitSink(this::emitCompressed, false);
  }

  /**
   * Creates an encoder that writes compressed bytes to {@code sink}.
   *
   * @param sink compressed output sink
   */
  public StreamEncoder(BrotliSink sink) {
    this(sink, false);
  }

  /**
   * Creates an encoder.
   *
   * @param sink compressed output sink
   * @param direct whether the bit writer should prefer direct buffers
   */
  public StreamEncoder(BrotliSink sink, boolean direct) {
    if (sink == null) {
      throw new NullPointerException("sink");
    }
    this.sink = sink;
    this.bw = new ArrayBitSink(this::emitCompressed, direct);
  }

  /**
   * Registers compressed output before encoding starts, returning this encoder. Replaces any
   * constructor sink. Buffers are valid only during the callback. The callback runs synchronously
   * on the caller's thread and survives reset.
   *
   * @param callback non-null output callback
   * @return this encoder
   */
  public StreamEncoder onCompressed(BrotliSink callback) {
    if (callback == null) {
      throw new NullPointerException("callback");
    }
    if (headerWritten) {
      throw new IllegalStateException("output callback cannot change after encode started");
    }
    this.sink = callback;
    return this;
  }

  /**
   * Registers successful completion before encoding starts, returning this encoder. Runs
   * synchronously after all final compressed bytes have been delivered. Repeated close calls do not
   * repeat this callback, including if it throws. Registration survives reset.
   *
   * @param callback completion callback, or null to disable
   * @return this encoder
   */
  public StreamEncoder onEndStream(BrotliEndStreamHandler callback) {
    if (headerWritten) {
      throw new IllegalStateException("completion callback cannot change after encode started");
    }
    this.endStreamCallback = callback;
    return this;
  }

  private void emitCompressed(ByteBuffer data) throws BrotliException {
    try {
      sink.compressed(data);
    } catch (BrotliException | RuntimeException | Error failure) {
      failed = true;
      throw failure;
    }
  }

  private void completeStream() throws BrotliException {
    finished = true;
    if (endStreamCallback != null) {
      endStreamCallback.endStream();
    }
  }

  /**
   * Selects the RFC 9841 large-window format, disabled by default. Set before encoding starts. When
   * enabled, window bits may be 10..30. This option survives reset.
   *
   * @param enabled whether to emit the large-window format
   */
  public void setLargeWindow(boolean enabled) {
    if (headerWritten) {
      throw new IllegalStateException("large-window mode cannot change after encoding starts");
    }
    if (!enabled && windowBits > 24) {
      throw new IllegalStateException(
          "reduce windowBits to 24 or less before disabling large-window mode");
    }
    largeWindow = enabled;
  }

  /**
   * Sets compression quality. Accepts 0..11.
   *
   * @param quality compression quality
   */
  public void setQuality(int quality) {
    if (quality < 0 || quality > 11) {
      throw new IllegalArgumentException("quality must be 0..11");
    }
    if (headerWritten) {
      throw new IllegalStateException("quality cannot change after encode started");
    }
    this.quality = quality;
  }

  /**
   * Sets window bits (10–24 normally, 10–30 with large-window mode enabled).
   *
   * @param windowBits WBITS
   */
  public void setWindowBits(int windowBits) {
    if (windowBits < 10 || windowBits > (largeWindow ? 30 : 24)) {
      throw new IllegalArgumentException("windowBits must be 10.." + (largeWindow ? 30 : 24));
    }
    if (headerWritten) {
      throw new IllegalStateException("windowBits cannot change after encode started");
    }
    this.windowBits = windowBits;
  }

  /**
   * Encodes the next chunk of uncompressed input.
   *
   * @param data uncompressed bytes in read mode
   * @throws BrotliException on encode failure
   */
  public void receive(ByteBuffer data) throws BrotliException {
    if (data == null) {
      throw new NullPointerException("data");
    }
    checkFailure();
    if (finished) {
      throw new BrotliException("Encoder already finished");
    }
    ensureHeader();
    if (quality == 0) {
      while (data.hasRemaining()) {
        int chunk = data.remaining();
        if (chunk > MAX_METABLOCK) {
          chunk = MAX_METABLOCK;
        }
        writeUncompressedMetablock(data, chunk, false);
      }
      return;
    }
    int flushAt = metablockFlushSize();
    while (data.hasRemaining()) {
      ensurePendingCapacity(pendingLen + 1);
      int room = pending.length - pendingLen;
      int n = data.remaining();
      if (n > room) {
        n = room;
      }
      data.get(pending, pendingLen, n);
      pendingLen += n;
      while (pendingLen >= flushAt) {
        flushCompressedMetablock(flushAt, false);
      }
    }
  }

  /**
   * Delivers all buffered input and output without ending the stream. An empty metadata
   * metablock supplies a legal byte-aligned boundary, including any residual compressed bits.
   *
   * @throws BrotliException on encode failure; reset is required after an output failure
   */
  public void flush() throws BrotliException {
    checkFailure();
    if (finished) throw new BrotliException("Encoder already finished");
    ensureHeader();
    if (pendingLen > 0) flushCompressedMetablock(pendingLen, false);
    // ISLAST=0, MNIBBLES=3 (metadata), reserved=0, MSKIPBYTES=0 (empty).
    bw.writeBits(0, 1);
    bw.writeBits(3, 2);
    bw.writeBits(0, 3);
    bw.jumpToByteBoundary();
    bw.flush();
  }

  /**
   * Finishes the stream (writes the final empty last metablock if needed).
   *
   * @throws BrotliException on encode failure
   */
  public void close() throws BrotliException {
    checkFailure();
    if (finished) {
      return;
    }
    ensureHeader();
    if (quality == 0) {
      bw.writeBits(1, 1);
      bw.writeBits(1, 1);
      bw.finish();
      completeStream();
      return;
    }
    if (pendingLen > 0) {
      flushCompressedMetablock(pendingLen, true);
    } else {
      bw.writeBits(1, 1);
      bw.writeBits(1, 1);
    }
    bw.finish();
    completeStream();
  }

  /** Metablock flush threshold for the current quality and window. */
  private int metablockFlushSize() {
    if (explicitMetablockSize > 0) return explicitMetablockSize;
    if (quality < 9) {
      return DEFAULT_BLOCK;
    }
    int size = QUALITY9_BLOCK;
    int winCap = 1 << windowBits;
    if (size > winCap) {
      size = winCap;
    }
    if (size > MAX_METABLOCK) {
      size = MAX_METABLOCK;
    }
    return size;
  }

  /** Resets encoder state for a new stream (same sink). */
  public void reset() {
    bw.reset();
    headerWritten = false;
    finished = false;
    failed = false;
    pendingLen = 0;
    historyLen = 0;
    distRing.reset();
  }
}
