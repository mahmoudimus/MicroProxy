/*
 * MetablockDecoder.java
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
import org.microproxy.thirdparty.jaybrotli.BrotliLocator;
import org.microproxy.thirdparty.jaybrotli.CorruptStreamException;
import org.microproxy.thirdparty.jaybrotli.LimitExceededException;
import org.microproxy.thirdparty.jaybrotli.MetablockKind;
import org.microproxy.thirdparty.jaybrotli.config.Limits;
import org.microproxy.thirdparty.jaybrotli.config.TrailingData;
import org.microproxy.thirdparty.jaybrotli.internal.bits.ArrayBitSource;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitCursor;
import org.microproxy.thirdparty.jaybrotli.internal.bits.BitReader;
import org.microproxy.thirdparty.jaybrotli.internal.history.Dictionary;
import org.microproxy.thirdparty.jaybrotli.internal.history.DistanceCoding;
import org.microproxy.thirdparty.jaybrotli.internal.history.DistanceRing;
import org.microproxy.thirdparty.jaybrotli.internal.history.Histories;
import org.microproxy.thirdparty.jaybrotli.internal.history.History;
import org.microproxy.thirdparty.jaybrotli.internal.history.HistoryReplayer;
import org.microproxy.thirdparty.jaybrotli.internal.history.RingBuffer;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.HuffmanTable;
import org.microproxy.thirdparty.jaybrotli.internal.huffman.PrefixCode;
import org.microproxy.thirdparty.jaybrotli.internal.ir.Command;
import org.microproxy.thirdparty.jaybrotli.internal.metablock.Context;
import org.microproxy.thirdparty.jaybrotli.internal.parse.LengthCoder;
import java.nio.ByteBuffer;

/**
 * Event-driven Brotli decoder (RFC 7932), with optional large-window support.
 *
 * <p>Feed compressed bytes with {@link StreamDecoder#receive(ByteBuffer)}; reconstructed output
 * and optional LZ77 events are delivered through a {@link BrotliHandler}. Decoding is incremental
 * and resumes mid-symbol across buffer boundaries.
 */
public abstract class MetablockDecoder {
  protected abstract void clearCompressedState();

  protected enum DecoderState {
    WINDOW_BITS,
    METABLOCK_BEGIN,
    METABLOCK_ISLASTEMPTY,
    METABLOCK_MNIBBLES,
    METABLOCK_MLEN,
    METABLOCK_METADATA,
    METABLOCK_UNCOMPRESSED_BIT,
    METABLOCK_UNCOMPRESSED_DATA,
    METABLOCK_COMPRESSED_HEADER,
    COMMAND_LOOP,
    FINISH,
    DONE
  }

  protected static final int BLOCK_CATEGORY_L = 0;
  protected static final int BLOCK_CATEGORY_I = 1;
  protected static final int BLOCK_CATEGORY_D = 2;

  /** Default max literal bytes before a {@link BrotliHandler#content} callback. */
  protected static final int DEFAULT_CONTENT_EMIT_THRESHOLD = 4096;

  protected final BitReader br = new ArrayBitSource();
  protected final DistanceRing distRing = new DistanceRing();
  protected final int[] tmpBits = new int[1];
  protected final int[] unpackOut = new int[3];
  protected final byte[] dictScratch = new byte[Dictionary.MAX_TRANSFORMED_WORD_LENGTH];
  protected final int[] mtfScratch = new int[256];
  protected final LocatorImpl locator = new LocatorImpl();

  /** Literal bytes written to the ring but not yet passed to {@code content}. */
  protected int contentEmitPending;

  protected int contentEmitThreshold = DEFAULT_CONTENT_EMIT_THRESHOLD;

  protected BrotliHandler handler = new BrotliDefaultHandler();
  protected BrotliContentHandler contentCallback;
  protected BrotliEndStreamHandler endStreamCallback;
  protected final BrotliHandler contentDispatcher =
      new BrotliDefaultHandler() {
        @Override
        public void content(ByteBuffer data, boolean end) throws BrotliException {
          if (contentCallback != null) {
            contentCallback.content(data, end);
          } else {
            handler.content(data, end);
          }
        }
      };

  protected Limits limits = new Limits();
  protected TrailingData trailingData = TrailingData.REJECT;

  /** True once the last meta-block has been decoded and its padding verified. */
  protected boolean finished;

  /** Compressed length of the stream in bytes once {@link #finished}; -1 before. */
  protected long streamLength = -1L;
  protected boolean handlerBound;
  protected boolean needsCommands;

  protected DecoderState state = DecoderState.WINDOW_BITS;
  protected int wbits;
  protected int windowSize;
  protected History ring;
  protected boolean offHeap;
  protected int metablockIndex;
  protected boolean isLast;
  protected boolean isLastEmpty;
  protected int mnibbles;
  protected int mlen;
  protected int metaSkipLen;
  protected int metaSkipRead;
  protected byte[] metaBuf;
  protected int uncompressedRead;
  protected byte[] uncompressedBuf;
  protected long metablockWritten;
  protected MetablockKind kind;

  // Compressed metablock state
  protected boolean largeWindowAllowed;
  protected boolean largeWindowStream;
  protected int distanceAlphabetLimit;
  protected int npostfix;
  protected int ndirect;
  protected int distanceAlphabetSize;

  protected int[] nbltypes = new int[3];
  protected int[] btype = new int[3];
  protected int[] btypePrev = new int[3];
  protected int[] blen = new int[3];
  protected HuffmanTable[] htreeBtype = new HuffmanTable[3];
  protected HuffmanTable[] htreeBlen = new HuffmanTable[3];

  protected int[] contextModes;
  protected int ntreesL;
  protected int ntreesD;
  protected int[] cmapL;
  protected int[] cmapD;
  protected HuffmanTable[] htreeL;
  protected HuffmanTable[] htreeI;
  protected HuffmanTable[] htreeD;

  // Header-reading progress
  protected int headerCategory;
  protected int headerPhase;
  protected int treesRead;
  protected int contextMapIndex;
  protected int contextMapSize;
  protected int contextMapRleMax;
  protected HuffmanTable contextMapTree;
  protected int[] contextMapTarget;
  protected int contextMapNtrees;
  protected boolean readingLiteralContextMap;

  // Command loop
  protected int insertLen;
  protected int copyLen;
  protected boolean implicitDistance0;
  protected int literalsRemaining;
  protected int distance;
  protected int distanceCode;
  protected boolean distanceResolved;
  protected int p1;
  protected int p2;
  protected byte[] insertAccum;
  protected int insertAccumLen;
  protected ByteBuffer insertView;

  // Lookup tables of the current meta-block's prefix codes, for the fast command loop.
  protected int[][] lutL;
  protected int[][] lutI;
  protected int[][] lutD;

  /**
   * Input bytes the fast command loop needs before it starts a command: enough for the worst-case
   * command header (block switches, symbol and extra bits, about 140 bits) and its distance, so it
   * never has to check for underflow. Per literal it needs {@link #FAST_LITERAL_MARGIN}.
   */
  protected static final int FAST_COMMAND_MARGIN = 64;

  protected static final int FAST_LITERAL_MARGIN = 16;

  /**
   * Ring bytes kept free of output that has not been emitted yet: a short copy may write up to 16
   * bytes past its end (see {@link RingBuffer#copyWithin}), which must never overwrite output the
   * content callback has not seen. Brotli keeps the same 16 bytes out of its window.
   */
  protected static final int RING_SLACK = 16;

  /** Per insert-and-copy symbol: insert base | insert extra bits << 24. */
  private static final int[] CMD_INSERT = new int[704];

  /** Per insert-and-copy symbol: copy base | copy extra bits << 24 | implicit distance << 31. */
  private static final int[] CMD_COPY = new int[704];

  static {
    int[] unpacked = new int[3];
    for (int sym = 0; sym < 704; sym++) {
      LengthCoder.unpack(sym, unpacked);
      CMD_INSERT[sym] =
          LengthCoder.INSERT_BASE[unpacked[0]] | LengthCoder.INSERT_EXTRA_BITS[unpacked[0]] << 24;
      CMD_COPY[sym] =
          LengthCoder.COPY_BASE[unpacked[1]]
              | LengthCoder.COPY_EXTRA_BITS[unpacked[1]] << 24
              | unpacked[2] << 31;
    }
  }

  protected final class LocatorImpl implements BrotliLocator {
    @Override
    public long getByteOffset() {
      return br.getByteOffset();
    }

    @Override
    public int getBitOffset() {
      return br.getBitOffset();
    }

    @Override
    public int getMetablockIndex() {
      return metablockIndex;
    }
  }

  protected void process() throws BrotliException {
    while (true) {
      switch (state) {
        case WINDOW_BITS:
          if (!readWindowBits()) {
            return;
          }
          break;
        case METABLOCK_BEGIN:
          if (!readMetablockBegin()) {
            return;
          }
          break;
        case METABLOCK_ISLASTEMPTY:
          if (!readIsLastEmpty()) {
            return;
          }
          break;
        case METABLOCK_MNIBBLES:
          if (!readMnibbles()) {
            return;
          }
          break;
        case METABLOCK_MLEN:
          if (!readMlen()) {
            return;
          }
          break;
        case METABLOCK_METADATA:
          if (!readMetadata()) {
            return;
          }
          break;
        case METABLOCK_UNCOMPRESSED_BIT:
          if (!readUncompressedBit()) {
            return;
          }
          break;
        case METABLOCK_UNCOMPRESSED_DATA:
          if (!readUncompressedData()) {
            return;
          }
          break;
        case METABLOCK_COMPRESSED_HEADER:
          if (!readCompressedHeader()) {
            return;
          }
          break;
        case COMMAND_LOOP:
          if (!processCommands()) {
            return;
          }
          break;
        case FINISH:
          finishStream();
          state = DecoderState.DONE;
          return;
        case DONE:
          return;
        default:
          throw new CorruptStreamException("Invalid decoder state");
      }
    }
  }

  protected boolean readWindowBits() throws BrotliException {
    BitCursor checkpoint = br.mark();
    if (!br.tryReadBits(1, tmpBits)) {
      br.resetTo(checkpoint);
      return false;
    }
    if (tmpBits[0] == 0) {
      wbits = 16;
    } else {
      if (!br.tryReadBits(3, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      int n = tmpBits[0];
      if (n != 0) {
        wbits = 17 + n;
      } else {
        if (!br.tryReadBits(3, tmpBits)) {
          br.resetTo(checkpoint);
          return false;
        }
        n = tmpBits[0];
        if (n == 1) {
          if (!largeWindowAllowed) {
            throw new CorruptStreamException("Large-window Brotli requires explicit opt-in");
          }
          if (!br.tryReadBits(1, tmpBits)) {
            br.resetTo(checkpoint);
            return false;
          }
          if (tmpBits[0] != 0) {
            throw new CorruptStreamException("Invalid large-window marker");
          }
          if (!br.tryReadBits(6, tmpBits)) {
            br.resetTo(checkpoint);
            return false;
          }
          wbits = tmpBits[0];
          largeWindowStream = true;
        } else if (n == 0) {
          wbits = 17;
        } else {
          wbits = 8 + n;
        }
      }
    }

    if (wbits < 10 || wbits > (largeWindowStream ? 30 : 24)) {
      throw new CorruptStreamException("WBITS out of range: " + wbits);
    }
    LimitChecks.checkWindowBits(limits, wbits);
    windowSize = (1 << wbits) - 16;
    ring = Histories.create(wbits, offHeap);
    handler.windowBits(wbits);
    state = DecoderState.METABLOCK_BEGIN;
    return true;
  }

  protected boolean readMetablockBegin() throws BrotliException {
    if (!br.tryReadBits(1, tmpBits)) {
      return false;
    }
    isLast = tmpBits[0] != 0;
    isLastEmpty = false;
    metablockWritten = 0L;
    clearCompressedState();
    if (isLast) {
      state = DecoderState.METABLOCK_ISLASTEMPTY;
    } else {
      state = DecoderState.METABLOCK_MNIBBLES;
    }
    return true;
  }

  protected boolean readIsLastEmpty() throws BrotliException {
    if (!br.tryReadBits(1, tmpBits)) {
      return false;
    }
    isLastEmpty = tmpBits[0] != 0;
    if (isLastEmpty) {
      state = DecoderState.FINISH;
      return true;
    }
    state = DecoderState.METABLOCK_MNIBBLES;
    return true;
  }

  protected boolean readMnibbles() throws BrotliException {
    if (!br.tryReadBits(2, tmpBits)) {
      return false;
    }
    int code = tmpBits[0];
    if (code == 3) {
      mnibbles = 0;
      kind = MetablockKind.METADATA;
      state = DecoderState.METABLOCK_METADATA;
      headerPhase = 0;
      return true;
    }
    mnibbles = code + 4;
    state = DecoderState.METABLOCK_MLEN;
    return true;
  }

  protected boolean readMlen() throws BrotliException {
    int bits = mnibbles * 4;
    if (!br.tryReadBits(bits, tmpBits)) {
      return false;
    }
    mlen = tmpBits[0] + 1;
    if (mnibbles > 4) {
      int nibbleMask = 0xf << ((mnibbles - 1) * 4);
      if ((tmpBits[0] & nibbleMask) == 0) {
        throw new CorruptStreamException("Invalid MLEN: trailing nibble zero");
      }
    }
    LimitChecks.checkMetablockLength(limits, mlen);
    if (!isLast) {
      state = DecoderState.METABLOCK_UNCOMPRESSED_BIT;
    } else {
      kind = MetablockKind.COMPRESSED;
      reserveRing();
      handler.startMetablock(mlen, true, kind);
      headerCategory = 0;
      headerPhase = 0;
      state = DecoderState.METABLOCK_COMPRESSED_HEADER;
    }
    return true;
  }

  /**
   * Grows the ring once for the meta-block about to be decoded, rather than by doubling. Never
   * beyond the output the limits still allow, so a header cannot make the decoder allocate more
   * than the output it would be permitted to write.
   */
  private void reserveRing() {
    if (ring instanceof RingBuffer rb) {
      long budget = limits.enabled() ? limits.maxTotalOutput() - rb.getTotalWritten() : mlen;
      rb.reserve((int) Math.max(0, Math.min(mlen, budget)));
    }
  }

  protected boolean readUncompressedBit() throws BrotliException {
    if (!br.tryReadBits(1, tmpBits)) {
      return false;
    }
    if (tmpBits[0] != 0) {
      kind = MetablockKind.UNCOMPRESSED;
      reserveRing();
      handler.startMetablock(mlen, isLast, kind);
      try {
        br.jumpToByteBoundary(true);
      } catch (BrotliException e) {
        throw e;
      }
      uncompressedRead = 0;
      if (uncompressedBuf == null || uncompressedBuf.length < Math.min(mlen, 65536)) {
        uncompressedBuf = new byte[Math.min(Math.max(mlen, 1), 65536)];
      }
      state = DecoderState.METABLOCK_UNCOMPRESSED_DATA;
    } else {
      kind = MetablockKind.COMPRESSED;
      reserveRing();
      handler.startMetablock(mlen, isLast, kind);
      headerCategory = 0;
      headerPhase = 0;
      state = DecoderState.METABLOCK_COMPRESSED_HEADER;
    }
    return true;
  }

  protected boolean readMetadata() throws BrotliException {
    // phase 0: reserved + MSKIPBYTES + MSKIPLEN
    if (headerPhase == 0) {
      BitCursor checkpoint = br.mark();
      if (!br.tryReadBits(1, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      if (tmpBits[0] != 0) {
        throw new CorruptStreamException("Metadata reserved bit must be zero");
      }
      if (!br.tryReadBits(2, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      int mskipBytes = tmpBits[0];
      if (mskipBytes == 0) {
        metaSkipLen = 0;
      } else {
        if (!br.tryReadBits(mskipBytes * 8, tmpBits)) {
          br.resetTo(checkpoint);
          return false;
        }
        metaSkipLen = tmpBits[0] + 1;
        if (mskipBytes > 1) {
          int top = 0xff << ((mskipBytes - 1) * 8);
          if ((tmpBits[0] & top) == 0) {
            throw new CorruptStreamException("Invalid metadata length");
          }
        }
      }

      LimitChecks.checkMetadataLength(limits, metaSkipLen);
      br.jumpToByteBoundary(true);
      handler.startMetablock(0, isLast, MetablockKind.METADATA);
      metaSkipRead = 0;
      if (metaSkipLen > 0) {
        metaBuf = new byte[Math.min(metaSkipLen, 65536)];
      }
      headerPhase = 1;
    }
    while (metaSkipRead < metaSkipLen) {
      int chunk = metaSkipLen - metaSkipRead;
      if (chunk > metaBuf.length) {
        chunk = metaBuf.length;
      }
      int got = br.tryReadBytesAligned(metaBuf, 0, chunk);
      if (got == 0) {
        return false;
      }
      ByteBuffer view = ByteBuffer.wrap(metaBuf, 0, got);
      handler.metadata(view);
      metaSkipRead += got;
      if (got < chunk) {
        return false;
      }
    }
    handler.endMetablock();
    metablockIndex++;
    if (isLast) {
      state = DecoderState.FINISH;
    } else {
      state = DecoderState.METABLOCK_BEGIN;
    }
    return true;
  }

  protected boolean readUncompressedData() throws BrotliException {
    while (uncompressedRead < mlen) {
      int chunk = mlen - uncompressedRead;
      if (chunk > uncompressedBuf.length) {
        chunk = uncompressedBuf.length;
      }
      chunk = Math.min(chunk, ring.getSize());
      int got = br.tryReadBytesAligned(uncompressedBuf, 0, chunk);
      LimitChecks.checkTotalOutput(limits, ring.getTotalWritten() + got);
      if (got == 0) {
        return false;
      }
      if (got >= 2) {
        p2 = uncompressedBuf[got - 2] & 0xff;
        p1 = uncompressedBuf[got - 1] & 0xff;
      } else {
        p2 = p1;
        p1 = uncompressedBuf[0] & 0xff;
      }
      ring.writeBytes(uncompressedBuf, 0, got);
      ring.emitContent(contentDispatcher, got);
      uncompressedRead += got;
      metablockWritten += got;
      LimitChecks.checkTotalOutput(limits, ring.getTotalWritten());
      if (got < chunk) {
        return false;
      }
    }
    handler.endMetablock();
    metablockIndex++;
    if (isLast) {
      state = DecoderState.FINISH;
    } else {
      state = DecoderState.METABLOCK_BEGIN;
    }
    return true;
  }

  /** Reads compressed metablock header. Returns false on underflow. */
  protected boolean readCompressedHeader() throws BrotliException {
    // Phases:
    // 0..2: for each category L,I,D: NBLTYPES + optional trees + first count
    // 3: NPOSTFIX, NDIRECT
    // 4: context modes
    // 5: NTREESL + context map L
    // 6: NTREESD + context map D
    // 7: literal trees
    // 8: insert-and-copy trees
    // 9: distance trees
    while (headerCategory < 3) {
      if (!readBlockTypeGroup(headerCategory)) {
        return false;
      }
      headerCategory++;
      headerPhase = 0;
    }

    if (headerPhase == 0) {
      BitCursor checkpoint = br.mark();
      if (!br.tryReadBits(2, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      npostfix = tmpBits[0];
      if (!br.tryReadBits(4, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      ndirect = tmpBits[0] << npostfix;

      distanceAlphabetSize = DistanceCoding.alphabetSize(largeWindowStream, npostfix, ndirect);
      distanceAlphabetLimit =
          largeWindowStream
              ? DistanceCoding.supportedAlphabetSize(npostfix, ndirect)
              : distanceAlphabetSize;
      headerPhase = 1;
    }

    if (headerPhase == 1) {
      int n = nbltypes[BLOCK_CATEGORY_L];
      if (contextModes == null || contextModes.length != n) {
        contextModes = new int[n];
        treesRead = 0;
      }
      while (treesRead < n) {
        if (!br.tryReadBits(2, tmpBits)) {
          return false;
        }
        contextModes[treesRead] = tmpBits[0];
        treesRead++;
      }
      headerPhase = 2;
      treesRead = 0;
    }

    if (headerPhase == 2) {
      if (!readVarLenUint8PlusOne(tmpBits)) {
        return false;
      }
      ntreesL = tmpBits[0];
      int mapSize = 64 * nbltypes[BLOCK_CATEGORY_L];
      cmapL = new int[mapSize];
      if (ntreesL >= 2) {
        readingLiteralContextMap = true;
        contextMapTarget = cmapL;
        contextMapSize = mapSize;
        contextMapNtrees = ntreesL;
        contextMapIndex = 0;
        contextMapTree = null;
        contextMapRleMax = -1;
        headerPhase = 3;
      } else {
        // already zeros
        headerPhase = 4;
      }
    }

    if (headerPhase == 3) {
      if (!readContextMap()) {
        return false;
      }
      headerPhase = 4;
    }

    if (headerPhase == 4) {
      if (!readVarLenUint8PlusOne(tmpBits)) {
        return false;
      }
      ntreesD = tmpBits[0];
      int mapSize = 4 * nbltypes[BLOCK_CATEGORY_D];
      cmapD = new int[mapSize];
      if (ntreesD >= 2) {
        readingLiteralContextMap = false;
        contextMapTarget = cmapD;
        contextMapSize = mapSize;
        contextMapNtrees = ntreesD;
        contextMapIndex = 0;
        contextMapTree = null;
        contextMapRleMax = -1;
        headerPhase = 5;
      } else {
        headerPhase = 6;
      }
    }

    if (headerPhase == 5) {
      if (!readContextMap()) {
        return false;
      }
      headerPhase = 6;
    }

    if (headerPhase == 6) {
      if (htreeL == null || htreeL.length != ntreesL) {
        htreeL = new HuffmanTable[ntreesL];
        treesRead = 0;
      }
      while (treesRead < ntreesL) {
        HuffmanTable t = PrefixCode.tryRead(br, 256);
        if (t == null) {
          return false;
        }
        htreeL[treesRead] = t;
        treesRead++;
      }
      headerPhase = 7;
      treesRead = 0;
    }

    if (headerPhase == 7) {
      int n = nbltypes[BLOCK_CATEGORY_I];
      if (htreeI == null || htreeI.length != n) {
        htreeI = new HuffmanTable[n];
        treesRead = 0;
      }
      while (treesRead < n) {
        HuffmanTable t = PrefixCode.tryRead(br, 704);
        if (t == null) {
          return false;
        }
        htreeI[treesRead] = t;
        treesRead++;
      }
      headerPhase = 8;
      treesRead = 0;
    }

    if (headerPhase == 8) {
      if (htreeD == null || htreeD.length != ntreesD) {
        htreeD = new HuffmanTable[ntreesD];
        treesRead = 0;
      }
      while (treesRead < ntreesD) {
        HuffmanTable t = PrefixCode.tryRead(br, distanceAlphabetSize, distanceAlphabetLimit);
        if (t == null) {
          return false;
        }
        htreeD[treesRead] = t;
        treesRead++;
      }
      lutL = luts(htreeL);
      lutI = luts(htreeI);
      lutD = luts(htreeD);
      // Ready for commands
      literalsRemaining = 0;
      distanceResolved = false;
      state = DecoderState.COMMAND_LOOP;
      return true;
    }

    return true;
  }

  private static int[][] luts(HuffmanTable[] tables) {
    int[][] luts = new int[tables.length][];
    for (int i = 0; i < tables.length; i++) luts[i] = tables[i].lut();
    return luts;
  }

  protected boolean readBlockTypeGroup(int category) throws BrotliException {
    // headerPhase 0: NBLTYPES
    // 1: btype tree
    // 2: blen tree
    // 3: first block count
    if (headerPhase == 0) {
      if (!readVarLenUint8PlusOne(tmpBits)) {
        return false;
      }
      nbltypes[category] = tmpBits[0];
      btype[category] = 0;
      btypePrev[category] = 1;
      if (nbltypes[category] >= 2) {
        headerPhase = 1;
      } else {
        blen[category] = 1 << 24;
        headerPhase = 0;
        return true; // done with this category
      }
    }
    if (headerPhase == 1) {
      HuffmanTable t = PrefixCode.tryRead(br, nbltypes[category] + 2);
      if (t == null) {
        return false;
      }
      htreeBtype[category] = t;
      headerPhase = 2;
    }
    if (headerPhase == 2) {
      HuffmanTable t = PrefixCode.tryRead(br, 26);
      if (t == null) {
        return false;
      }
      htreeBlen[category] = t;
      headerPhase = 3;
    }
    if (headerPhase == 3) {
      int len = readBlockLength(category);
      if (len < 0) {
        return false;
      }
      blen[category] = len;
      headerPhase = 0;
    }
    return true;
  }

  /**
   * Reads NBLTYPES / NTREES style value (DecodeVarLenUint8 + 1). Writes result to {@code out[0]}.
   * Returns false on underflow.
   */
  protected boolean readVarLenUint8PlusOne(int[] out) throws BrotliException {
    BitCursor checkpoint = br.mark();
    if (!br.tryReadBits(1, tmpBits)) {
      br.resetTo(checkpoint);
      return false;
    }
    if (tmpBits[0] == 0) {
      out[0] = 1;

      return true;
    }
    if (!br.tryReadBits(3, tmpBits)) {
      br.resetTo(checkpoint);
      return false;
    }
    int n = tmpBits[0];
    if (n == 0) {
      out[0] = 2;

      return true;
    }
    if (!br.tryReadBits(n, tmpBits)) {
      br.resetTo(checkpoint);
      return false;
    }
    out[0] = 1 + (1 << n) + tmpBits[0];

    return true;
  }

  /**
   * Reads a block length using the category's block-count Huffman table.
   *
   * @return length, or -1 on underflow
   */
  protected int readBlockLength(int category) throws BrotliException {
    BitCursor checkpoint = br.mark();
    int sym = htreeBlen[category].tryDecode(br);
    if (sym == -2) {
      br.resetTo(checkpoint);
      return -1;
    }
    if (sym < 0 || sym > 25) {
      throw new CorruptStreamException("Invalid block length symbol");
    }
    int nbits = LengthCoder.BLOCK_LEN_EXTRA_BITS[sym];
    if (!br.tryReadBits(nbits, tmpBits)) {
      br.resetTo(checkpoint);
      return -1;
    }

    return LengthCoder.BLOCK_LEN_BASE[sym] + tmpBits[0];
  }

  protected boolean readContextMap() throws BrotliException {
    if (contextMapRleMax < 0) {
      BitCursor checkpoint = br.mark();
      if (!br.tryReadBits(1, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      if (tmpBits[0] == 0) {
        contextMapRleMax = 0;
      } else {
        if (!br.tryReadBits(4, tmpBits)) {
          br.resetTo(checkpoint);
          return false;
        }
        contextMapRleMax = tmpBits[0] + 1;
      }
    }
    if (contextMapTree == null) {
      HuffmanTable t = PrefixCode.tryRead(br, contextMapNtrees + contextMapRleMax);
      if (t == null) {
        return false;
      }
      contextMapTree = t;
      contextMapIndex = 0;
    }

    while (contextMapIndex < contextMapSize) {
      BitCursor checkpoint = br.mark();
      int sym = contextMapTree.tryDecode(br);
      if (sym == -2) {
        br.resetTo(checkpoint);
        return false;
      }
      if (sym < 0) {
        throw new CorruptStreamException("Invalid context map symbol");
      }
      if (sym == 0) {
        contextMapTarget[contextMapIndex++] = 0;

      } else if (sym <= contextMapRleMax) {
        int repBits = sym;
        if (!br.tryReadBits(repBits, tmpBits)) {
          br.resetTo(checkpoint);
          return false;
        }
        int repeat = (1 << repBits) + tmpBits[0];
        if (contextMapIndex + repeat > contextMapSize) {
          throw new CorruptStreamException("Context map RLE overflow");
        }
        for (int r = 0; r < repeat; r++) {
          contextMapTarget[contextMapIndex++] = 0;
        }

      } else {
        contextMapTarget[contextMapIndex++] = sym - contextMapRleMax;
      }
    }

    if (!br.tryReadBits(1, tmpBits)) {
      return false;
    }
    if (tmpBits[0] != 0) {
      inverseMoveToFront(contextMapTarget, contextMapSize, mtfScratch);
    }
    contextMapTree = null;
    contextMapRleMax = -1;
    return true;
  }

  protected static void inverseMoveToFront(int[] v, int vLen, int[] mtf) {
    for (int i = 0; i < 256; i++) {
      mtf[i] = i;
    }
    for (int i = 0; i < vLen; i++) {
      int index = v[i] & 0xff;
      int value = mtf[index];
      v[i] = value;
      for (; index > 0; index--) {
        mtf[index] = mtf[index - 1];
      }
      mtf[0] = value;
    }
  }

  protected boolean processCommands() throws BrotliException {
    boolean fastEligible = !needsCommands && ring instanceof RingBuffer;
    while (metablockWritten < mlen) {
      if (fastEligible && br.fastLimit() - br.fastPosition() >= FAST_COMMAND_MARGIN) {
        fastCommands();
        if (metablockWritten >= mlen) {
          break;
        }
      }
      // Start of new command if no literals remaining mid-insert
      if (literalsRemaining == 0 && !distanceResolved && insertLen == 0 && copyLen == 0) {
        if (!readNextCommand()) {
          return false;
        }
      }

      // Insert literals
      while (literalsRemaining > 0) {
        if (!readOneLiteral()) {
          return false;
        }
      }

      if (metablockWritten >= mlen) {
        // Last command: skip copy
        insertLen = 0;
        copyLen = 0;
        distanceResolved = false;
        break;
      }

      // Resolve and apply copy
      if (!distanceResolved) {
        if (!resolveDistance()) {
          return false;
        }
      }
      if (!applyCopy()) {
        return false;
      }
      insertLen = 0;
      copyLen = 0;
      distanceResolved = false;
    }

    if (literalsRemaining != 0 || metablockWritten != mlen) {
      // Unreachable while inserts are bounded above; kept as a guard so that no path can end a
      // meta-block with a different length than its header declares.
      throw new CorruptStreamException("Meta-block length mismatch");
    }

    // Emit any pending insert command event
    flushContentEmit();
    flushInsertEvent();

    handler.endMetablock();
    metablockIndex++;
    if (isLast) {
      state = DecoderState.FINISH;
    } else {
      state = DecoderState.METABLOCK_BEGIN;
    }
    return true;
  }

  /**
   * Decodes commands while plenty of input is buffered, with the bit accumulator, ring position and
   * output counters in locals and without per-symbol underflow checks. Returns at a command or
   * literal boundary when input runs low or the meta-block is complete, leaving the same state the
   * checked path ({@link #readNextCommand}, {@link #readOneLiteral}, {@link #resolveDistance},
   * {@link #applyCopy}) would have, so decoding resumes there.
   *
   * <p>Output is written straight into the ring buffer and handed to the content callback in
   * batches of the emit threshold, never more than the ring holds.
   */
  protected void fastCommands() throws BrotliException {
    if (distanceResolved) {
      return; // Mid-copy state belongs to the checked path.
    }
    final byte[] in = br.fastBuffer();
    final int inEnd = br.fastLimit();
    int ip = br.fastPosition();
    long acc = br.fastAccumulator();
    int bits = br.fastBitCount();

    final RingBuffer rb = (RingBuffer) ring;
    if (literalsRemaining > 0) {
      rb.reserve(literalsRemaining); // Resuming an insert the checked path started.
    }
    byte[] rd = rb.array();
    int rmask = rd.length - 1;
    long rpos = rb.getPos();
    int pending = contentEmitPending;
    int emitLimit = Math.min(contentEmitThreshold, rd.length - RING_SLACK);
    final long maxOut = limits.enabled() ? limits.maxTotalOutput() : Long.MAX_VALUE;
    final long end = mlen;
    long written = metablockWritten;

    final int[] lookup = Context.lookupTable();
    final boolean trivialLiterals = ntreesL == 1;
    int[] lut0 = lutL[0];
    int typeL = btype[BLOCK_CATEGORY_L];
    int modeOffset = contextModes[typeL] << 9;
    int cmapOffset = typeL << 6;
    int c1 = p1;
    int c2 = p2;
    int[] lutCommand = lutI[btype[BLOCK_CATEGORY_I]];
    int distanceMapOffset = btype[BLOCK_CATEGORY_D] << 2;
    // Once the ring has its final size, writes never need to grow it.
    boolean growable = rb.canGrow();
    // Hot per-literal counters live in locals; the finally block stores them back.
    int lits = literalsRemaining;
    int blenL = blen[BLOCK_CATEGORY_L];

    try {
      while (written < end) {
        if (lits == 0 && copyLen == 0) {
          // ---- Command header ----
          if (inEnd - ip < FAST_COMMAND_MARGIN) {
            return;
          }
          if (blen[BLOCK_CATEGORY_I] == 0 && nbltypes[BLOCK_CATEGORY_I] >= 2) {
            br.fastCommit(acc, bits, ip);
            boolean switched = ensureBlockSwitch(BLOCK_CATEGORY_I);
            acc = br.fastAccumulator();
            bits = br.fastBitCount();
            ip = br.fastPosition();
            if (!switched) {
              return; // Not reachable with the margin checked above; resume on the checked path.
            }
            lutCommand = lutI[btype[BLOCK_CATEGORY_I]];
          }
          blen[BLOCK_CATEGORY_I]--;
          if (bits < 15) {
            acc |= BitReader.longAt(in, ip) << bits;
            ip += (63 - bits) >>> 3;
            bits |= 56;
          }
          int[] lut = lutCommand;
          int e = lut[(int) acc & HuffmanTable.ROOT_MASK];
          if ((e & HuffmanTable.LINK) != 0) {
            e = lut[(e >>> 16) + ((int) (acc >>> HuffmanTable.ROOT_BITS) & ((1 << (e & 0xff)) - 1))];
          }
          if (e == HuffmanTable.INVALID) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Invalid insert-and-copy symbol");
          }
          acc >>>= e & 0xff;
          bits -= e & 0xff;
          int sym = e >>> 16;
          int insert = CMD_INSERT[sym];
          int copy = CMD_COPY[sym];
          if (bits < 24) {
            acc |= BitReader.longAt(in, ip) << bits;
            ip += (63 - bits) >>> 3;
            bits |= 56;
          }
          int n = insert >>> 24;
          int insertLength = (insert & 0xffffff) + (int) (acc & ((1L << n) - 1));
          acc >>>= n;
          bits -= n;
          if (bits < 24) {
            acc |= BitReader.longAt(in, ip) << bits;
            ip += (63 - bits) >>> 3;
            bits |= 56;
          }
          n = (copy >>> 24) & 0x7f;
          copyLen = (copy & 0xffffff) + (int) (acc & ((1L << n) - 1));
          acc >>>= n;
          bits -= n;
          implicitDistance0 = copy < 0;
          // RFC 7932 section 9.3: literals must fit in the rest of the meta-block.
          if (insertLength > end - written) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Insert length exceeds remaining MLEN");
          }
          if (rpos + insertLength > maxOut) {
            br.fastCommit(acc, bits, ip);
            throw new LimitExceededException(
                "Total output " + (rpos + insertLength) + " exceeds limit " + maxOut);
          }
          insertLen = insertLength;
          lits = insertLength;
          distanceResolved = false;
          if (growable && insertLength > 0) {
            rb.advance((int) (rpos - rb.getPos()));
            rb.reserve(insertLength);
            if (rb.array() != rd) {
              rd = rb.array();
              rmask = rd.length - 1;
              emitLimit = Math.min(contentEmitThreshold, rd.length - RING_SLACK);
            }
            growable = rb.canGrow();
          }
        }

        // ---- Literals ----
        while (lits > 0) {
          if (inEnd - ip < FAST_LITERAL_MARGIN) {
            return;
          }
          if (blenL == 0 && nbltypes[BLOCK_CATEGORY_L] >= 2) {
            br.fastCommit(acc, bits, ip);
            blen[BLOCK_CATEGORY_L] = blenL;
            boolean switched = ensureBlockSwitch(BLOCK_CATEGORY_L);
            blenL = blen[BLOCK_CATEGORY_L];
            acc = br.fastAccumulator();
            bits = br.fastBitCount();
            ip = br.fastPosition();
            if (!switched) {
              return; // Not reachable with the margin checked above; resume on the checked path.
            }
            typeL = btype[BLOCK_CATEGORY_L];
            modeOffset = contextModes[typeL] << 9;
            cmapOffset = typeL << 6;
          }
          blenL--;
          if (bits < 15) {
            acc |= BitReader.longAt(in, ip) << bits;
            ip += (63 - bits) >>> 3;
            bits |= 56;
          }
          int[] lut =
              trivialLiterals
                  ? lut0
                  : lutL[
                      cmapL[
                          cmapOffset
                              + (lookup[modeOffset + c1] | lookup[modeOffset + 256 + c2])]];
          int e = lut[(int) acc & HuffmanTable.ROOT_MASK];
          if ((e & HuffmanTable.LINK) != 0) {
            e = lut[(e >>> 16) + ((int) (acc >>> HuffmanTable.ROOT_BITS) & ((1 << (e & 0xff)) - 1))];
          }
          if (e == HuffmanTable.INVALID) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Invalid literal symbol");
          }
          acc >>>= e & 0xff;
          bits -= e & 0xff;
          int literal = e >>> 16;
          rd[(int) rpos & rmask] = (byte) literal;
          rpos++;
          c2 = c1;
          c1 = literal;
          lits--;
          written++;
          if (++pending >= emitLimit) {
            rb.advance((int) (rpos - rb.getPos()));
            contentEmitPending = pending;
            flushContentEmit();
            pending = 0;
          }
        }

        if (written >= end) {
          // The literals completed the meta-block: the copy part is ignored.
          insertLen = 0;
          copyLen = 0;
          break;
        }

        // ---- Distance ----
        if (inEnd - ip < FAST_COMMAND_MARGIN / 2) {
          return;
        }
        int dist;
        if (implicitDistance0) {
          distanceCode = 0;
          dist = distRing.get(0);
        } else {
          if (blen[BLOCK_CATEGORY_D] == 0 && nbltypes[BLOCK_CATEGORY_D] >= 2) {
            br.fastCommit(acc, bits, ip);
            boolean switched = ensureBlockSwitch(BLOCK_CATEGORY_D);
            acc = br.fastAccumulator();
            bits = br.fastBitCount();
            ip = br.fastPosition();
            if (!switched) {
              return; // Not reachable with the margin checked above; resume on the checked path.
            }
            distanceMapOffset = btype[BLOCK_CATEGORY_D] << 2;
          }
          blen[BLOCK_CATEGORY_D]--;
          if (bits < 15) {
            acc |= BitReader.longAt(in, ip) << bits;
            ip += (63 - bits) >>> 3;
            bits |= 56;
          }
          int cid = copyLen > 4 ? 3 : copyLen - 2;
          int[] lut = lutD[cmapD[distanceMapOffset + cid]];
          int e = lut[(int) acc & HuffmanTable.ROOT_MASK];
          if ((e & HuffmanTable.LINK) != 0) {
            e = lut[(e >>> 16) + ((int) (acc >>> HuffmanTable.ROOT_BITS) & ((1 << (e & 0xff)) - 1))];
          }
          int dsym = e >>> 16;
          if (e == HuffmanTable.INVALID || dsym >= distanceAlphabetLimit) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Invalid distance symbol");
          }
          acc >>>= e & 0xff;
          bits -= e & 0xff;
          distanceCode = dsym;
          if (dsym < 16) {
            dist = distRing.resolveShort(dsym);
            if (dist < 1) {
              br.fastCommit(acc, bits, ip);
              throw new CorruptStreamException("Invalid short distance");
            }
          } else if (dsym < 16 + ndirect) {
            dist = dsym - 15;
          } else {
            int code = dsym - ndirect - 16;
            int ndistbits = 1 + (code >> (npostfix + 1));
            long extra = 0;
            int got = 0;
            while (got < ndistbits) {
              // At most 24 bits per read keeps the accumulator from running dry.
              int take = Math.min(24, ndistbits - got);
              if (bits < 24) {
                acc |= BitReader.longAt(in, ip) << bits;
                ip += (63 - bits) >>> 3;
                bits |= 56;
              }
              extra |= (acc & ((1L << take) - 1)) << got;
              acc >>>= take;
              bits -= take;
              got += take;
            }
            int hcode = code >> npostfix;
            int lcode = code & ((1 << npostfix) - 1);
            long offset = ((2L + (hcode & 1)) << ndistbits) - 4;
            long decoded = ((offset + extra) << npostfix) + lcode + ndirect + 1;
            if (decoded > DistanceCoding.MAX_SUPPORTED_DISTANCE) {
              br.fastCommit(acc, bits, ip);
              throw new CorruptStreamException("Distance exceeds supported integer range");
            }
            dist = (int) decoded;
          }
        }
        distance = dist;

        // ---- Copy ----
        long maxDistance = Math.min(rpos, windowSize);
        if (dist <= maxDistance) {
          if (copyLen > end - written) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Copy length exceeds remaining MLEN");
          }
          if (distanceCode != 0) {
            distRing.push(dist);
          }
          if (rpos + copyLen > maxOut) {
            br.fastCommit(acc, bits, ip);
            throw new LimitExceededException(
                "Total output " + (rpos + copyLen) + " exceeds limit " + maxOut);
          }
          int left = copyLen;
          while (left > 0) {
            if (growable) {
              rb.advance((int) (rpos - rb.getPos()));
              rb.reserve(left);
              if (rb.array() != rd) {
                rd = rb.array();
                rmask = rd.length - 1;
                emitLimit = Math.min(contentEmitThreshold, rd.length - RING_SLACK);
              }
              growable = rb.canGrow();
            }
            int room = rd.length - RING_SLACK - pending;
            if (room <= 0) {
              contentEmitPending = pending;
              flushContentEmit();
              pending = 0;
              room = rd.length - RING_SLACK;
            }
            int chunk = Math.min(left, room);
            RingBuffer.copyWithin(rd, rmask, rpos, dist, chunk);
            rpos += chunk;
            pending += chunk;
            written += chunk;
            left -= chunk;
            if (pending >= emitLimit) {
              rb.advance((int) (rpos - rb.getPos()));
              contentEmitPending = pending;
              flushContentEmit();
              pending = 0;
            }
          }
        } else {
          // Static dictionary reference; the distance is not pushed.
          rb.advance((int) (rpos - rb.getPos()));
          int outLen = Dictionary.lookup(copyLen, dist, (int) maxDistance, dictScratch);
          if (outLen < 0) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Invalid dictionary reference");
          }
          if (outLen > end - written) {
            br.fastCommit(acc, bits, ip);
            throw new CorruptStreamException("Dictionary word exceeds remaining MLEN");
          }
          if (rpos + outLen > maxOut) {
            br.fastCommit(acc, bits, ip);
            throw new LimitExceededException(
                "Total output " + (rpos + outLen) + " exceeds limit " + maxOut);
          }
          rb.reserve(outLen);
          if (rb.array() != rd) {
            rd = rb.array();
            rmask = rd.length - 1;
            emitLimit = Math.min(contentEmitThreshold, rd.length - RING_SLACK);
          }
          growable = rb.canGrow();
          if (pending + outLen > rd.length - RING_SLACK) {
            contentEmitPending = pending;
            flushContentEmit();
            pending = 0;
          }
          rb.writeBytes(dictScratch, 0, outLen);
          rpos += outLen;
          pending += outLen;
          written += outLen;
          if (pending >= emitLimit) {
            contentEmitPending = pending;
            flushContentEmit();
            pending = 0;
          }
        }
        c1 = rd[(int) (rpos - 1) & rmask] & 0xff;
        c2 = rd[(int) (rpos - 2) & rmask] & 0xff;
        insertLen = 0;
        copyLen = 0;
        distanceResolved = false;
      }
    } finally {
      // Hand every local back, on normal exit and before an exception propagates.
      br.fastCommit(acc, bits, ip);
      rb.advance((int) (rpos - rb.getPos()));
      contentEmitPending = pending;
      metablockWritten = written;
      literalsRemaining = lits;
      blen[BLOCK_CATEGORY_L] = blenL;
      p1 = c1;
      p2 = c2;
    }
  }

  protected boolean readNextCommand() throws BrotliException {
    if (!ensureBlockSwitch(BLOCK_CATEGORY_I)) {
      return false;
    }

    BitCursor checkpoint = br.mark();
    int sym = htreeI[btype[BLOCK_CATEGORY_I]].tryDecode(br);
    if (sym == -2) {
      br.resetTo(checkpoint);
      return false;
    }
    if (sym < 0 || sym > 703) {
      throw new CorruptStreamException("Invalid insert-and-copy symbol");
    }
    LengthCoder.unpack(sym, unpackOut);
    int insertCode = unpackOut[0];
    int copyCode = unpackOut[1];
    boolean dist0 = unpackOut[2] != 0;

    int ibits = LengthCoder.INSERT_EXTRA_BITS[insertCode];
    if (!br.tryReadBits(ibits, tmpBits)) {
      br.resetTo(checkpoint);
      return false;
    }
    int decodedInsert = LengthCoder.INSERT_BASE[insertCode] + tmpBits[0];

    int cbits = LengthCoder.COPY_EXTRA_BITS[copyCode];
    if (!br.tryReadBits(cbits, tmpBits)) {
      br.resetTo(checkpoint);
      return false;
    }
    int decodedCopy = LengthCoder.COPY_BASE[copyCode] + tmpBits[0];

    // RFC 7932 section 9.3: a command's literals must fit in what remains of the meta-block.
    // The copy part is checked once its distance is known (it is skipped entirely when the
    // literals end the meta-block).
    if (decodedInsert > mlen - metablockWritten) {
      throw new CorruptStreamException("Insert length exceeds remaining MLEN");
    }

    insertLen = decodedInsert;
    copyLen = decodedCopy;
    implicitDistance0 = dist0;
    blen[BLOCK_CATEGORY_I]--;
    literalsRemaining = insertLen;
    distanceResolved = false;
    if (needsCommands && insertLen > 0) {
      if (insertAccum == null || insertAccum.length < insertLen) {
        insertAccum = new byte[insertLen];
      }
      insertAccumLen = 0;
    }
    return true;
  }

  protected boolean ensureBlockSwitch(int category) throws BrotliException {
    if (nbltypes[category] < 2) {
      return true;
    }
    if (blen[category] > 0) {
      return true;
    }
    BitCursor checkpoint = br.mark();
    int sym = htreeBtype[category].tryDecode(br);
    if (sym == -2) {
      br.resetTo(checkpoint);
      return false;
    }
    if (sym < 0) {
      throw new CorruptStreamException("Invalid block type symbol");
    }
    int n = nbltypes[category];
    int newType;
    if (sym == 0) {
      newType = btypePrev[category];
    } else if (sym == 1) {
      newType = btype[category] + 1;
      if (newType >= n) {
        newType = 0;
      }
    } else {
      newType = sym - 2;
      if (newType >= n) {
        throw new CorruptStreamException("Block type out of range");
      }
    }
    int len = readBlockLengthAfterMark(category);
    if (len < 0) {
      // Nothing is committed until the whole switch command has been read: the retry decodes
      // the type symbol again, relative to the same previous types.
      br.resetTo(checkpoint);
      return false;
    }
    btypePrev[category] = btype[category];
    btype[category] = newType;
    blen[category] = len;

    return true;
  }

  /**
   * Like {@link #readBlockLength} but assumes an outer mark is already set (does not mark/reset
   * itself on success path for the Huffman symbol; still needs bits for extra).
   */
  protected int readBlockLengthAfterMark(int category) throws BrotliException {
    int sym = htreeBlen[category].tryDecode(br);
    if (sym == -2) {
      return -1;
    }
    if (sym < 0 || sym > 25) {
      throw new CorruptStreamException("Invalid block length symbol");
    }
    int nbits = LengthCoder.BLOCK_LEN_EXTRA_BITS[sym];
    if (!br.tryReadBits(nbits, tmpBits)) {
      return -1;
    }
    return LengthCoder.BLOCK_LEN_BASE[sym] + tmpBits[0];
  }

  protected boolean readOneLiteral() throws BrotliException {
    if (!ensureBlockSwitch(BLOCK_CATEGORY_L)) {
      return false;
    }

    int mode = contextModes[btype[BLOCK_CATEGORY_L]];
    int cid = Context.literalContextId(mode, p1, p2);
    int treeIndex = cmapL[64 * btype[BLOCK_CATEGORY_L] + cid];
    if (treeIndex < 0 || treeIndex >= ntreesL) {
      throw new CorruptStreamException("Literal context map index out of range");
    }

    int sym = htreeL[treeIndex].tryDecode(br);
    if (sym == -2) {
      return false;
    }
    if (sym < 0 || sym > 255) {
      throw new CorruptStreamException("Invalid literal symbol");
    }

    blen[BLOCK_CATEGORY_L]--;
    byte b = (byte) sym;
    if (needsCommands && insertAccum != null) {
      insertAccum[insertAccumLen++] = b;
    }
    p2 = p1;
    p1 = sym;
    LimitChecks.checkTotalOutput(limits, ring.getTotalWritten() + 1);
    ring.writeByte(b);
    contentEmitPending++;
    if ((needsCommands && literalsRemaining == 1)
        || contentEmitPending >= Math.min(contentEmitThreshold, ring.getSize() - RING_SLACK)) {
      flushContentEmit();
    }
    metablockWritten++;
    literalsRemaining--;
    LimitChecks.checkTotalOutput(limits, ring.getTotalWritten());
    return true;
  }

  protected void flushContentEmit() throws BrotliException {
    if (contentEmitPending <= 0) {
      return;
    }
    ring.emitContent(contentDispatcher, contentEmitPending);
    contentEmitPending = 0;
  }

  protected boolean resolveDistance() throws BrotliException {
    if (implicitDistance0) {
      distanceCode = 0;
      distance = distRing.get(0);
      distanceResolved = true;
      return true;
    }

    if (!ensureBlockSwitch(BLOCK_CATEGORY_D)) {
      return false;
    }

    BitCursor checkpoint = br.mark();
    // Peek: we need to decrement blen only after successful decode
    int cid = Context.distanceContextId(copyLen);
    int treeIndex = cmapD[4 * btype[BLOCK_CATEGORY_D] + cid];
    if (treeIndex < 0 || treeIndex >= ntreesD) {
      throw new CorruptStreamException("Distance context map index out of range");
    }
    int sym = htreeD[treeIndex].tryDecode(br);
    if (sym == -2) {
      br.resetTo(checkpoint);
      return false;
    }
    if (sym < 0 || sym >= distanceAlphabetLimit) {
      throw new CorruptStreamException("Invalid distance symbol");
    }
    distanceCode = sym;

    if (sym < 16) {
      distance = distRing.resolveShort(sym);
      if (distance < 1) {
        throw new CorruptStreamException("Invalid short distance");
      }

    } else if (sym < 16 + ndirect) {
      distance = sym - 15;

    } else {
      int dcode = sym;
      int ndistbits = 1 + ((dcode - ndirect - 16) >> (npostfix + 1));
      if (!br.tryReadBits(ndistbits, tmpBits)) {
        br.resetTo(checkpoint);
        return false;
      }
      int dextra = tmpBits[0];
      int postfixMask = (1 << npostfix) - 1;
      int hcode = (dcode - ndirect - 16) >> npostfix;
      int lcode = (dcode - ndirect - 16) & postfixMask;
      long offset = ((2L + (hcode & 1)) << ndistbits) - 4;
      long decodedDistance = ((offset + dextra) << npostfix) + lcode + ndirect + 1;
      if (decodedDistance > DistanceCoding.MAX_SUPPORTED_DISTANCE) {
        throw new CorruptStreamException("Distance exceeds supported integer range");
      }
      distance = (int) decodedDistance;
    }

    blen[BLOCK_CATEGORY_D]--;
    distanceResolved = true;
    return true;
  }

  protected boolean applyCopy() throws BrotliException {
    if (needsCommands) {
      // Command events interleave with content: deliver this command's literals first.
      flushContentEmit();
      flushInsertEvent();
    }

    long maxAllowed = ring.getTotalWritten();
    if (maxAllowed > windowSize) {
      maxAllowed = windowSize;
    }

    if (distance <= maxAllowed) {
      int remaining = (int) (mlen - metablockWritten);
      if (copyLen > remaining) {
        throw new CorruptStreamException("Copy length exceeds remaining MLEN");
      }
      if (needsCommands) {
        handler.copy(distance, copyLen);
      }
      // RFC §4: do not push distance symbol 0
      if (distanceCode != 0) {
        distRing.push(distance);
      }
      LimitChecks.checkTotalOutput(limits, ring.getTotalWritten() + copyLen);
      int remainingCopy = copyLen;
      while (remainingCopy > 0) {
        // Output is batched across commands; never let unemitted bytes be overwritten.
        int room = ring.getSize() - RING_SLACK - contentEmitPending;
        if (room <= 0) {
          flushContentEmit();
          room = ring.getSize() - RING_SLACK;
        }
        int chunk = Math.min(remainingCopy, room);
        ring.copyBackward(distance, chunk);
        contentEmitPending += chunk;
        remainingCopy -= chunk;
        if (contentEmitPending >= Math.min(contentEmitThreshold, ring.getSize() - RING_SLACK)) {
          flushContentEmit();
        }
      }
      if (needsCommands) {
        flushContentEmit();
      }
      p1 = ring.recent(1) & 0xff;
      p2 = ring.recent(2) & 0xff;
      metablockWritten += copyLen;
      LimitChecks.checkTotalOutput(limits, ring.getTotalWritten());
      return true;
    }

    // Dictionary reference — do not push
    int outLen = Dictionary.lookup(copyLen, distance, (int) maxAllowed, dictScratch);
    if (outLen < 0) {
      throw new CorruptStreamException("Invalid dictionary reference");
    }
    int remaining = (int) (mlen - metablockWritten);
    if (outLen > remaining) {
      throw new CorruptStreamException("Dictionary word exceeds remaining MLEN");
    }
    if (needsCommands) {
      long wordId = (long) distance - (maxAllowed + 1L);
      int nw = Dictionary.nwords(copyLen);
      int wordIndex = (int) (wordId % nw);
      int transformId = (int) (wordId >> Dictionary.ndbits(copyLen));
      handler.dictionary(copyLen, wordIndex, transformId);
    }
    LimitChecks.checkTotalOutput(limits, ring.getTotalWritten() + outLen);
    if (contentEmitPending + outLen > ring.getSize() - RING_SLACK) {
      flushContentEmit();
    }
    HistoryReplayer.dictionary(
        ring, new Command.DictionaryCopy(distance, copyLen, outLen), dictScratch);
    contentEmitPending += outLen;
    if (needsCommands
        || contentEmitPending >= Math.min(contentEmitThreshold, ring.getSize() - RING_SLACK)) {
      flushContentEmit();
    }
    p1 = ring.recent(1) & 0xff;
    p2 = ring.recent(2) & 0xff;
    metablockWritten += outLen;
    LimitChecks.checkTotalOutput(limits, ring.getTotalWritten());
    return true;
  }

  protected void flushInsertEvent() throws BrotliException {
    if (needsCommands && insertAccum != null && insertAccumLen > 0) {
      if (insertView == null) {
        insertView = ByteBuffer.wrap(insertAccum, 0, insertAccumLen);
      } else {
        insertView.clear();
        insertView.limit(insertAccumLen);
      }
      // wrap creates a new buffer each time for correct limit — safer:
      handler.insert(ByteBuffer.wrap(insertAccum, 0, insertAccumLen));
      insertAccumLen = 0;
    }
  }

  protected void finishStream() throws BrotliException {
    flushContentEmit();
    // RFC 7932 section 9.2: the bits that pad the last meta-block to a byte boundary are zero.
    br.jumpToByteBoundary(true);
    streamLength = br.byteOffset();
    if (trailingData == TrailingData.REJECT && br.hasUnconsumedInput()) {
      throw new CorruptStreamException("Trailing bytes after the end of the stream");
    }
    finished = true;
    if (endStreamCallback != null) {
      endStreamCallback.endStream();
    } else {
      handler.endStream();
    }
  }
}
