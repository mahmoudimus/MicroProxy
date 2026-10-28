// Ported from Google quiche quiche/quic/core/quic_chaos_protector.cc (BSD-3-Clause, Copyright
// 2021 The Chromium Authors): CRYPTO frames split at random points, PING frames added, the
// padding spread between the frames, and the frames shuffled, in a packet of the same size.
package io.github.mahmoudimus.quic.connection;

import io.github.mahmoudimus.quic.VarInt;
import io.github.mahmoudimus.quic.frame.Frame;
import io.github.mahmoudimus.quic.frame.FrameDecoder;
import io.github.mahmoudimus.quic.frame.FrameException;
import io.github.mahmoudimus.quic.packet.PacketType;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.random.RandomGenerator;

/**
 * Chrome's "chaos protection" of a client's Initial packets: the ClientHello's CRYPTO data is cut
 * into 3 to 11 frames at random points, 2 to 10 PING frames are added, the padding is spread in
 * random amounts between the frames, and every frame but an ACK is shuffled, so that the packet
 * keeps its size but no two look alike and no middlebox can read the hello by its position.
 */
final class ChaosProtector {

    private static final int MIN_ADDED_CRYPTO_FRAMES = 2;
    private static final int MAX_ADDED_CRYPTO_FRAMES = 10;
    private static final int MIN_ADDED_PING_FRAMES = 2;
    private static final int MAX_ADDED_PING_FRAMES = 10;

    private ChaosProtector() {}

    /**
     * Lays out an Initial packet's frames again, in place: {@code payload}'s bytes from its position
     * to its limit, which keep their length. A payload without both a CRYPTO frame and padding is
     * left as it is, as quiche leaves it.
     *
     * @param payload the plaintext payload, padding included
     * @param random the source of the cuts, counts and order
     */
    static void protect(ByteBuffer payload, RandomGenerator random) {
        List<Frame> decoded;
        // decoded from a copy: the frames' data must not change under them as the payload is rewritten
        ByteBuffer copy = ByteBuffer.allocate(payload.remaining()).put(payload.duplicate()).flip();
        try {
            decoded = FrameDecoder.decodeAll(copy, PacketType.INITIAL);
        } catch (FrameException e) {
            return; // our own frames; nothing to protect if they do not decode
        }
        List<Frame> frames = new ArrayList<>();
        int padding = 0;
        boolean crypto = false;
        for (Frame f : decoded) {
            if (f instanceof Frame.Padding p) {
                padding += p.length();
            } else {
                crypto |= f instanceof Frame.Crypto;
                frames.add(f);
            }
        }
        if (!crypto || padding == 0) return;

        padding = splitCrypto(frames, padding, random);
        padding = addPings(frames, padding, random);
        List<Object> laidOut = spreadPadding(frames, padding, random);
        reorder(laidOut, random);

        ByteBuffer out = payload.duplicate();
        int end = out.limit();
        for (Object item : laidOut) {
            if (item instanceof Integer n) {
                for (int i = 0; i < n; i++) out.put((byte) 0);
            } else {
                ((Frame) item).encode(out);
            }
        }
        while (out.position() < end) out.put((byte) 0);
    }

    /** The bytes a CRYPTO frame takes besides its data: its type, offset and length. */
    private static int overhead(long offset, int length) {
        return 1 + VarInt.size(offset) + VarInt.size(length);
    }

    private static int splitCrypto(List<Frame> frames, int padding, RandomGenerator random) {
        int added = MIN_ADDED_CRYPTO_FRAMES + random.nextInt(MAX_ADDED_CRYPTO_FRAMES + 1 - MIN_ADDED_CRYPTO_FRAMES);
        long maxEnd = 0;
        for (Frame f : frames) {
            if (f instanceof Frame.Crypto c) maxEnd = Math.max(maxEnd, c.offset() + c.data().remaining());
        }
        int maxOverhead = overhead(maxEnd, (int) Math.min(maxEnd, Integer.MAX_VALUE));
        for (int i = 0; i < added; i++) {
            if (padding < maxOverhead) break;
            int index = random.nextInt(frames.size());
            if (!(frames.get(index) instanceof Frame.Crypto c) || c.data().remaining() <= 1) continue;
            int length = c.data().remaining();
            int keep = 1 + random.nextInt(length - 1);
            int oldOverhead = overhead(c.offset(), length);
            Frame.Crypto first = new Frame.Crypto(c.offset(), c.data().duplicate().limit(c.data().position() + keep));
            Frame.Crypto second = new Frame.Crypto(c.offset() + keep, c.data().duplicate().position(c.data().position() + keep));
            frames.set(index, first);
            frames.add(second);
            padding -= overhead(second.offset(), second.data().remaining());
            padding -= overhead(first.offset(), first.data().remaining());
            padding += oldOverhead;
        }
        return padding;
    }

    private static int addPings(List<Frame> frames, int padding, RandomGenerator random) {
        if (padding == 0) return 0;
        int pings = Math.min(MIN_ADDED_PING_FRAMES + random.nextInt(MAX_ADDED_PING_FRAMES + 1 - MIN_ADDED_PING_FRAMES), padding);
        for (int i = 0; i < pings; i++) frames.add(new Frame.Ping());
        return padding - pings;
    }

    /** The frames with runs of padding (as Integers) before some of them, and what is left at the end. */
    private static List<Object> spreadPadding(List<Frame> frames, int padding, RandomGenerator random) {
        List<Object> out = new ArrayList<>();
        for (Frame f : frames) {
            int here = random.nextInt(padding + 1);
            if (here > 0 && !(f instanceof Frame.Ack)) {
                out.add(here);
                padding -= here;
            }
            out.add(f);
        }
        if (padding > 0) out.add(padding);
        return out;
    }

    /** Swaps each item, last first, with a random earlier one, leaving ACK frames where they are. */
    private static void reorder(List<Object> items, RandomGenerator random) {
        for (int i = items.size() - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            if (!(items.get(i) instanceof Frame.Ack) && !(items.get(j) instanceof Frame.Ack)) {
                Collections.swap(items, i, j);
            }
        }
    }
}
