/*
 * The RemoteCidQueue tests up to alwaysValid are ported from quinn-proto src/cid_queue.rs (tests)
 * (Apache-2.0).
 */
package io.github.mahmoudimus.quic.connection;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.StatelessResetToken;
import io.github.mahmoudimus.quic.frame.Frame;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ConnectionIdTest {

    private static final long SECOND = 1_000_000_000L;
    private static final int LEN = RemoteCidQueue.DEFAULT_LIMIT;
    private static final byte[] KEY = new byte[32];

    private static Frame.NewConnectionId cid(long sequence, long retirePriorTo) {
        byte[] id = new byte[8];
        Arrays.fill(id, (byte) 0xAB);
        byte[] token = new byte[16];
        Arrays.fill(token, (byte) 0xCD);
        return new Frame.NewConnectionId(sequence, retirePriorTo, ConnectionId.of(id), StatelessResetToken.of(token));
    }

    private static Frame.NewConnectionId cid(long sequence, long retirePriorTo, int idByte) {
        byte[] id = new byte[8];
        Arrays.fill(id, (byte) idByte);
        byte[] token = new byte[16];
        Arrays.fill(token, (byte) idByte);
        return new Frame.NewConnectionId(sequence, retirePriorTo, ConnectionId.of(id), StatelessResetToken.of(token));
    }

    private static ConnectionId initialCid() {
        byte[] id = new byte[8];
        Arrays.fill(id, (byte) 0xFF);
        return ConnectionId.of(id);
    }

    private static RemoteCidQueue.InsertError insertError(RemoteCidQueue q, Frame.NewConnectionId f) {
        try {
            q.insert(f);
            return null;
        } catch (RemoteCidQueue.CidInsertException e) {
            return e.error();
        }
    }

    @Test
    void nextDense() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        assertNull(q.next());
        assertNull(q.next());
        for (long i = 1; i < LEN; i++) {
            q.insert(cid(i, 0));
        }
        for (long i = 1; i < LEN; i++) {
            RemoteCidQueue.Retired r = q.next();
            assertEquals(i, q.activeSeq());
            assertEquals(1, r.end() - r.start());
        }
        assertNull(q.next());
    }

    @Test
    void nextSparse() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        for (long i = 2; i < LEN; i += 2) {
            q.insert(cid(i, 0));
        }
        for (long i = 2; i < LEN; i += 2) {
            RemoteCidQueue.Retired r = q.next();
            assertEquals(i, q.activeSeq());
            assertEquals(Math.max(q.activeSeq() - 2, 0), r.start());
            assertEquals(q.activeSeq(), r.end());
        }
        assertNull(q.next());
    }

    @Test
    void wrap() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        for (long i = 1; i < LEN; i++) {
            q.insert(cid(i, 0));
        }
        for (long i = 1; i < LEN - 1; i++) {
            q.next();
        }
        for (long i = LEN; i < LEN + 3; i++) {
            q.insert(cid(i, 0));
        }
        for (long i = LEN - 1; i < LEN + 3; i++) {
            q.next();
            assertEquals(i, q.activeSeq());
        }
        assertNull(q.next());
    }

    @Test
    void retireDense() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        for (long i = 1; i < LEN; i++) {
            q.insert(cid(i, 0));
        }
        assertEquals(0, q.activeSeq());
        RemoteCidQueue.Retired r = q.insert(cid(4, 2));
        assertEquals(0, r.start());
        assertEquals(2, r.end());
        assertEquals(2, q.activeSeq());
        assertNull(q.insert(cid(4, 2)));
        for (long i = 2; i < LEN - 1; i++) {
            q.next();
            assertEquals(i + 1, q.activeSeq());
            assertNull(q.insert(cid(i + 1, i + 1)));
        }
        assertNull(q.next());
    }

    @Test
    void retireSparse() throws Exception {
        // Retiring 0 when 1 is unknown retires 1 too, moving to 2
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        q.insert(cid(2, 0));
        RemoteCidQueue.Retired r = q.insert(cid(3, 1));
        assertEquals(0, r.start());
        assertEquals(2, r.end());
        assertEquals(2, q.activeSeq());
    }

    @Test
    void retireMany() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        q.insert(cid(2, 0));
        RemoteCidQueue.Retired r = q.insert(cid(1_000_000, 1_000_000));
        assertEquals(0, r.start());
        assertEquals(LEN, r.end());
        assertEquals(1_000_000, q.activeSeq());
    }

    @Test
    void insertLimit() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        assertNull(q.insert(cid(LEN - 1, 0)));
        assertEquals(RemoteCidQueue.InsertError.EXCEEDS_LIMIT, insertError(q, cid(LEN, 0)));
    }

    @Test
    void insertDuplicate() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        q.insert(cid(0, 0));
        q.insert(cid(0, 0));
    }

    @Test
    void insertRetired() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        assertNull(q.insert(cid(0, 0)), "reinserting the active ID succeeds");
        assertNull(q.next(), "the active ID isn't requeued");
        q.insert(cid(1, 0));
        q.next();
        assertEquals(RemoteCidQueue.InsertError.RETIRED, insertError(q, cid(0, 0)));
    }

    @Test
    void retireThenInsertNext() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        for (long i = 1; i < LEN; i++) {
            q.insert(cid(i, 0));
        }
        q.next();
        q.insert(cid(LEN, 0));
        assertEquals(RemoteCidQueue.InsertError.EXCEEDS_LIMIT, insertError(q, cid(LEN + 1, 0)));
    }

    @Test
    void alwaysValid() {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        assertNull(q.next());
        assertEquals(initialCid(), q.active());
        assertEquals(0, q.activeSeq());
    }

    // ---- our own ----

    @Test
    void remoteQueueHonoursOurActiveConnectionIdLimit() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid(), 2);
        Retransmits pending = new Retransmits();
        assertNull(q.onNewConnectionId(cid(1, 0, 1), pending));
        QuicException e = assertThrows(QuicException.class, () -> q.onNewConnectionId(cid(2, 0, 2), pending));
        assertEquals(QuicException.CONNECTION_ID_LIMIT_ERROR, e.code());

        // Retiring the first makes room: the peer may exceed the limit if it retires the excess
        StatelessResetToken token = q.onNewConnectionId(cid(2, 1, 2), pending);
        assertEquals(cid(1, 0, 1).resetToken(), token, "ID 1 is now in use");
        assertEquals(List.of(0L), pending.retireCids);
        assertEquals(1, q.activeSeq());
        assertEquals(cid(1, 0, 1).connectionId(), q.active());
        assertThrows(IllegalArgumentException.class, () -> new RemoteCidQueue(initialCid(), 1));
    }

    @Test
    void remoteQueueRejectsReusedSequenceNumbersAndRetiresStaleOnes() throws Exception {
        RemoteCidQueue q = new RemoteCidQueue(initialCid());
        Retransmits pending = new Retransmits();
        q.onNewConnectionId(cid(1, 0, 1), pending);
        assertNull(q.onNewConnectionId(cid(1, 0, 1), pending), "a duplicate frame is harmless");
        QuicException e = assertThrows(QuicException.class, () -> q.onNewConnectionId(cid(1, 0, 9), pending));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());

        // Retire Prior To 3 jumps past 1 and 2
        q.onNewConnectionId(cid(3, 3, 3), pending);
        assertEquals(List.of(0L, 1L, 2L), pending.retireCids);
        // A late NEW_CONNECTION_ID for 2 is retired at once
        assertNull(q.onNewConnectionId(cid(2, 0, 2), pending));
        assertEquals(List.of(0L, 1L, 2L, 2L), pending.retireCids);
    }

    @Test
    void zeroLengthPeerIdsCannotBeReplaced() {
        RemoteCidQueue q = new RemoteCidQueue(ConnectionId.EMPTY);
        QuicException e = assertThrows(QuicException.class, () -> q.onNewConnectionId(cid(1, 0), new Retransmits()));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
    }

    @Test
    void randomGeneratorMakesDistinctIdsOfTheConfiguredLength() {
        RandomConnectionIdGenerator gen = new RandomConnectionIdGenerator(12, -1, new Random(3));
        Set<ConnectionId> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            ConnectionId id = gen.generateCid();
            assertEquals(12, id.length());
            assertTrue(seen.add(id));
        }
        assertEquals(12, gen.cidLength());
        assertTrue(gen.validate(ConnectionId.EMPTY));
        assertEquals(8, new RandomConnectionIdGenerator().generateCid().length());
        assertThrows(IllegalArgumentException.class, () -> new RandomConnectionIdGenerator(21, -1, new Random()));
    }

    private static LocalCidState local(long lifetime) {
        RandomConnectionIdGenerator gen = new RandomConnectionIdGenerator(8, lifetime, new Random(5));
        return new LocalCidState(gen, KEY, 0, gen.generateCid());
    }

    @Test
    void issuanceHasSequenceNumbersAndResetTokens() {
        LocalCidState state = local(-1);
        assertEquals(1, state.issuedCount(), "the handshake ID is sequence 0");
        assertEquals(3, state.initialIssueCount(4));
        assertEquals(7, state.initialIssueCount(100), "at most eight at once");
        List<IssuedCid> ids = state.issue(0, 3);
        assertEquals(List.of(1L, 2L, 3L), ids.stream().map(IssuedCid::sequence).toList());
        for (IssuedCid id : ids) {
            assertEquals(StatelessResetToken.derive(KEY, id.id()), id.resetToken());
            assertEquals(id.resetToken(), state.resetToken(id.id()));
        }
        assertNotEquals(ids.get(0).resetToken(), ids.get(1).resetToken());
        assertEquals(Set.of(0L, 1L, 2L, 3L), new HashSet<>(state.activeSequences()));
        assertEquals(0, state.retirePriorTo());
        assertEquals(NanoClock.NONE, state.nextTimeout(), "IDs without a lifetime never expire");
    }

    @Test
    void retirementIsLimitedByThePeersLimit() throws Exception {
        LocalCidState state = local(-1);
        List<IssuedCid> ids = state.issue(0, 1); // the peer allows 2: sequence 0 and 1
        LocalCidState.Retirement r = state.onRetireConnectionId(0, ids.get(0).id(), 2);
        assertNotEquals(null, r.retired());
        assertTrue(r.issueReplacement(), "one active, the limit is 2");

        IssuedCid replacement = state.issue(0, 1).get(0);
        assertEquals(2, replacement.sequence());
        assertEquals(Set.of(1L, 2L), new HashSet<>(state.activeSequences()));

        // Retiring again is harmless but issues nothing
        r = state.onRetireConnectionId(0, ids.get(0).id(), 2);
        assertNull(r.retired());
        assertFalse(r.issueReplacement());
    }

    @Test
    void invalidRetirementsAreProtocolViolations() {
        LocalCidState state = local(-1);
        List<IssuedCid> ids = state.issue(0, 2);
        QuicException e = assertThrows(QuicException.class, () -> state.onRetireConnectionId(3, ConnectionId.EMPTY, 8));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code(), "never issued");
        e = assertThrows(QuicException.class, () -> state.onRetireConnectionId(1, ids.get(0).id(), 8));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code(), "the ID of its own packet");

        RandomConnectionIdGenerator empty = new RandomConnectionIdGenerator(0, -1, new Random());
        LocalCidState zero = new LocalCidState(empty, KEY, 0, ConnectionId.EMPTY);
        e = assertThrows(QuicException.class, () -> zero.onRetireConnectionId(0, ConnectionId.EMPTY, 8));
        assertEquals(QuicException.PROTOCOL_VIOLATION, e.code());
        assertTrue(zero.issue(0, 3).isEmpty());
        assertEquals(0, zero.initialIssueCount(8));
    }

    @Test
    void lifetimesRotateIdsThroughRetirePriorTo() throws Exception {
        LocalCidState state = local(60 * SECOND);
        ConnectionId handshake = state.activeCids().get(0L);
        assertEquals(60 * SECOND, state.nextTimeout());
        List<IssuedCid> batch = state.issue(10 * SECOND, 2); // sequences 1 and 2, one batch
        assertEquals(60 * SECOND, state.nextTimeout());

        // The handshake ID expires: Retire Prior To becomes 1, and a new ID carries it
        assertTrue(state.onCidTimeout());
        assertEquals(1, state.retirePriorTo());
        assertEquals(70 * SECOND, state.nextTimeout());
        state.issue(60 * SECOND, 1); // sequence 3, expires at 120 s

        // The batch expires before the peer retired sequence 0: Retire Prior To must not move
        // (RFC 9000 section 5.1.2), so no new ID is pushed
        assertFalse(state.onCidTimeout(), "ID 0 is still active");
        assertEquals(1, state.retirePriorTo());

        // Once the peer retires 0, the next expiry advances Retire Prior To past everything
        // expired, up to sequence 3
        state.onRetireConnectionId(0, batch.get(0).id(), 8);
        assertFalse(state.activeCids().containsValue(handshake));
        assertEquals(120 * SECOND, state.nextTimeout());
        assertTrue(state.onCidTimeout());
        assertEquals(4, state.retirePriorTo());
    }

    @Test
    void resetTokensAreStablePerConnectionId() {
        ConnectionId id = ConnectionId.of(new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
        StatelessResetToken t1 = StatelessResetToken.derive(KEY, id);
        StatelessResetToken t2 = local(-1).resetToken(id);
        assertEquals(t1, t2);
        assertArrayEquals(t1.toByteArray(), t2.toByteArray());
    }
}
