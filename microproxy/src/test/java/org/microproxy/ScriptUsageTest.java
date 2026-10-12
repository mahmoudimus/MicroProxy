package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Test;

/** {@link FlowContext#scriptStats()}: the totals of an exchange's calls into scripts. */
class ScriptUsageTest {

    private static FlowContext context() {
        return new FlowContext(1, () -> new InetSocketAddress("127.0.0.1", 1), () -> null, new ClientDetails());
    }

    /** A context made outside the proxy, as the proxy's own resets its totals with each exchange. */
    private static final class Resettable extends FlowContext {
        Resettable() {
            super(2, () -> new InetSocketAddress("127.0.0.1", 2), () -> null, new ClientDetails());
        }

        void nextExchange() {
            resetScriptStats();
        }
    }

    @Test
    void anExchangeWithoutCallsHasNone() {
        FlowContext flow = context();
        assertSame(ScriptUsage.NONE, flow.scriptStats());
        assertEquals(0, flow.scriptStats().calls());
        assertEquals(0, flow.scriptStats().nanos());
        assertEquals(0, flow.scriptStats().steps());
        assertEquals(0, flow.scriptStats().allocBytes());
    }

    @Test
    void callsAddUp() {
        FlowContext flow = context();
        flow.recordScriptCall(1_000, 10, 100);
        flow.recordScriptCall(2_000, 20, 200);
        ScriptUsage usage = flow.scriptStats();
        assertEquals(2, usage.calls());
        assertEquals(3_000, usage.nanos());
        assertEquals(30, usage.steps());
        assertEquals(300, usage.allocBytes());
        assertEquals(0, ScriptUsage.NONE.calls(), "NONE is never added to");
    }

    @Test
    void aServerSideViewSharesItsExchangesTotals() {
        FlowContext flow = context();
        FullFlowContext server = new FullFlowContext(flow, "example.test:80", null, null);
        server.recordScriptCall(5, 1, 1);
        flow.recordScriptCall(5, 1, 1);
        assertEquals(2, flow.scriptStats().calls());
        assertSame(flow.scriptStats(), server.scriptStats());
    }

    @Test
    void aNewExchangeStartsFromZero() {
        Resettable flow = new Resettable();
        flow.recordScriptCall(5, 1, 1);
        flow.nextExchange();
        assertSame(ScriptUsage.NONE, flow.scriptStats());
        flow.recordScriptCall(7, 2, 3);
        assertEquals(1, flow.scriptStats().calls());
        assertEquals(7, flow.scriptStats().nanos());
    }

    @Test
    void callsFromSeveralThreadsAllCount() throws Exception {
        FlowContext flow = context();
        int threads = 8;
        int calls = 10_000;
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> running = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            running.add(Thread.ofVirtual().start(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                for (int i = 0; i < calls; i++) flow.recordScriptCall(1, 2, 3);
            }));
        }
        start.countDown();
        for (Thread t : running) t.join();
        ScriptUsage usage = flow.scriptStats();
        assertEquals((long) threads * calls, usage.calls());
        assertEquals((long) threads * calls, usage.nanos());
        assertEquals(2L * threads * calls, usage.steps());
        assertEquals(3L * threads * calls, usage.allocBytes());
    }
}
