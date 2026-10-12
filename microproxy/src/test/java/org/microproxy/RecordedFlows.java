package org.microproxy;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

/** An {@link ActivityTracker} that keeps every {@link FlowRecord}, for tests of access logs. */
public final class RecordedFlows implements ActivityTracker {

    public final List<FlowRecord> records = new CopyOnWriteArrayList<>();

    @Override
    public void flowEnded(FlowRecord record) {
        records.add(record);
    }

    /** The first record that matches, once there is one (failing after a while). */
    public FlowRecord await(String what, Predicate<FlowRecord> matches) {
        TestSupport.eventually(what + " in " + records, () -> records.stream().anyMatch(matches));
        return records.stream().filter(matches).findFirst().orElseThrow();
    }

    /** The first record of {@code kind}, once there is one. */
    public FlowRecord await(FlowRecord.Kind kind) {
        return await("a " + kind.label() + " record", r -> r.kind() == kind);
    }

    /** The first record of {@code kind}, once there is one, waiting up to {@code timeout} for it. */
    public FlowRecord await(FlowRecord.Kind kind, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (records.stream().noneMatch(r -> r.kind() == kind)) {
            if (System.nanoTime() - deadline > 0) {
                throw new AssertionError("timed out waiting for a " + kind.label() + " record in " + records);
            }
            Thread.sleep(10);
        }
        return records.stream().filter(r -> r.kind() == kind).findFirst().orElseThrow();
    }
}
