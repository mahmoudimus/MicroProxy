package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.microproxy.ActivityTracker;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.FlowContext;

class TrackersTest {

    private static ActivityTracker named(String name, List<String> calls, boolean fail) {
        return new ActivityTrackerAdapter() {
            @Override
            public void connectionTimedOut(FlowContext ctx) {
                calls.add(name);
                if (fail) throw new IllegalStateException(name + " failed (expected by the test)");
            }
        };
    }

    @Test
    void everyTrackerRunsInOrderEvenWhenOneThrows() {
        Logger log = Logger.getLogger(Trackers.class.getName());
        Level previous = log.getLevel();
        log.setLevel(Level.OFF);
        try {
            List<String> calls = new CopyOnWriteArrayList<>();
            Trackers trackers = new Trackers();
            assertTrue(trackers.isEmpty());
            trackers.add(named("first", calls, true));
            trackers.add(named("second", calls, false));
            trackers.add(named("third", calls, true));
            assertFalse(trackers.isEmpty());

            trackers.fire(t -> t.connectionTimedOut(null));
            trackers.fire(t -> t.connectionTimedOut(null));
            assertEquals(List.of("first", "second", "third", "first", "second", "third"), calls);
            assertEquals(3, trackers.list().size());
        } finally {
            log.setLevel(previous);
        }
    }
}
