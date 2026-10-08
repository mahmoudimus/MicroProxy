package org.microproxy.impl;

import java.lang.System.Logger.Level;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.microproxy.ActivityTracker;

/** Fans activity events out to all registered trackers, isolating their failures. */
final class Trackers {

    private static final System.Logger LOG = System.getLogger(Trackers.class.getName());

    private final List<ActivityTracker> trackers = new CopyOnWriteArrayList<>();

    void add(ActivityTracker tracker) {
        trackers.add(tracker);
    }

    List<ActivityTracker> list() {
        return List.copyOf(trackers);
    }

    boolean isEmpty() {
        return trackers.isEmpty();
    }

    void fire(Consumer<ActivityTracker> event) {
        for (ActivityTracker t : trackers) {
            try {
                event.accept(t);
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "ActivityTracker threw", e);
            }
        }
    }
}
