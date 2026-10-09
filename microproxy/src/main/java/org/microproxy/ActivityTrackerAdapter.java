package org.microproxy;

/** An {@link ActivityTracker} that ignores everything; extend it and override what you need. */
public class ActivityTrackerAdapter implements ActivityTracker {
    /** Creates an observer whose activity callbacks do nothing. */
    public ActivityTrackerAdapter() {}
}
