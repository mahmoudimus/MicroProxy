package io.github.mahmoudimus.quic.connection;

/**
 * A monotonic clock in nanoseconds, injected into the connection layer so that timers can be
 * driven deterministically in tests. The components of this package never read a clock; they take
 * {@code now} as an argument, which the connection reads from its {@code NanoClock}.
 *
 * <p>Times from one clock are compared directly, so a clock must not wrap during a connection's
 * lifetime ({@link System#nanoTime()} wraps after 292 years).
 */
@FunctionalInterface
public interface NanoClock {

    /**
     * The time that is not set, used where a time is optional. No clock returns it.
     */
    long NONE = Long.MIN_VALUE;

    /**
     * The current time.
     *
     * @return nanoseconds from an arbitrary origin, never {@link #NONE}
     */
    long nanoTime();

    /**
     * The system's monotonic clock.
     *
     * @return a clock backed by {@link System#nanoTime()}
     */
    static NanoClock system() {
        return System::nanoTime;
    }
}
