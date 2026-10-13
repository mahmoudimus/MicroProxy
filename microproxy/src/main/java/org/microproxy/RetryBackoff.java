package org.microproxy;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.random.RandomGenerator;

/**
 * How long the proxy waits before trying the next route after a connection attempt failed: the
 * next chained proxy, or the direct fallback, that the {@link ChainedProxyManager} offered. Set for
 * the whole server with {@link HttpProxyServerBootstrap#withChainedProxyRetryBackoff(RetryBackoff)}
 * and for one request with {@link HttpFilters#chainedProxyRetryBackoff()}.
 *
 * <p>The built-in policies:
 *
 * <ul>
 *   <li>{@link #none()}: no waiting; the next route is tried at once (the default).
 *   <li>{@link #fixed(Duration)}: the same wait before every retry.
 *   <li>{@link #exponential(Duration, Duration)}: deterministic doubling, {@code initial}, {@code 2
 *       x initial}, {@code 4 x initial}, ... capped at {@code max}, without jitter. Each wait is
 *       known in advance, which suits tests that depend on exact timings, as LittleProxy forks that
 *       added a backoff did.
 *   <li>{@link #exponentialWithJitter(Duration, Duration)}: the same doubling ceiling, but each
 *       wait is a uniformly random time between zero and that ceiling ("full jitter"), so that
 *       clients failing together do not retry together.
 * </ul>
 *
 * <p>Attempts are counted from the first: the wait before attempt {@code n + 1} is {@link
 * #delay(int) delay(n)}, where {@code n} attempts have failed. Instances are immutable and
 * thread-safe, and equal when they wait the same way.
 */
public final class RetryBackoff {

    private static final RetryBackoff NONE = new RetryBackoff(0, 0, false);

    /** A {@link ThreadLocalRandom} for whichever thread draws from it. */
    private static final RandomGenerator THREAD_LOCAL = new RandomGenerator() {
        @Override
        public long nextLong() {
            return ThreadLocalRandom.current().nextLong();
        }

        @Override
        public double nextDouble() {
            return ThreadLocalRandom.current().nextDouble();
        }
    };

    private final long initialNanos;
    private final long maxNanos;
    private final boolean jitter;

    private RetryBackoff(long initialNanos, long maxNanos, boolean jitter) {
        this.initialNanos = initialNanos;
        this.maxNanos = maxNanos;
        this.jitter = jitter;
    }

    /**
     * No waiting: the next route is tried as soon as an attempt fails.
     *
     * @return the policy that never waits
     */
    public static RetryBackoff none() {
        return NONE;
    }

    /**
     * The same wait before every retry, without jitter: {@code exponential(delay, delay)}.
     *
     * @param delay the wait, positive
     * @return the policy
     * @throws IllegalArgumentException if {@code delay} is not positive
     * @throws NullPointerException if {@code delay} is null
     */
    public static RetryBackoff fixed(Duration delay) {
        return exponential(delay, delay);
    }

    /**
     * Deterministic doubling: waits {@code initial} before the second attempt, then twice as long
     * before each further one, capped at {@code max}, without jitter. For example {@code
     * exponential(100 ms, 1 s)} waits 100, 200, 400, 800, 1000, 1000, ... ms.
     *
     * @param initial the wait before the second attempt, positive
     * @param max the longest wait, at least {@code initial}
     * @return the policy
     * @throws IllegalArgumentException if {@code initial} is not positive or {@code max} is below
     *     it
     * @throws NullPointerException if either is null
     */
    public static RetryBackoff exponential(Duration initial, Duration max) {
        return of(initial, max, false);
    }

    /**
     * Exponential backoff with "full jitter": before attempt {@code n + 1}, a uniformly random time
     * from zero up to (not including) the {@link #exponential} wait {@code min(max, initial x
     * 2^(n-1))}. On average it waits half as long as {@link #exponential}, and spreads the retries
     * of clients that failed at the same time.
     *
     * @param initial the ceiling of the wait before the second attempt, positive
     * @param max the ceiling of every wait, at least {@code initial}
     * @return the policy
     * @throws IllegalArgumentException if {@code initial} is not positive or {@code max} is below
     *     it
     * @throws NullPointerException if either is null
     */
    public static RetryBackoff exponentialWithJitter(Duration initial, Duration max) {
        return of(initial, max, true);
    }

    private static RetryBackoff of(Duration initial, Duration max, boolean jitter) {
        Objects.requireNonNull(initial, "initial");
        Objects.requireNonNull(max, "max");
        if (!initial.isPositive()) {
            throw new IllegalArgumentException("the initial backoff must be positive: " + initial);
        }
        if (max.compareTo(initial) < 0) {
            throw new IllegalArgumentException("the maximum backoff " + max + " is below the initial " + initial);
        }
        try {
            return new RetryBackoff(initial.toNanos(), max.toNanos(), jitter);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("the maximum backoff is too long: " + max, e);
        }
    }

    /**
     * Whether this policy never waits ({@link #none()}).
     *
     * @return whether every delay is zero
     */
    public boolean isNone() {
        return maxNanos == 0;
    }

    /**
     * The wait before the second attempt (its ceiling, with jitter); zero for {@link #none()}.
     *
     * @return the initial wait
     */
    public Duration initial() {
        return Duration.ofNanos(initialNanos);
    }

    /**
     * The longest wait; zero for {@link #none()}.
     *
     * @return the maximum wait
     */
    public Duration max() {
        return Duration.ofNanos(maxNanos);
    }

    /**
     * Whether the waits are random ({@link #exponentialWithJitter}) rather than exact.
     *
     * @return whether the policy jitters its waits
     */
    public boolean jittered() {
        return jitter;
    }

    /**
     * The longest wait before the attempt that follows {@code failedAttempts} failed ones: {@code
     * min(max, initial x 2^(failedAttempts-1))}. Without jitter it is the wait itself.
     *
     * @param failedAttempts how many attempts have failed, at least 1
     * @return the wait's ceiling
     * @throws IllegalArgumentException if {@code failedAttempts} is below 1
     */
    public Duration ceiling(int failedAttempts) {
        return Duration.ofNanos(ceilingNanos(failedAttempts));
    }

    private long ceilingNanos(int failedAttempts) {
        if (failedAttempts < 1) throw new IllegalArgumentException("no attempt has failed: " + failedAttempts);
        int doublings = Math.min(failedAttempts - 1, 62);
        return initialNanos > (maxNanos >> doublings) ? maxNanos : Math.min(maxNanos, initialNanos << doublings);
    }

    /**
     * The wait before the attempt that follows {@code failedAttempts} failed ones, drawing the
     * jitter (if any) from a {@link ThreadLocalRandom}.
     *
     * @param failedAttempts how many attempts have failed, at least 1
     * @return the wait
     * @throws IllegalArgumentException if {@code failedAttempts} is below 1
     */
    public Duration delay(int failedAttempts) {
        return delay(failedAttempts, THREAD_LOCAL);
    }

    /**
     * The wait before the attempt that follows {@code failedAttempts} failed ones. With jitter it
     * is the {@link #ceiling} scaled by {@code random.nextDouble()} (clamped to {@code [0, 1]}).
     * Without jitter it is the ceiling, and {@code random} is not used.
     *
     * @param failedAttempts how many attempts have failed, at least 1
     * @param random where the jitter comes from
     * @return the wait
     * @throws IllegalArgumentException if {@code failedAttempts} is below 1
     */
    public Duration delay(int failedAttempts, RandomGenerator random) {
        long ceiling = ceilingNanos(failedAttempts);
        if (!jitter || ceiling == 0) return Duration.ofNanos(ceiling);
        double fraction = Math.min(1.0, Math.max(0.0, random.nextDouble()));
        return Duration.ofNanos((long) (ceiling * fraction));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RetryBackoff other && initialNanos == other.initialNanos && maxNanos == other.maxNanos
                && jitter == other.jitter;
    }

    @Override
    public int hashCode() {
        return Objects.hash(initialNanos, maxNanos, jitter);
    }

    /** {@return how the policy is made, such as {@code exponential(PT0.1S, PT2S)}} */
    @Override
    public String toString() {
        if (isNone()) return "none()";
        if (!jitter && initialNanos == maxNanos) return "fixed(" + initial() + ")";
        return (jitter ? "exponentialWithJitter(" : "exponential(") + initial() + ", " + max() + ")";
    }
}
