package org.microproxy;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
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
 * #delay(int) delay(n)}, where {@code n} attempts have failed.
 *
 * <p>The waits of one request add up to at most a budget; once it is spent, the remaining routes
 * are tried without waiting. By default the budget is the request's connect timeout, at most 30
 * seconds, so a long route list cannot hold a request for minutes. {@link #withBudget(Duration)}
 * sets another total, and {@link #unbudgeted()} lifts it: every wait the policy names is then
 * waited, as LittleProxy forks that added a backoff did. Either way a client that leaves ends the
 * wait.
 *
 * <p>Instances are immutable and thread-safe, and equal when they wait the same way.
 */
public final class RetryBackoff {

    /** {@link #budgetNanos} for the default budget: the connect timeout, at most 30 seconds. */
    private static final long DEFAULT_BUDGET = -1;
    /** {@link #budgetNanos} for no budget at all. */
    private static final long UNBUDGETED = Long.MAX_VALUE;

    private static final RetryBackoff NONE = new RetryBackoff(0, 0, false, DEFAULT_BUDGET);

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
    /** The most all waits of one request may add up to: {@link #DEFAULT_BUDGET}, {@link #UNBUDGETED} or a positive budget. */
    private final long budgetNanos;

    private RetryBackoff(long initialNanos, long maxNanos, boolean jitter, long budgetNanos) {
        this.initialNanos = initialNanos;
        this.maxNanos = maxNanos;
        this.jitter = jitter;
        this.budgetNanos = budgetNanos;
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
            return new RetryBackoff(initial.toNanos(), max.toNanos(), jitter, DEFAULT_BUDGET);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("the maximum backoff is too long: " + max, e);
        }
    }

    /**
     * This policy with {@code total} as the most that all waits of one request may add up to, in
     * place of the default (the request's connect timeout, at most 30 seconds). Once the budget is
     * spent, the remaining routes are tried without waiting; the wait that would overrun it is
     * shortened to what is left. A budget too long to count in nanoseconds (about 292 years) is
     * no budget, as {@link #unbudgeted()}. {@link #none()} never waits, and stays as it is.
     *
     * @param total the budget for all waits of one request, positive
     * @return the policy with that budget
     * @throws IllegalArgumentException if {@code total} is not positive
     * @throws NullPointerException if {@code total} is null
     */
    public RetryBackoff withBudget(Duration total) {
        Objects.requireNonNull(total, "total");
        if (!total.isPositive()) {
            throw new IllegalArgumentException("the backoff budget must be positive: " + total);
        }
        long nanos;
        try {
            nanos = total.toNanos();
        } catch (ArithmeticException e) {
            nanos = UNBUDGETED;
        }
        return withBudgetNanos(nanos);
    }

    /**
     * This policy without a budget: every wait it names is waited, however long they add up to
     * (the route list and each wait's {@link #max()} still bound them), as LittleProxy forks that
     * added a backoff did. A client that leaves still ends the wait. {@link #none()} never waits,
     * and stays as it is.
     *
     * @return the policy without a budget
     */
    public RetryBackoff unbudgeted() {
        return withBudgetNanos(UNBUDGETED);
    }

    /**
     * This policy with the default budget again: the request's connect timeout, at most 30
     * seconds.
     *
     * @return the policy with the default budget
     */
    public RetryBackoff withDefaultBudget() {
        return withBudgetNanos(DEFAULT_BUDGET);
    }

    private RetryBackoff withBudgetNanos(long nanos) {
        if (isNone() || nanos == budgetNanos) return this;
        return new RetryBackoff(initialNanos, maxNanos, jitter, nanos);
    }

    /**
     * The budget set with {@link #withBudget(Duration)}: the most all waits of one request may add
     * up to. Empty when the default budget applies (the request's connect timeout, at most 30
     * seconds) and when there is none ({@link #isUnbudgeted()}).
     *
     * @return the policy's own budget, or empty
     */
    public Optional<Duration> budget() {
        return budgetNanos == DEFAULT_BUDGET || budgetNanos == UNBUDGETED ? Optional.empty()
                : Optional.of(Duration.ofNanos(budgetNanos));
    }

    /**
     * Whether the waits of one request have no budget ({@link #unbudgeted()}).
     *
     * @return whether every wait the policy names is waited
     */
    public boolean isUnbudgeted() {
        return budgetNanos == UNBUDGETED;
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
                && jitter == other.jitter && budgetNanos == other.budgetNanos;
    }

    @Override
    public int hashCode() {
        return Objects.hash(initialNanos, maxNanos, jitter, budgetNanos);
    }

    /**
     * {@return how the policy is made, such as {@code exponential(PT0.1S, PT2S)} or {@code
     * fixed(PT1S).unbudgeted()}}
     */
    @Override
    public String toString() {
        if (isNone()) return "none()";
        String made = !jitter && initialNanos == maxNanos ? "fixed(" + initial() + ")"
                : (jitter ? "exponentialWithJitter(" : "exponential(") + initial() + ", " + max() + ")";
        if (budgetNanos == UNBUDGETED) return made + ".unbudgeted()";
        return budgetNanos == DEFAULT_BUDGET ? made : made + ".withBudget(" + Duration.ofNanos(budgetNanos) + ")";
    }
}
