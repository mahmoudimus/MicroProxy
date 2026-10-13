package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.SplittableRandom;
import java.util.random.RandomGenerator;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/** {@link RetryBackoff}: the waits each policy chooses, computed without waiting. */
class RetryBackoffTest {

    private static final Duration MS = Duration.ofMillis(1);

    /** A generator that fails if drawn from: deterministic policies must not use it. */
    private static final RandomGenerator NEVER = () -> {
        throw new AssertionError("drew a random number");
    };

    private static List<Duration> delays(RetryBackoff backoff, int attempts, RandomGenerator random) {
        return IntStream.rangeClosed(1, attempts).mapToObj(n -> backoff.delay(n, random)).toList();
    }

    private static List<Duration> millis(long... values) {
        return java.util.Arrays.stream(values).mapToObj(Duration::ofMillis).toList();
    }

    @Test
    void exponentialDoublesExactlyUpToTheMaximum() {
        RetryBackoff backoff = RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofSeconds(1));
        assertEquals(millis(100, 200, 400, 800, 1000, 1000), delays(backoff, 6, NEVER));
        assertEquals(millis(100, 200, 400, 800, 1000, 1000), delays(backoff, 6, NEVER), "the same every time");
        assertEquals(Duration.ofMillis(400), backoff.delay(3));
        assertEquals(Duration.ofSeconds(1), backoff.delay(Integer.MAX_VALUE, NEVER), "no overflow");
        assertFalse(backoff.jittered());
        assertFalse(backoff.isNone());
        assertEquals(Duration.ofMillis(100), backoff.initial());
        assertEquals(Duration.ofSeconds(1), backoff.max());
    }

    @Test
    void exponentialWithoutARealCapKeepsDoubling() {
        RetryBackoff backoff = RetryBackoff.exponential(Duration.ofSeconds(1), Duration.ofDays(365 * 200));
        assertEquals(Duration.ofSeconds(1L << 20), backoff.delay(21, NEVER));
        assertEquals(Duration.ofDays(365 * 200), backoff.delay(64, NEVER));
    }

    @Test
    void fixedWaitsTheSameEveryTime() {
        RetryBackoff backoff = RetryBackoff.fixed(Duration.ofMillis(250));
        assertEquals(millis(250, 250, 250, 250), delays(backoff, 4, NEVER));
        assertEquals(RetryBackoff.exponential(Duration.ofMillis(250), Duration.ofMillis(250)), backoff);
        assertEquals("fixed(PT0.25S)", backoff.toString());
    }

    @Test
    void noneNeverWaits() {
        RetryBackoff none = RetryBackoff.none();
        assertTrue(none.isNone());
        assertEquals(List.of(Duration.ZERO, Duration.ZERO, Duration.ZERO), delays(none, 3, NEVER));
        assertEquals(Duration.ZERO, none.max());
        assertEquals("none()", none.toString());
    }

    @Test
    void fullJitterScalesTheExponentialCeiling() {
        RetryBackoff backoff = RetryBackoff.exponentialWithJitter(Duration.ofMillis(100), Duration.ofSeconds(1));
        assertTrue(backoff.jittered());
        RandomGenerator half = new RandomGenerator() {
            @Override
            public long nextLong() {
                throw new UnsupportedOperationException();
            }

            @Override
            public double nextDouble() {
                return 0.5;
            }
        };
        assertEquals(millis(50, 100, 200, 400, 500), delays(backoff, 5, half));
        assertEquals(Duration.ofMillis(400), backoff.ceiling(3));
    }

    @Test
    void fullJitterStaysWithinZeroAndTheCeiling() {
        RetryBackoff backoff = RetryBackoff.exponentialWithJitter(Duration.ofMillis(10), Duration.ofMillis(300));
        SplittableRandom random = new SplittableRandom(42);
        for (int failures = 1; failures <= 8; failures++) {
            int failed = failures;
            Duration ceiling = backoff.ceiling(failed);
            long distinct = IntStream.range(0, 200).mapToObj(i -> backoff.delay(failed, random)).distinct().count();
            for (int i = 0; i < 1000; i++) {
                Duration d = backoff.delay(failed, random);
                assertFalse(d.isNegative(), d + " is negative");
                assertTrue(d.compareTo(ceiling) < 0, d + " is not below " + ceiling);
            }
            assertTrue(distinct > 1, "the waits vary");
        }
        assertEquals(millis(10, 20, 40, 80, 160, 300, 300),
                IntStream.rangeClosed(1, 7).mapToObj(backoff::ceiling).toList());
        for (int i = 0; i < 1000; i++) {
            Duration d = backoff.delay(4);
            assertTrue(!d.isNegative() && d.compareTo(Duration.ofMillis(80)) < 0, d.toString());
        }
    }

    @Test
    void outOfRangeJitterIsClamped() {
        RetryBackoff backoff = RetryBackoff.exponentialWithJitter(Duration.ofMillis(100), Duration.ofMillis(100));
        assertEquals(Duration.ofMillis(100), backoff.delay(1, fraction(7.0)));
        assertEquals(Duration.ZERO, backoff.delay(1, fraction(-1.0)));
    }

    private static RandomGenerator fraction(double value) {
        return new RandomGenerator() {
            @Override
            public long nextLong() {
                throw new UnsupportedOperationException();
            }

            @Override
            public double nextDouble() {
                return value;
            }
        };
    }

    @Test
    void invalidPoliciesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.exponential(Duration.ZERO, MS));
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.exponential(MS.negated(), MS));
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.exponential(Duration.ofSeconds(2), MS));
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.exponentialWithJitter(MS, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.fixed(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.exponential(MS, Duration.ofDays(365L * 1000)),
                "too long to count in nanoseconds");
        assertThrows(NullPointerException.class, () -> RetryBackoff.exponential(null, MS));
        assertThrows(NullPointerException.class, () -> RetryBackoff.exponential(MS, null));
        assertThrows(IllegalArgumentException.class, () -> RetryBackoff.fixed(MS).delay(0, NEVER));
    }

    @Test
    void policiesAreValues() {
        Duration a = Duration.ofMillis(100);
        Duration b = Duration.ofSeconds(2);
        assertEquals(RetryBackoff.exponential(a, b), RetryBackoff.exponential(a, b));
        assertEquals(RetryBackoff.exponential(a, b).hashCode(), RetryBackoff.exponential(a, b).hashCode());
        assertNotEquals(RetryBackoff.exponential(a, b), RetryBackoff.exponentialWithJitter(a, b));
        assertEquals("exponential(PT0.1S, PT2S)", RetryBackoff.exponential(a, b).toString());
        assertEquals("exponentialWithJitter(PT0.1S, PT2S)", RetryBackoff.exponentialWithJitter(a, b).toString());
    }

    @Test
    void theBudgetIsPartOfThePolicy() {
        RetryBackoff base = RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofSeconds(1));
        assertEquals(java.util.Optional.empty(), base.budget(), "the default budget");
        assertFalse(base.isUnbudgeted());

        RetryBackoff budgeted = base.withBudget(Duration.ofSeconds(10));
        assertEquals(java.util.Optional.of(Duration.ofSeconds(10)), budgeted.budget());
        assertFalse(budgeted.isUnbudgeted());
        assertEquals(delays(base, 6, NEVER), delays(budgeted, 6, NEVER), "the waits are the same");
        assertNotEquals(base, budgeted);
        assertEquals(budgeted, RetryBackoff.exponential(Duration.ofMillis(100), Duration.ofSeconds(1))
                .withBudget(Duration.ofSeconds(10)));
        assertEquals("exponential(PT0.1S, PT1S).withBudget(PT10S)", budgeted.toString());

        RetryBackoff unbudgeted = budgeted.unbudgeted();
        assertTrue(unbudgeted.isUnbudgeted());
        assertEquals(java.util.Optional.empty(), unbudgeted.budget());
        assertEquals("exponential(PT0.1S, PT1S).unbudgeted()", unbudgeted.toString());
        assertEquals(unbudgeted.hashCode(), base.unbudgeted().hashCode());
        assertEquals(base, unbudgeted.withDefaultBudget());
        assertEquals("fixed(PT1S).unbudgeted()", RetryBackoff.fixed(Duration.ofSeconds(1)).unbudgeted().toString());

        assertTrue(base.withBudget(Duration.ofSeconds(Long.MAX_VALUE)).isUnbudgeted(), "too long to count");
        assertThrows(IllegalArgumentException.class, () -> base.withBudget(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> base.withBudget(Duration.ofMillis(-1)));
        assertThrows(NullPointerException.class, () -> base.withBudget(null));

        assertEquals(RetryBackoff.none(), RetryBackoff.none().unbudgeted(), "none() never waits");
        assertEquals(RetryBackoff.none(), RetryBackoff.none().withBudget(Duration.ofSeconds(1)));
    }
}
