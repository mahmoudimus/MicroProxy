package org.microproxy.bench;

/**
 * The JMH settings every benchmark class uses, in one place so both proxies, which every class
 * runs as a pair, always get the same: forks, warm-up, measurement and JVM arguments. Each can be
 * overridden from the command line ({@code -f}, {@code -wi}, {@code -w}, {@code -i}, {@code -r},
 * {@code -jvmArgsAppend}), which again applies to both proxies alike.
 */
public final class BenchConfig {

    /** Separate JVMs per benchmark and parameter set. */
    public static final int FORKS = 2;

    /** Warm-up iterations per fork. */
    public static final int WARMUP_ITERATIONS = 5;

    /** Seconds per warm-up iteration. */
    public static final int WARMUP_SECONDS = 2;

    /** Measured iterations per fork. */
    public static final int MEASUREMENT_ITERATIONS = 5;

    /** Seconds per measured iteration. */
    public static final int MEASUREMENT_SECONDS = 3;

    /** A fixed heap, so neither proxy's numbers depend on how the heap happened to grow. */
    public static final String HEAP_MIN = "-Xms2g";

    /** A fixed heap, so neither proxy's numbers depend on how the heap happened to grow. */
    public static final String HEAP_MAX = "-Xmx2g";

    private BenchConfig() {}
}
