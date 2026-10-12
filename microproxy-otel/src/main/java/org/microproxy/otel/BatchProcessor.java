package org.microproxy.otel;

import java.lang.System.Logger.Level;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * OpenTelemetry's batch processor: finished items wait in a bounded queue, and one virtual thread
 * exports them in batches of up to {@code maxBatch}, as soon as a batch is full or {@code delay}
 * after its first item came. When the queue is full (the collector is slow or down), new items are
 * dropped and counted, so the proxy's threads never wait for the collector and memory stays
 * bounded.
 *
 * @param <T> the items: spans or log records
 */
final class BatchProcessor<T> implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(BatchProcessor.class.getName());

    /** Asks the worker to export what it holds now; it counts the latch down when done. */
    private record Flush(CountDownLatch done) {}

    private static final Object STOP = new Object();

    private final String name;
    private final int maxQueue;
    private final int maxBatch;
    private final long delayNanos;
    private final Predicate<List<T>> exporter;
    /** Items and requests: the items are counted in {@link #queued}, the requests not. */
    private final LinkedBlockingQueue<Object> queue = new LinkedBlockingQueue<>();
    private final AtomicInteger queued = new AtomicInteger();
    final AtomicLong exported = new AtomicLong();
    final AtomicLong dropped = new AtomicLong();
    final AtomicLong failed = new AtomicLong();
    private final Thread worker;
    private volatile boolean closed;

    /**
     * Starts the worker.
     *
     * @param name what the items are, for the worker's name and logs ({@code spans})
     * @param exporter sends a batch; returns whether it was accepted
     */
    BatchProcessor(String name, int maxQueue, int maxBatch, Duration delay, Predicate<List<T>> exporter) {
        if (maxQueue <= 0 || maxBatch <= 0) throw new IllegalArgumentException("queue and batch sizes must be positive");
        this.name = name;
        this.maxQueue = maxQueue;
        this.maxBatch = Math.min(maxBatch, maxQueue);
        this.delayNanos = Math.max(1, delay.toNanos());
        this.exporter = exporter;
        this.worker = Thread.ofVirtual().name("microproxy-otel-" + name).start(this::run);
    }

    /** Queues {@code item}; returns false, and counts it as dropped, when the queue is full or closed. */
    boolean offer(T item) {
        if (closed || queued.incrementAndGet() > maxQueue) {
            if (!closed) queued.decrementAndGet();
            dropped.incrementAndGet();
            return false;
        }
        queue.add(item);
        return true;
    }

    /** {@return the items waiting to be exported} */
    int queued() {
        return Math.max(0, queued.get());
    }

    /**
     * Exports what is queued now, waiting up to {@code timeout} for it.
     *
     * @return whether the export finished in time
     */
    boolean flush(Duration timeout) {
        if (!worker.isAlive()) return true;
        CountDownLatch done = new CountDownLatch(1);
        queue.add(new Flush(done));
        try {
            return done.await(timeout.toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Exports what is queued, waiting up to {@code timeout}, and stops the worker. */
    void shutdown(Duration timeout) {
        if (closed) return;
        closed = true;
        queue.add(STOP);
        try {
            if (!worker.join(timeout)) {
                LOG.log(Level.WARNING, "OTLP {0} still exporting after {1}; {2} left unsent", name, timeout, queued());
                worker.interrupt();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        shutdown(Duration.ofSeconds(10));
    }

    @SuppressWarnings("unchecked")
    private void run() {
        List<T> batch = new ArrayList<>(maxBatch);
        long deadline = 0;
        while (true) {
            Object next;
            try {
                next = batch.isEmpty() ? queue.take() : queue.poll(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (next == null) {
                // The delay since the batch's first item is over.
                export(batch);
            } else if (next == STOP) {
                drain(batch);
                return;
            } else if (next instanceof Flush flush) {
                boolean stop = drain(batch);
                flush.done().countDown();
                if (stop) return;
            } else {
                queued.decrementAndGet();
                if (batch.isEmpty()) deadline = System.nanoTime() + delayNanos;
                batch.add((T) next);
                if (batch.size() >= maxBatch) export(batch);
            }
        }
    }

    /**
     * Exports the batch and everything queued, in batches; requests behind the items are answered
     * after. Returns whether one of them was {@link #STOP}.
     */
    @SuppressWarnings("unchecked")
    private boolean drain(List<T> batch) {
        List<Object> later = new ArrayList<>();
        boolean stop = false;
        Object next;
        while ((next = queue.poll()) != null) {
            if (next == STOP) {
                stop = true;
                continue;
            }
            if (next instanceof Flush) {
                later.add(next);
                continue;
            }
            queued.decrementAndGet();
            batch.add((T) next);
            if (batch.size() >= maxBatch) export(batch);
        }
        export(batch);
        for (Object request : later) {
            if (request instanceof Flush flush) flush.done().countDown();
        }
        return stop;
    }

    private void export(List<T> batch) {
        if (batch.isEmpty()) return;
        List<T> items = List.copyOf(batch);
        batch.clear();
        boolean ok;
        try {
            ok = exporter.test(items);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "OTLP " + name + " export failed", e);
            ok = false;
        }
        (ok ? exported : failed).addAndGet(items.size());
    }

    @Override
    public String toString() {
        return "BatchProcessor[" + name + " queued=" + queued() + " exported=" + exported + " dropped=" + dropped
                + " failed=" + failed + "]";
    }
}
