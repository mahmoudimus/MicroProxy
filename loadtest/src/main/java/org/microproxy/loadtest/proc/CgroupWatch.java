package org.microproxy.loadtest.proc;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Holds a cgroup's memory, its TCP socket buffers aside, to a limit, and records the peaks of both.
 *
 * <p>cgroup v2 charges a group for its sockets' TCP buffers, and a kernel limit ({@code memory.max})
 * covers them too: with a few hundred slow clients the buffers alone can fill a limit sized for a
 * proxy's own memory, and the OOM killer then ends the proxy whatever the proxy itself holds. How
 * much a connection leaves in those buffers is set mostly by the kernel ({@code tcp_rmem},
 * {@code tcp_wmem}, autotuning), so a comparison of proxies' memory under such clients holds each
 * proxy's own memory to the limit and reports the buffers beside it. The group then has no kernel
 * limit ({@link Environment#createMemoryCgroup}), and this watch reads its memory every
 * {@code every} and calls {@code overLimit} once, the first time the memory other than the socket
 * buffers passes {@code limitBytes}.
 */
public final class CgroupWatch implements AutoCloseable {

    private final Path procs;
    private final long limitBytes;
    private final Runnable overLimit;
    private final AtomicLong peakOwn = new AtomicLong(-1);
    private final AtomicLong peakSock = new AtomicLong(-1);
    private final AtomicLong overAt = new AtomicLong(-1);
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final Thread thread;

    private CgroupWatch(Path procs, long limitBytes, Duration every, Runnable overLimit, String name) {
        this.procs = procs;
        this.limitBytes = limitBytes;
        this.overLimit = overLimit;
        this.thread = Thread.ofPlatform().daemon().name(name).unstarted(() -> loop(every));
    }

    /** Starts watching the cgroup of {@code procs} (its {@code cgroup.procs} file). */
    public static CgroupWatch start(Path procs, long limitBytes, Duration every, Runnable overLimit, String name) {
        CgroupWatch w = new CgroupWatch(procs, limitBytes, every, overLimit, name);
        w.thread.start();
        return w;
    }

    private void loop(Duration every) {
        while (!stopped.get()) {
            poll();
            try {
                Thread.sleep(every);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    /** Reads the cgroup once; calls {@code overLimit} if its own memory passed the limit for the first time. */
    void poll() {
        Environment.CgroupMemory m = Environment.cgroupMemory(procs);
        if (m == null) return;
        peakOwn.accumulateAndGet(m.ownBytes(), Math::max);
        peakSock.accumulateAndGet(m.sockBytes(), Math::max);
        if (m.ownBytes() > limitBytes && overAt.compareAndSet(-1, m.ownBytes())) overLimit.run();
    }

    /** Whether the memory other than the socket buffers passed the limit. */
    public boolean overLimit() {
        return overAt.get() >= 0;
    }

    /** The memory other than the socket buffers when it passed the limit, in bytes, or -1. */
    public long overLimitBytes() {
        return overAt.get();
    }

    /** The highest memory other than the socket buffers seen, in KB, or -1 if never read. */
    public long peakOwnKb() {
        long b = peakOwn.get();
        return b < 0 ? -1 : b / 1024;
    }

    /** The highest socket-buffer memory seen, in KB, or -1 if never read. */
    public long peakSockKb() {
        long b = peakSock.get();
        return b < 0 ? -1 : b / 1024;
    }

    /** The limit on the memory other than the socket buffers, in bytes. */
    public long limitBytes() {
        return limitBytes;
    }

    @Override
    public void close() {
        if (stopped.compareAndSet(false, true)) {
            thread.interrupt();
            try {
                thread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
