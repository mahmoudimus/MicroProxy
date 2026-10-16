package org.microproxy.loadtest.proc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CgroupWatchTest {

    private static final long MB = 1024 * 1024;

    @TempDir
    Path dir;

    /** A cgroup v2 directory charged {@code current} bytes in all, {@code sock} of them socket buffers. */
    private Path v2(long current, long sock) throws IOException {
        Files.writeString(dir.resolve("memory.current"), current + "\n");
        Files.writeString(dir.resolve("memory.stat"), "anon " + (current - sock) + "\nfile 0\nkernel 4096\nsock " + sock + "\nshmem 0\n");
        return dir.resolve("cgroup.procs");
    }

    @Test
    void readsTheSocketBuffersApartFromTheRest() throws IOException {
        Environment.CgroupMemory m = Environment.cgroupMemory(v2(400 * MB, 350 * MB));
        assertEquals(50 * MB, m.ownBytes());
        assertEquals(350 * MB, m.sockBytes());
    }

    @Test
    void readsCgroupV1WhereTheTcpBuffersAreACounterOfTheirOwn() throws IOException {
        Files.writeString(dir.resolve("memory.usage_in_bytes"), (60 * MB) + "\n");
        Files.writeString(dir.resolve("memory.kmem.tcp.usage_in_bytes"), (300 * MB) + "\n");
        Environment.CgroupMemory m = Environment.cgroupMemory(dir.resolve("cgroup.procs"));
        assertEquals(60 * MB, m.ownBytes());
        assertEquals(300 * MB, m.sockBytes());
    }

    @Test
    void anUnreadableCgroupIsNull() {
        assertNull(Environment.cgroupMemory(dir.resolve("cgroup.procs")));
        assertNull(Environment.cgroupMemory(null));
    }

    @Test
    void socketBuffersPastTheLimitDoNotCountAgainstIt() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        Path procs = v2(500 * MB, 470 * MB);
        try (CgroupWatch w = CgroupWatch.start(procs, 512 * MB, Duration.ofDays(1), calls::incrementAndGet, "test")) {
            w.poll();
            v2(900 * MB, 860 * MB); // 40 MB of its own: the buffers alone are far past the limit
            w.poll();
            assertFalse(w.overLimit());
            assertEquals(0, calls.get());
            assertEquals(860 * 1024, w.peakSockKb());
            assertEquals(40 * 1024, w.peakOwnKb());
        }
    }

    @Test
    void itsOwnMemoryPastTheLimitIsReportedOnce() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        Path procs = v2(100 * MB, 10 * MB);
        try (CgroupWatch w = CgroupWatch.start(procs, 512 * MB, Duration.ofDays(1), calls::incrementAndGet, "test")) {
            w.poll();
            assertFalse(w.overLimit());
            v2(700 * MB, 100 * MB);
            w.poll();
            v2(800 * MB, 100 * MB);
            w.poll();
            assertTrue(w.overLimit());
            assertEquals(1, calls.get());
            assertEquals(600 * MB, w.overLimitBytes());
            assertEquals(700 * 1024, w.peakOwnKb());
        }
    }

    @Test
    void theWatchPollsByItself() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        Path procs = v2(600 * MB, 0);
        try (CgroupWatch w = CgroupWatch.start(procs, 512 * MB, Duration.ofMillis(10), calls::incrementAndGet, "test")) {
            long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (!w.overLimit() && System.nanoTime() < deadline) Thread.sleep(10);
            assertTrue(w.overLimit());
        }
        assertEquals(1, calls.get());
    }
}
