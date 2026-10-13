package org.microproxy.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The idle timeout of the waits a keep-alive connection spends most of its time in (a client's
 * next request, a server's response head), without a timer for every wait.
 *
 * <p>A socket read with a timeout ({@code SO_TIMEOUT}) that has to wait parks its virtual thread
 * with that timeout, and the JDK arms a timer for the park and cancels it when the bytes come: on
 * JDK 25 each arm and each cancel wakes the scheduler's delay thread, two thread switches per wait,
 * twice per proxied request. A wait here reads with no timeout instead, and one daemon thread
 * keeps the deadlines of all the waits, waking only when the earliest is due. A wait whose
 * deadline passes has its socket's input shut down, which ends the read; it then fails with a
 * {@link SocketTimeoutException}, as the timed read would have. The socket can still be written
 * (an error response) and closed, which is all a connection does after its idle timeout.
 *
 * <p>Only plain sockets are watched this way; a TLS socket's input cannot be shut down on its
 * own, and its reads keep their {@code SO_TIMEOUT}. So does every read the socket's timeout was
 * changed for: the deadline is taken from the socket's timeout when the wait starts.
 */
final class IdleWaits {

    private IdleWaits() {}

    /** The waits in progress. */
    private static final Set<Wait> WAITS = ConcurrentHashMap.newKeySet();

    private static final ReentrantLock LOCK = new ReentrantLock();
    private static final Condition CHANGED = LOCK.newCondition();
    /** Started on the first wait; guarded by {@link #LOCK}. */
    private static Thread keeper;
    /**
     * When the keeper wakes next ({@link System#nanoTime()}); meaningful only when {@link #timed}.
     * A wait due earlier wakes it.
     */
    private static volatile long wakeAt;
    /** Whether the keeper sleeps until {@link #wakeAt}; false while it sweeps or has no deadline. */
    private static volatile boolean timed;

    /** Whether waits on {@code socket} can be watched here: a plain TCP socket. */
    static boolean supports(Socket socket) {
        return socket != null && socket.getClass() == Socket.class;
    }

    /**
     * Reads one byte from {@code in}, the input of {@code socket}, waiting at most the socket's
     * current read timeout (none if it is 0).
     *
     * @throws SocketTimeoutException if the timeout passed first; the socket's input is then shut
     *     down
     */
    static int readFirst(Socket socket, InputStream in) throws IOException {
        int timeout = socket.getSoTimeout();
        if (timeout <= 0) return in.read();
        Wait wait = new Wait(socket, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeout));
        socket.setSoTimeout(0);
        try {
            add(wait);
            int b;
            try {
                b = in.read();
            } catch (IOException e) {
                if (!wait.finish()) throw timedOut(timeout, e);
                throw e;
            }
            if (!wait.finish()) throw timedOut(timeout, null);
            return b;
        } finally {
            WAITS.remove(wait);
            try {
                socket.setSoTimeout(timeout);
            } catch (SocketException closed) {
                // closed meanwhile: there is nothing more to read
            }
        }
    }

    private static SocketTimeoutException timedOut(int timeout, IOException cause) {
        SocketTimeoutException e = new SocketTimeoutException("Read timed out (idle for " + timeout + " ms)");
        if (cause != null) e.initCause(cause);
        return e;
    }

    private static void add(Wait wait) {
        WAITS.add(wait);
        if (timed && wait.deadline - wakeAt >= 0) return;
        // The keeper sleeps past this deadline, sweeps, or is not running: tell it.
        LOCK.lock();
        try {
            if (keeper == null) {
                keeper = Thread.ofPlatform().daemon().name("MicroProxy-idle-timeouts").start(IdleWaits::keep);
            }
            if (!timed || wait.deadline - wakeAt < 0) CHANGED.signal();
        } finally {
            LOCK.unlock();
        }
    }

    /** The keeper's loop: expires the waits that are due, then sleeps until the next one is. */
    private static void keep() {
        LOCK.lock();
        try {
            while (true) {
                timed = false;
                long now = System.nanoTime();
                long earliest = 0;
                boolean any = false;
                for (Wait wait : WAITS) {
                    if (wait.deadline - now <= 0) {
                        wait.expire();
                    } else if (!any || wait.deadline - earliest < 0) {
                        earliest = wait.deadline;
                        any = true;
                    }
                }
                try {
                    if (any) {
                        wakeAt = earliest;
                        timed = true;
                        CHANGED.awaitNanos(earliest - now);
                    } else {
                        CHANGED.await();
                    }
                } catch (InterruptedException e) {
                    // a daemon thread nobody interrupts; keep watching
                }
            }
        } finally {
            LOCK.unlock();
        }
    }

    /** One wait for a socket's next bytes; its value is its state. */
    @SuppressWarnings("serial")
    private static final class Wait extends AtomicInteger {
        private static final int WAITING = 0;
        private static final int DONE = 1;
        private static final int EXPIRED = 2;

        final transient Socket socket;
        final long deadline;

        Wait(Socket socket, long deadline) {
            super(WAITING);
            this.socket = socket;
            this.deadline = deadline;
        }

        /** Ends the wait as its reader; false if its deadline had passed first. */
        boolean finish() {
            return compareAndSet(WAITING, DONE);
        }

        /** Ends the read of a wait whose deadline passed, unless it ended already. */
        void expire() {
            if (compareAndSet(WAITING, EXPIRED)) {
                try {
                    socket.shutdownInput();
                } catch (IOException e) {
                    // closed meanwhile: the read has ended anyway
                }
            }
        }
    }
}
