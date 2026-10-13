package org.microproxy.bench;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/**
 * The servers of one benchmark trial: the shared {@link Origin} and the proxy under test, both in
 * the benchmark's own JVM, started before the trial's first iteration and stopped after its last.
 * The {@link #proxy} parameter runs every benchmark against both proxies with the same JMH
 * settings and JVM arguments, so they are always measured as a pair; JMH forks fresh JVMs for each
 * parameter set, so neither proxy inherits the other's JIT profile or heap.
 *
 * <p>Each scenario subclasses this (again as a {@code @State(Scope.Benchmark)}) and says what the
 * proxy does ({@link #options()}) and whether the origin needs its TLS listener ({@link
 * #originTls()}).
 */
@State(Scope.Benchmark)
public abstract class ProxyState {

    /** Which proxy this trial measures. */
    @Param({ProxyUnderTest.MICROPROXY, ProxyUnderTest.LITTLEPROXY})
    public String proxy;

    /** The shared origin. */
    public Origin origin;

    /** The proxy under test. */
    public ProxyUnderTest server;

    // Thread states that still use the servers in their own tear-down (see attach()).
    private final ReentrantLock usersLock = new ReentrantLock();
    private final Condition noUsers = usersLock.newCondition();
    private int users;

    /** Creates the state; JMH instantiates it. */
    protected ProxyState() {}

    /** {@return what the proxy does beyond forwarding: by default, nothing} */
    protected ProxyUnderTest.Options options() {
        return ProxyUnderTest.Options.PLAIN;
    }

    /** {@return whether the origin also listens for TLS: by default, not} */
    protected boolean originTls() {
        return false;
    }

    /**
     * Starts the origin, then the proxy.
     *
     * @throws IOException if the origin cannot listen
     */
    @Setup(Level.Trial)
    public void startServers() throws IOException {
        origin = Origin.start(originTls() ? BenchTls.originContext() : null);
        server = ProxyUnderTest.start(proxy, options());
    }

    /**
     * Registers a thread state that talks to the servers in its own tear-down: the servers are not
     * stopped until it calls {@link #detach()}. JMH tears the shared state down on whichever
     * benchmark thread finishes first, possibly while other threads are still tearing down theirs.
     */
    public void attach() {
        usersLock.lock();
        try {
            users++;
        } finally {
            usersLock.unlock();
        }
    }

    /** Ends what {@link #attach()} began. */
    public void detach() {
        usersLock.lock();
        try {
            if (--users == 0) noUsers.signalAll();
        } finally {
            usersLock.unlock();
        }
    }

    /**
     * Stops the proxy, then the origin, once every attached thread state has detached (or after
     * a minute).
     *
     * @throws InterruptedException if interrupted while waiting
     */
    @TearDown(Level.Trial)
    public void stopServers() throws InterruptedException {
        usersLock.lock();
        try {
            long left = TimeUnit.MINUTES.toNanos(1);
            while (users > 0 && left > 0) left = noUsers.awaitNanos(left);
        } finally {
            usersLock.unlock();
        }
        if (server != null) server.close();
        if (origin != null) origin.close();
    }

    /** {@return the proxy's address} */
    public InetSocketAddress proxyAddress() {
        return server.address();
    }
}
