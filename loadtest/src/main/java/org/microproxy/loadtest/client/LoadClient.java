package org.microproxy.loadtest.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import org.HdrHistogram.Histogram;
import org.microproxy.loadtest.Json;
import org.microproxy.loadtest.proc.ManagedProcess;

/**
 * The load generator's JVM ({@code client} sub-command). It reads one JSON command per line from
 * standard input and answers each with one protocol line on standard output, so the orchestrator
 * can keep connections open across steps while it samples the proxy between them.
 *
 * <p>Commands: {@code config} (the proxy's address, source addresses, timeouts), {@code rate}
 * (open-loop load, see {@link OpenLoop}), {@code hold}, {@code holdStatus} and {@code release}
 * (idle connections, see {@link Holder}), {@code requests} (a batch of requests on fresh
 * connections, each outcome counted: the validation and fault checks), {@code closePool} and
 * {@code exit}.
 */
public final class LoadClient {

    private InetSocketAddress proxy;
    private List<InetAddress> sources = List.of();
    private int perSource = 25000;
    private int connectTimeoutMs = 5000;
    private int readTimeoutMs = 10000;
    private final Map<String, OpenLoop.Pool> pools = new LinkedHashMap<>();
    private final Map<String, MemoryWorkloads.Handle> workloads = new LinkedHashMap<>();
    private Holder holder;

    /** Runs the command loop until {@code exit} or the end of standard input. */
    public static void main(String[] args) throws Exception {
        LoadClient client = new LoadClient();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) continue;
            Map<String, Object> reply;
            try {
                Map<String, Object> cmd = Json.parseObject(line);
                if ("exit".equals(cmd.get("cmd"))) {
                    client.shutdown();
                    reply("ok", Json.obj("ok", true));
                    return;
                }
                reply = client.handle(cmd);
            } catch (Exception e) {
                reply = Json.obj("error", e.toString());
            }
            reply("reply", reply);
        }
        client.shutdown();
    }

    private static void reply(String kind, Map<String, Object> m) {
        m.put("self", selfStats());
        System.out.println(ManagedProcess.PROTOCOL_PREFIX + Json.write(m));
        System.out.flush();
    }

    private static Map<String, Object> selfStats() {
        Runtime rt = Runtime.getRuntime();
        return Json.obj("heapUsedKb", (rt.totalMemory() - rt.freeMemory()) / 1024, "threads", Thread.activeCount());
    }

    private Map<String, Object> handle(Map<String, Object> cmd) throws Exception {
        String name = Json.getString(cmd, "cmd", "");
        switch (name) {
            case "config" -> {
                proxy = new InetSocketAddress(InetAddress.getByName(Json.getString(cmd, "proxyHost", "127.0.0.1")),
                        (int) Json.getLong(cmd, "proxyPort", 0));
                List<InetAddress> s = new ArrayList<>();
                Object list = cmd.get("sources");
                if (list instanceof List<?> l) for (Object o : l) s.add(InetAddress.getByName(o.toString()));
                sources = s;
                perSource = (int) Json.getLong(cmd, "perSource", 25000);
                connectTimeoutMs = (int) Json.getLong(cmd, "connectTimeoutMs", 5000);
                readTimeoutMs = (int) Json.getLong(cmd, "readTimeoutMs", 10000);
                return Json.obj("ok", true);
            }
            case "rate" -> {
                String poolName = Json.getString(cmd, "pool", "main");
                OpenLoop.Pool pool = pools.computeIfAbsent(poolName,
                        k -> new OpenLoop.Pool(proxy, sources, connectTimeoutMs, readTimeoutMs));
                HttpConn.Target t = target(cmd);
                return OpenLoop.run(pool, t, Json.getDouble(cmd, "rate", 100), (int) Json.getLong(cmd, "connections", 1),
                        Json.getLong(cmd, "durationMs", 1000) * 1_000_000L);
            }
            case "closePool" -> {
                OpenLoop.Pool pool = pools.remove(Json.getString(cmd, "pool", "main"));
                if (pool != null) pool.close();
                return Json.obj("ok", true);
            }
            case "hold" -> {
                if (holder == null) holder = new Holder(proxy, sources, perSource, connectTimeoutMs, readTimeoutMs);
                List<HttpConn.Target> warm = new ArrayList<>();
                Object urls = cmd.get("warmUrls");
                if (urls instanceof List<?> l) {
                    for (Object u : l) warm.add(HttpConn.Target.of(u.toString(), 200, Json.getLong(cmd, "expectLength", -1), 0));
                }
                return holder.open((int) Json.getLong(cmd, "count", 0), (int) Json.getLong(cmd, "parallel", 32), warm,
                        Json.getLong(cmd, "maxFailures", Long.MAX_VALUE));
            }
            case "holdStatus" -> {
                return holder == null ? Json.obj("held", 0) : new LinkedHashMap<>(holder.status());
            }
            case "release" -> {
                if (holder != null) holder.release();
                return Json.obj("ok", true);
            }
            case "requests" -> {
                return requests(cmd);
            }
            case "attackStart" -> {
                String id = Json.getString(cmd, "attack", "");
                workloads.put(id, MemoryWorkloads.start(proxy, cmd));
                return Json.obj("started", id);
            }
            case "attackProgress" -> {
                MemoryWorkloads.Handle h = workloads.get(Json.getString(cmd, "attack", ""));
                return h == null ? Json.obj("missing", true) : new LinkedHashMap<>(h.progress());
            }
            case "attackStop" -> {
                MemoryWorkloads.Handle h = workloads.remove(Json.getString(cmd, "attack", ""));
                return h == null ? Json.obj("missing", true) : new LinkedHashMap<>(h.stop());
            }
            default -> throw new IllegalArgumentException("unknown command " + name);
        }
    }

    private static HttpConn.Target target(Map<String, Object> cmd) {
        return HttpConn.Target.of(Json.getString(cmd, "url", ""), (int) Json.getLong(cmd, "expectStatus", 200),
                Json.getLong(cmd, "expectLength", -1), Json.getLong(cmd, "uploadBytes", 0));
    }

    /**
     * {@code count} requests, {@code concurrency} at a time, each on a fresh connection closed
     * afterwards: every outcome and status is counted, with each request's duration.
     */
    private Map<String, Object> requests(Map<String, Object> cmd) throws InterruptedException {
        HttpConn.Target t = target(cmd);
        int count = (int) Json.getLong(cmd, "count", 1);
        int concurrency = (int) Math.max(1, Json.getLong(cmd, "concurrency", 1));
        int timeout = (int) Json.getLong(cmd, "timeoutMs", readTimeoutMs);
        AtomicInteger next = new AtomicInteger();
        ReentrantLock lock = new ReentrantLock();
        EnumMap<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);
        Map<String, Object> statuses = new LinkedHashMap<>();
        List<Object> details = new ArrayList<>();
        Histogram all = Histograms.create();
        List<Thread> threads = new ArrayList<>();
        for (int w = 0; w < concurrency; w++) {
            threads.add(Thread.ofVirtual().start(() -> {
                while (next.getAndIncrement() < count) {
                    long t0 = System.nanoTime();
                    HttpConn.Result r;
                    try (HttpConn c = HttpConn.open(proxy, null, connectTimeoutMs, timeout, 0)) {
                        r = c.exchange(t);
                    } catch (IOException e) {
                        r = new HttpConn.Result(Outcome.of(e, true, false), -1, 0, e.getMessage());
                    }
                    long dt = System.nanoTime() - t0;
                    lock.lock();
                    try {
                        outcomes.merge(r.outcome(), 1L, Long::sum);
                        if (r.status() > 0) statuses.merge(Integer.toString(r.status()), 1L, (a, b) -> (Long) a + (Long) b);
                        Histograms.recordNanos(all, dt);
                        if (details.size() < 5 && r.outcome() != Outcome.OK) {
                            details.add(r.outcome() + (r.status() > 0 ? " " + r.status() : "") + " after "
                                    + dt / 1_000_000 + " ms, " + r.bodyBytes() + " body bytes"
                                    + (r.detail() != null ? ": " + r.detail() : ""));
                        }
                    } finally {
                        lock.unlock();
                    }
                }
            }));
        }
        for (Thread th : threads) th.join();
        Map<String, Object> o = new LinkedHashMap<>();
        outcomes.forEach((k, v) -> o.put(k.name(), v));
        return Json.obj("url", t.url(), "count", count, "outcomes", o, "statuses", statuses,
                "durationMs", Histograms.summary(all), "details", details);
    }

    private void shutdown() {
        for (OpenLoop.Pool p : pools.values()) p.close();
        for (MemoryWorkloads.Handle h : workloads.values()) h.stop();
        if (holder != null) holder.release();
    }
}
