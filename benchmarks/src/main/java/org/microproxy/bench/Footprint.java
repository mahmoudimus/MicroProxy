package org.microproxy.bench;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Measures what each proxy keeps per idle client connection: heap, direct memory, resident memory
 * and platform threads. Not a JMH benchmark: run it with
 *
 * <pre>{@code
 * java -cp benchmarks/target/benchmarks.jar org.microproxy.bench.Footprint [--connections N] [--proxies microproxy,littleproxy]
 * }</pre>
 *
 * <p>Each proxy runs alone in a child JVM started with the same arguments, so its numbers hold
 * nothing but the proxy: the origin and the client stay in this JVM. For each proxy:
 *
 * <ol>
 *   <li>The child starts the proxy, and this JVM warms it up with a few hundred requests on
 *       connections it then closes.
 *   <li>The child collects garbage until the used heap settles and reports its usage: the baseline.
 *   <li>This JVM opens {@code N} keep-alive connections and sends one small request on each, so the
 *       proxy also holds a server connection for each, as an idle keep-alive client leaves it.
 *   <li>The child collects again and reports; the difference over {@code N} is the footprint of one
 *       idle client connection (and its server connection).
 * </ol>
 *
 * <p>Heap is what {@link MemoryMXBean} reports as used after collection. Direct memory is the
 * JDK's {@code direct} buffer pool plus, for LittleProxy, what Netty allocates itself (its pooled
 * buffers do not all show in the JDK's pool). Resident memory ({@code VmRSS}, Linux only) includes
 * thread stacks and everything else, but the JVM rarely gives memory back, so read it as an upper
 * bound.
 */
public final class Footprint {

    private static final String CHILD = "--child";

    private Footprint() {}

    /**
     * Runs the harness, or, with {@code --child <proxy>}, one proxy for it.
     *
     * @param args {@code [--connections N] [--proxies a,b] [--jvm-arg ARG]...}
     * @throws Exception if a proxy or the origin fails
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals(CHILD)) {
            child(args[1]);
            return;
        }
        int connections = 2000;
        List<String> proxies = ProxyUnderTest.ALL;
        List<String> jvmArgs = new ArrayList<>(List.of(BenchConfig.HEAP_MIN, BenchConfig.HEAP_MAX));
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--connections" -> connections = Integer.parseInt(args[++i]);
                case "--proxies" -> proxies = List.of(args[++i].split(","));
                case "--jvm-arg" -> jvmArgs.add(args[++i]);
                default -> {
                    System.err.println("usage: Footprint [--connections N] [--proxies microproxy,littleproxy]"
                            + " [--jvm-arg ARG]...");
                    System.exit(2);
                }
            }
        }
        List<String[]> rows = new ArrayList<>();
        try (Origin origin = Origin.start(null)) {
            for (String proxy : proxies) {
                rows.add(measure(proxy, origin, connections, jvmArgs));
            }
        }
        PrintStream out = System.out;
        out.println();
        out.println("Retained per idle keep-alive client connection (" + connections + " connections, "
                + "LittleProxy " + littleProxyVersion() + "):");
        out.println();
        out.println("| Proxy | Heap/conn | Direct/conn | RSS/conn | Platform threads/conn |");
        out.println("|---|---:|---:|---:|---:|");
        for (String[] row : rows) out.println("| " + String.join(" | ", row) + " |");
    }

    private static String[] measure(String proxy, Origin origin, int connections, List<String> jvmArgs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(ProcessHandle.current().info().command().orElse("java"));
        command.addAll(jvmArgs);
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(Footprint.class.getName());
        command.add(CHILD);
        command.add(proxy);
        Process process = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        BufferedReader replies = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        PrintStream commands = new PrintStream(process.getOutputStream(), true, StandardCharsets.UTF_8);
        List<HttpConnection> open = new ArrayList<>();
        try {
            int port = Integer.parseInt(expect(replies, "LISTENING"));
            InetSocketAddress address = new InetSocketAddress(origin.plainAddress().getAddress(), port);
            byte[] request = HttpConnection.get(origin.plainAddress(), 1024, true, false, "");

            // Warm up: load classes, compile the request path, fill pools; then close.
            for (int round = 0; round < 5; round++) {
                List<HttpConnection> warm = new ArrayList<>();
                for (int i = 0; i < 50; i++) {
                    HttpConnection c = HttpConnection.open(address);
                    warm.add(c);
                    for (int r = 0; r < 4; r++) {
                        c.send(request);
                        c.readResponse(200, 1024);
                    }
                }
                for (HttpConnection c : warm) c.close();
            }
            Thread.sleep(1_000);

            Sample before = Sample.parse(ask(commands, replies));
            for (int i = 0; i < connections; i++) {
                HttpConnection c = HttpConnection.open(address);
                open.add(c);
                c.send(request);
                c.readResponse(200, 1024);
            }
            Thread.sleep(1_000);
            Sample after = Sample.parse(ask(commands, replies));
            if (origin.openConnections() < connections) {
                System.err.println(proxy + ": only " + origin.openConnections() + " server connections open");
            }
            System.err.printf(Locale.ROOT, "%s: before %s%n%s: after  %s%n", proxy, before, proxy, after);
            return new String[] {
                proxy,
                bytes((after.heap - before.heap) / (double) connections),
                bytes((after.direct - before.direct) / (double) connections),
                after.rss < 0 ? "n/a" : bytes((after.rss - before.rss) / (double) connections),
                String.format(Locale.ROOT, "%.3f", (after.threads - before.threads) / (double) connections),
            };
        } finally {
            for (HttpConnection c : open) c.close();
            commands.println("EXIT");
            process.waitFor();
        }
    }

    private static String ask(PrintStream commands, BufferedReader replies) throws IOException {
        commands.println("MEASURE");
        return expect(replies, "SAMPLE");
    }

    private static String expect(BufferedReader replies, String tag) throws IOException {
        String line;
        while ((line = replies.readLine()) != null) {
            if (line.startsWith(tag + " ")) return line.substring(tag.length() + 1);
        }
        throw new IOException("the proxy's JVM ended before answering " + tag);
    }

    private static String bytes(double b) {
        return b >= 10 * 1024 ? String.format(Locale.ROOT, "%.1f KiB", b / 1024) : String.format(Locale.ROOT, "%.0f B", b);
    }

    /** {@return the LittleProxy version on the class path, from its jar's manifest or Maven metadata} */
    static String littleProxyVersion() {
        Package p = org.littleshoot.proxy.HttpProxyServer.class.getPackage();
        if (p != null && p.getImplementationVersion() != null) return p.getImplementationVersion();
        try (var in = Footprint.class.getResourceAsStream("/META-INF/maven/io.github.littleproxy/littleproxy/pom.properties")) {
            if (in == null) return "unknown";
            java.util.Properties properties = new java.util.Properties();
            properties.load(in);
            return properties.getProperty("version", "unknown");
        } catch (IOException e) {
            return "unknown";
        }
    }

    /** One measurement of the proxy's JVM. */
    private record Sample(long heap, long direct, long rss, long threads) {
        static Sample parse(String line) {
            String[] f = line.split(" ");
            return new Sample(Long.parseLong(f[0]), Long.parseLong(f[1]), Long.parseLong(f[2]), Long.parseLong(f[3]));
        }

        @Override
        public String toString() {
            return String.format(Locale.ROOT, "heap %.1f MiB, direct %.1f MiB, rss %s, %d platform threads",
                    heap / 1048576.0, direct / 1048576.0,
                    rss < 0 ? "n/a" : String.format(Locale.ROOT, "%.1f MiB", rss / 1048576.0), threads);
        }
    }

    /** The child JVM: runs one proxy and measures itself when asked. */
    private static void child(String proxy) throws Exception {
        try (ProxyUnderTest server = ProxyUnderTest.start(proxy, ProxyUnderTest.Options.PLAIN)) {
            System.out.println("LISTENING " + server.address().getPort());
            System.out.flush();
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line;
            while ((line = in.readLine()) != null && !line.equals("EXIT")) {
                if (line.equals("MEASURE")) {
                    System.out.println("SAMPLE " + settledHeap() + " " + directMemory() + " " + rss() + " "
                            + ManagementFactory.getThreadMXBean().getThreadCount());
                    System.out.flush();
                }
            }
        }
    }

    /** Collects until the used heap stops shrinking, and returns it. */
    private static long settledHeap() throws InterruptedException {
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        long previous = Long.MAX_VALUE;
        for (int i = 0; i < 10; i++) {
            System.gc();
            Thread.sleep(100);
            long used = memory.getHeapMemoryUsage().getUsed();
            if (used >= previous - 64 * 1024) return Math.min(used, previous);
            previous = used;
        }
        return previous;
    }

    private static long directMemory() {
        long total = 0;
        for (BufferPoolMXBean pool : ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)) {
            if (pool.getName().equals("direct")) total += pool.getMemoryUsed();
        }
        try {
            // Netty's own count of the direct memory it allocates without the JDK's accounting.
            Class<?> platform = Class.forName("io.netty.util.internal.PlatformDependent");
            long netty = (long) platform.getMethod("usedDirectMemory").invoke(null);
            if (netty > 0) total += netty;
        } catch (ReflectiveOperationException | LinkageError e) {
            // not on the class path, or not counting
        }
        return total;
    }

    private static long rss() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("VmRSS:")) {
                    String[] f = line.trim().split("\\s+");
                    return Long.parseLong(f[1]) * 1024;
                }
            }
        } catch (IOException | RuntimeException e) {
            // not Linux
        }
        return -1;
    }
}
