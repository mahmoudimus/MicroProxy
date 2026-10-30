package io.github.mahmoudimus.quic.tls;

import com.sun.net.httpserver.HttpServer;
import io.github.mahmoudimus.quic.StatelessResetToken;
import java.io.PrintWriter;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Random;

/**
 * Opt-in, local synthetic timing observations; no JUnit tests and no timing pass/fail threshold.
 * See docs/security-timing-audit.md and scripts/security/assess-local-timing.sh.
 */
public final class LocalTimingAssessment {
    private static final int POOL_SIZE = 256;
    private static volatile int sink;

    private LocalTimingAssessment() {}

    @FunctionalInterface
    private interface Operation {
        int run(int index) throws Throwable;
    }

    public static void main(String[] args) throws Throwable {
        if (args.length != 4) {
            throw new IllegalArgumentException("usage: LocalTimingAssessment samples-per-class kem-samples-per-class seed output.csv");
        }
        int samples = Integer.parseInt(args[0]);
        int kemSamples = Integer.parseInt(args[1]);
        long seed = Long.parseLong(args[2]);
        if (samples < 100 || kemSamples < 100 || samples > 1_000_000 || kemSamples > 100_000) {
            throw new IllegalArgumentException("samples must be 100..1000000; KEM samples 100..100000");
        }
        Random random = new Random(seed);
        System.out.printf("java=%s vm=%s os=%s/%s seed=%d%n", System.getProperty("java.runtime.version"),
                System.getProperty("java.vm.name"), System.getProperty("os.name"), System.getProperty("os.arch"), seed);
        System.out.println("Exploratory local observations only; Welch t is not a constant-time proof or a CI gate.");
        try (PrintWriter csv = new PrintWriter(Files.newBufferedWriter(Path.of(args[3])))) {
            csv.println("scenario,cohort,sample,elapsed_ns,operations");
            byte[] expected = randomBytes(random, 32);
            byte[] equal = expected.clone(); // distinct object: do not measure the identity shortcut
            byte[] first = expected.clone();
            byte[] last = expected.clone();
            first[0] ^= 1;
            last[last.length - 1] ^= 1;
            byte[][] guesses = randomPool(random, expected.length);
            byte[][] firstLast = cases(first, repeat(last));
            measure(csv, "digest-first-vs-last-mismatch", samples, 64, random,
                    i -> MessageDigest.isEqual(expected, firstLast[i]) ? 1 : 0);
            byte[][] fixedRandom = cases(first, guesses);
            measure(csv, "digest-fixed-vs-random-mismatch", samples, 64, random,
                    i -> MessageDigest.isEqual(expected, fixedRandom[i]) ? 1 : 0);
            byte[][] equalRandom = cases(equal, guesses);
            measure(csv, "digest-equal-vs-random-mismatch", samples, 64, random,
                    i -> MessageDigest.isEqual(expected, equalRandom[i]) ? 1 : 0);

            StatelessResetToken reset = StatelessResetToken.of(Arrays.copyOf(expected, 16));
            ByteBuffer[] datagrams = new ByteBuffer[2 * POOL_SIZE];
            ByteBuffer fixedDatagram = ByteBuffer.wrap(randomBytes(random, 48));
            for (int i = 0; i < POOL_SIZE; i++) {
                datagrams[i] = fixedDatagram;
                datagrams[i + POOL_SIZE] = ByteBuffer.wrap(randomBytes(random, 48));
            }
            measure(csv, "stateless-reset-fixed-vs-random-mismatch", samples, 32, random,
                    i -> reset.matches(datagrams[i]) ? 1 : 0);

            credentials(csv, samples, random);
            byte[] kemSeed = randomBytes(random, 64);
            MlKem768.DecapsulationKey key = MlKem768.DecapsulationKey.fromSeed(kemSeed);
            byte[][] valid = new byte[POOL_SIZE][];
            byte[][] invalid = randomPool(random, MlKem768.CIPHERTEXT_SIZE);
            byte[] publicKey = key.encapsulationKey();
            for (int i = 0; i < valid.length; i++) {
                MlKem768.Encapsulation encapsulation = MlKem768.encapsulate(publicKey, randomBytes(random, 32));
                valid[i] = encapsulation.ciphertext();
                if (!MessageDigest.isEqual(encapsulation.sharedKey(), key.decapsulate(valid[i]))) {
                    throw new AssertionError("synthetic valid ciphertext did not decapsulate");
                }
                checkRejection(key, kemSeed, invalid[i]);
            }
            byte[] tampered = valid[0].clone();
            tampered[0] ^= 1;
            checkRejection(key, kemSeed, tampered);
            byte[][] validCases = cases(valid[0], valid);
            measure(csv, "mlkem-fixed-vs-random-valid", kemSamples, 1, random,
                    i -> consume(key.decapsulate(validCases[i])));
            byte[][] invalidCases = cases(tampered, invalid);
            measure(csv, "mlkem-fixed-vs-random-invalid", kemSamples, 1, random,
                    i -> consume(key.decapsulate(invalidCases[i])));
            byte[][] validInvalidCases = cases(valid[0], invalid);
            measure(csv, "mlkem-valid-vs-random-invalid", kemSamples, 1, random,
                    i -> consume(key.decapsulate(validInvalidCases[i])));
        }
        System.out.println("raw_samples=" + Path.of(args[3]).toAbsolutePath() + " sink=" + sink);
    }

    /** Exercise the production comparator and admin parser when the proxy module is present. */
    private static void credentials(PrintWriter csv, int samples, Random random) throws Throwable {
        Class<?> upstream;
        Class<?> admin;
        try {
            upstream = Class.forName("org.microproxy.UpstreamProxyManager");
            admin = Class.forName("org.microproxy.impl.AdminServer");
        } catch (ClassNotFoundException e) {
            System.out.println("admin/upstream skipped: add microproxy/target/classes to the class path");
            return;
        }
        String expected = "synthetic-local-credential-32byte";
        String first = "X" + expected.substring(1);
        String last = expected.substring(0, expected.length() - 1) + "X";
        var proxy = upstream.getMethod("proxy", String.class);
        Object configured = proxy.invoke(null, "h2://user:" + expected + "@proxy.invalid");
        Object firstProxy = proxy.invoke(null, "h2://user:" + first + "@proxy.invalid");
        Object lastProxy = proxy.invoke(null, "h2://user:" + last + "@proxy.invalid");
        Object otherUser = proxy.invoke(null, "h2://other:" + expected + "@proxy.invalid");
        if (configured.equals(otherUser)) throw new AssertionError("stale upstream account-comparison implementation");
        Object[] upstreamCases = new Object[2 * POOL_SIZE];
        Arrays.fill(upstreamCases, 0, POOL_SIZE, firstProxy);
        Arrays.fill(upstreamCases, POOL_SIZE, upstreamCases.length, lastProxy);
        measure(csv, "upstream-first-vs-last-mismatch", samples, 32, random,
                i -> configured.equals(upstreamCases[i]) ? 1 : 0);

        // The real AdminServer constructor and authorized() are used. The HTTP fixture only binds
        // loopback; it is never started and no request or timing measurement crosses the network.
        HttpServer http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        try {
            Constructor<?> constructor = admin.getDeclaredConstructor(
                    Class.forName("org.microproxy.impl.DefaultHttpProxyServer"), HttpServer.class,
                    java.util.concurrent.ExecutorService.class, String.class);
            constructor.setAccessible(true);
            Object fixture = constructor.newInstance(null, http, null, expected);
            MethodHandle authorized = MethodHandles.privateLookupIn(admin, MethodHandles.lookup())
                    .findVirtual(admin, "authorized", MethodType.methodType(boolean.class, String.class))
                    .bindTo(fixture);
            String[] bearerCases = new String[2 * POOL_SIZE];
            Arrays.fill(bearerCases, 0, POOL_SIZE, "Bearer " + first);
            Arrays.fill(bearerCases, POOL_SIZE, bearerCases.length, "Bearer " + last);
            measure(csv, "admin-bearer-first-vs-last-mismatch", samples, 16, random,
                    i -> (boolean) authorized.invokeExact(bearerCases[i]) ? 1 : 0);
            String basicFirst = "Basic " + Base64.getEncoder().encodeToString(("user:" + first).getBytes(StandardCharsets.UTF_8));
            String basicLast = "Basic " + Base64.getEncoder().encodeToString(("user:" + last).getBytes(StandardCharsets.UTF_8));
            String[] basicCases = new String[2 * POOL_SIZE];
            Arrays.fill(basicCases, 0, POOL_SIZE, basicFirst);
            Arrays.fill(basicCases, POOL_SIZE, basicCases.length, basicLast);
            measure(csv, "admin-basic-first-vs-last-mismatch", samples, 16, random,
                    i -> (boolean) authorized.invokeExact(basicCases[i]) ? 1 : 0);
        } finally {
            http.stop(0);
        }
    }

    private static byte[] randomBytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[][] randomPool(Random random, int length) {
        byte[][] pool = new byte[POOL_SIZE][];
        for (int i = 0; i < pool.length; i++) pool[i] = randomBytes(random, length);
        return pool;
    }

    private static byte[][] repeat(byte[] bytes) {
        byte[][] pool = new byte[POOL_SIZE][];
        Arrays.fill(pool, bytes);
        return pool;
    }

    private static byte[][] cases(byte[] fixed, byte[][] varied) {
        byte[][] inputs = new byte[2 * POOL_SIZE][];
        Arrays.fill(inputs, 0, POOL_SIZE, fixed);
        System.arraycopy(varied, 0, inputs, POOL_SIZE, POOL_SIZE);
        return inputs;
    }

    private static int consume(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) value = value * 31 + b;
        return value;
    }

    private static void checkRejection(MlKem768.DecapsulationKey key, byte[] seed, byte[] ciphertext) {
        byte[] rejection = new byte[MlKem768.SHARED_KEY_SIZE];
        Shake.shake256().update(Arrays.copyOfRange(seed, 32, 64)).update(ciphertext).read(rejection);
        if (!MessageDigest.isEqual(rejection, key.decapsulate(ciphertext))) {
            throw new AssertionError("synthetic rejected ciphertext did not select J(z || c)");
        }
    }

    private static void measure(PrintWriter csv, String name, int samples, int batch, Random random,
            Operation operation) throws Throwable {
        int checksum = 0;
        // Warm both paths before measuring; warmup and allocations can still affect later samples.
        for (int n = 0; n < Math.max(5_000, samples / 2); n++) {
            checksum ^= operation.run(n & (POOL_SIZE - 1));
            checksum ^= operation.run(POOL_SIZE + (n & (POOL_SIZE - 1)));
        }
        int[] order = new int[samples * 2];
        for (int i = samples; i < order.length; i++) order[i] = 1;
        for (int i = order.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int value = order[i];
            order[i] = order[j];
            order[j] = value;
        }
        double[] mean = new double[2];
        double[] m2 = new double[2];
        int[] count = new int[2];
        long[] elapsed = new long[order.length];
        for (int n = 0; n < order.length; n++) {
            int cohort = order[n];
            int base = cohort * POOL_SIZE;
            int index = random.nextInt(POOL_SIZE);
            long start = System.nanoTime();
            for (int j = 0; j < batch; j++) checksum ^= operation.run(base + ((index + j) & (POOL_SIZE - 1)));
            elapsed[n] = System.nanoTime() - start;
            double observation = (double) elapsed[n] / batch;
            int size = ++count[cohort];
            double delta = observation - mean[cohort];
            mean[cohort] += delta / size;
            m2[cohort] += delta * (observation - mean[cohort]);
        }
        sink = checksum;
        for (int n = 0; n < order.length; n++) csv.printf(Locale.ROOT, "%s,%d,%d,%d,%d%n", name, order[n], n, elapsed[n], batch);
        csv.flush();
        double variance0 = m2[0] / (count[0] - 1);
        double variance1 = m2[1] / (count[1] - 1);
        double denominator = Math.sqrt(variance0 / count[0] + variance1 / count[1]);
        double t = denominator == 0 ? Double.NaN : (mean[0] - mean[1]) / denominator;
        System.out.printf(Locale.ROOT, "%s n=%d/%d batch=%d mean_ns=%.2f/%.2f welch_t=%.3f%n",
                name, count[0], count[1], batch, mean[0], mean[1], t);
    }
}
