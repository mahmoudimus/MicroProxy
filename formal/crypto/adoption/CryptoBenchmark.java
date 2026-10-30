package io.github.mahmoudimus.quic.tls;

import java.lang.management.ManagementFactory;
import java.util.Arrays;

/** Performance evidence only; this is not a timing side-channel test. */
public final class CryptoBenchmark {
    private static volatile long sink;
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
    private static final int BATCH = 64;
    private static final int SAMPLES = 9;

    private static void consume(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < bytes.length; i += 31) value += bytes[i];
        sink ^= value;
    }

    private static void measure(String name, Runnable operation) {
        long[][] values = new long[3][SAMPLES];
        for (int sample = 0; sample < SAMPLES; sample++) {
            long wall = System.nanoTime();
            long cpu = THREADS.getCurrentThreadCpuTime();
            long allocated = THREADS.getThreadAllocatedBytes(Thread.currentThread().threadId());
            for (int i = 0; i < BATCH; i++) operation.run();
            values[2][sample] = THREADS.getThreadAllocatedBytes(Thread.currentThread().threadId()) - allocated;
            values[1][sample] = THREADS.getCurrentThreadCpuTime() - cpu;
            values[0][sample] = System.nanoTime() - wall;
        }
        for (long[] row : values) Arrays.sort(row);
        System.out.printf("{\"operation\":\"%s\",\"samples\":%d,\"batch\":%d,\"wall_ns\":%d,\"cpu_ns\":%d,\"allocated_bytes\":%d}%n",
                name, SAMPLES, BATCH, values[0][SAMPLES / 2] / BATCH,
                values[1][SAMPLES / 2] / BATCH, values[2][SAMPLES / 2] / BATCH);
    }

    public static void main(String[] args) {
        THREADS.setThreadCpuTimeEnabled(true);
        THREADS.setThreadAllocatedMemoryEnabled(true);
        byte[] seed = new byte[64];
        byte[] message = new byte[32];
        var key = MlKem768.DecapsulationKey.fromSeed(seed);
        byte[] publicKey = key.encapsulationKey();
        var encapsulation = MlKem768.encapsulate(publicKey, message);
        byte[] tampered = encapsulation.ciphertext().clone();
        tampered[0] ^= 1;
        Runnable keygen = () -> {
            seed[0]++;
            consume(MlKem768.DecapsulationKey.fromSeed(seed).encapsulationKey());
        };
        Runnable encapsulate = () -> {
            message[0]++;
            var result = MlKem768.encapsulate(publicKey, message);
            consume(result.sharedKey());
            consume(result.ciphertext());
        };
        Runnable decapsulate = () -> consume(key.decapsulate(encapsulation.ciphertext()));
        Runnable reject = () -> consume(key.decapsulate(tampered));
        Runnable shake = () -> {
            byte[] out = new byte[840];
            Shake.shake128().update(message).read(out);
            consume(out);
        };
        for (int i = 0; i < 1024; i++) {
            keygen.run(); encapsulate.run(); decapsulate.run(); reject.run(); shake.run();
        }
        measure("keygen", keygen);
        measure("encapsulate", encapsulate);
        measure("decapsulate", decapsulate);
        measure("implicit_rejection", reject);
        measure("shake128_32_840", shake);
        System.out.println("sink=" + sink);
    }
}
