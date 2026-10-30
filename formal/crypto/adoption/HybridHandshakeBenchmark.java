package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.crypto.Keys;
import io.github.mahmoudimus.quic.crypto.PacketKey;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

/** Complete in-memory TLS 1.3 handshakes through the existing Handshakes fixture. */
public final class HybridHandshakeBenchmark {
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
    private static final byte[] PAYLOAD = "hybrid TLS application data".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static volatile int sink;

    private HybridHandshakeBenchmark() {}

    private static void origin(Class<?> type, Path expected) throws Exception {
        Path actual = Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if (!actual.equals(expected.toRealPath())) throw new AssertionError("Unexpected class origin: " + type + " " + actual);
    }

    private static void applicationData(PacketKey sender, PacketKey receiver) {
        ByteBuffer packet = ByteBuffer.allocate(5 + PAYLOAD.length + PacketKey.TAG_LENGTH);
        packet.put(new byte[] {0x40, 1, 2, 3, 4}).put(PAYLOAD);
        int end = sender.seal(1, packet, 0, 5, 5 + PAYLOAD.length);
        int opened = receiver.open(1, packet, 0, 5, end);
        if (opened != 5 + PAYLOAD.length || !Arrays.equals(PAYLOAD,
                Arrays.copyOfRange(packet.array(), 5, opened))) throw new AssertionError("Application data failed");
        sink ^= packet.get(5);
    }

    private static void handshake(TlsConfig client, TlsConfig server) throws Exception {
        Handshakes h = Handshakes.run(client, server);
        h.assertAgreement();
        if (h.client.negotiatedGroup() != NamedGroup.X25519_MLKEM768
                || h.server.negotiatedGroup() != NamedGroup.X25519_MLKEM768
                || h.client.cipherSuite() != CipherSuite.TLS_AES_128_GCM_SHA256
                || !"h3".equals(h.client.negotiatedAlpn()) || h.client.usedHelloRetryRequest()
                || h.client.isResumed() || h.server.isResumed()) {
            throw new AssertionError("Expected a full X25519MLKEM768 handshake without retry");
        }
        Keys c = Keys.fromSecrets(h.clientSecrets.get(EncryptionLevel.ONE_RTT), false);
        Keys s = Keys.fromSecrets(h.serverSecrets.get(EncryptionLevel.ONE_RTT), true);
        applicationData(c.local().packet(), s.remote().packet());
        applicationData(s.local().packet(), c.remote().packet());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 7) throw new IllegalArgumentException("backend main fixtures harness native-or-none warmup batch");
        origin(MlKem768.class, Path.of(args[0]));
        origin(Shake.class, Path.of(args[0]));
        origin(TlsSession.class, Path.of(args[1]));
        origin(Handshakes.class, Path.of(args[2]));
        origin(TestCerts.class, Path.of(args[2]));
        origin(HybridHandshakeBenchmark.class, Path.of(args[3]));
        if (!args[4].equals("none")) {
            origin(Class.forName("io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeMlKem.__default"), Path.of(args[4]));
        }
        int warmup = Integer.parseInt(args[5]);
        int batch = Integer.parseInt(args[6]);
        TestCerts.Authority ca = TestCerts.seeded("Hybrid benchmark CA", 20261029);
        CertifiedKey certificate = ca.issue(TestCerts.KeyType.P256, "quic.test");
        TlsConfig client = TlsConfig.builder().serverName("quic.test").alpnProtocols("h3")
                .trustManager(ca.trustManager()).groups(NamedGroup.X25519_MLKEM768)
                .cipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256).secureRandom(TestCerts.seededRandom(41)).build();
        TlsConfig server = TlsConfig.builder().certificate(certificate).alpnProtocols("h3")
                .groups(NamedGroup.X25519_MLKEM768).cipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256)
                .secureRandom(TestCerts.seededRandom(43)).build();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (var cert : certificate.chain()) sha.update(cert.getEncoded());
        System.out.println("{\"certificate_chain_sha256\":\"" + HexFormat.of().formatHex(sha.digest()) + "\"}");
        THREADS.setThreadCpuTimeEnabled(true);
        THREADS.setThreadAllocatedMemoryEnabled(true);
        for (int i = 0; i < warmup; i++) handshake(client, server);
        for (int sample = 0; sample < 9; sample++) {
            long wall = System.nanoTime();
            long cpu = THREADS.getCurrentThreadCpuTime();
            long allocated = THREADS.getThreadAllocatedBytes(Thread.currentThread().threadId());
            for (int i = 0; i < batch; i++) handshake(client, server);
            long bytes = THREADS.getThreadAllocatedBytes(Thread.currentThread().threadId()) - allocated;
            long cpuNanos = THREADS.getCurrentThreadCpuTime() - cpu;
            long wallNanos = System.nanoTime() - wall;
            System.out.printf("{\"sample\":%d,\"completed_full_handshakes\":%d,\"wall_ns\":%d,\"cpu_ns\":%d,\"allocated_bytes\":%d}%n",
                    sample, batch, wallNanos, cpuNanos, bytes);
        }
        System.out.println("{\"sink\":" + sink + "}");
    }
}
