package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import org.junit.jupiter.api.Assumptions;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.tls.CertificateAuthority;

/**
 * grpcio, the gRPC library of Python, as both ends of a call through the proxy: its server ({@code
 * interop/grpc_server.py}) and its client ({@code interop/grpc_client.py}), which reaches the
 * server through the proxy as a forward proxy, with {@code CONNECT}. The interpreter is {@code
 * -Dgrpc.interop.python}, else {@code $GRPC_INTEROP_PYTHON}, else {@code python3}; tests that need
 * it are skipped when it lacks grpcio, unless {@code -Dgrpc.interop.required=true}.
 */
public final class GrpcPeers {

    /** The proxy settings of the environment, which grpcio would otherwise follow or bypass. */
    private static final List<String> PROXY_ENVIRONMENT = List.of("http_proxy", "https_proxy", "grpc_proxy",
            "all_proxy", "no_proxy", "no_grpc_proxy");

    private static volatile String python;
    private static volatile Boolean available;

    private GrpcPeers() {}

    /** Skips the calling test unless Python with grpcio is available (fails it if it is required). */
    public static void assumeAvailable() {
        Boolean known = available;
        if (known == null) {
            python = System.getProperty("grpc.interop.python",
                    System.getenv().getOrDefault("GRPC_INTEROP_PYTHON", "python3"));
            known = hasGrpcio(python);
            available = known;
        }
        if (Boolean.getBoolean("grpc.interop.required")) {
            assertTrue(known, python + " with grpcio is required but not available");
        }
        Assumptions.assumeTrue(known, python + " with grpcio is not available");
    }

    private static boolean hasGrpcio(String python) {
        try {
            Process p = new ProcessBuilder(python, "-c", "import grpc").redirectErrorStream(true).start();
            p.getInputStream().transferTo(OutputStream.nullOutputStream());
            return p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** {@code cmd}, without the environment's proxy settings. */
    private static ProcessBuilder process(List<String> cmd) {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().keySet().removeIf(k -> PROXY_ENVIRONMENT.contains(k.toLowerCase()));
        return pb;
    }

    /** Writes the CA's certificate to {@code dir} as PEM, for the client to trust. */
    public static Path trust(Path dir, CertificateAuthority ca) throws IOException {
        return AioquicPeers.certificates(dir.resolve("grpc-proxy-ca.pem"), ca.getCertificate());
    }

    // ---------------------------------------------------------------------------------------
    // The client

    /**
     * Runs the grpcio client's {@code cases} (all of them when none are named) through the forward
     * proxy at {@code proxy}, to the server at {@code target} ({@code host:port}, as the client
     * asks the proxy for it), trusting {@code ca}. Returns what each case saw, by name.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Map<String, Object>> call(Path dir, InetSocketAddress proxy, String target, Path ca,
            String... cases) throws Exception {
        assumeAvailable();
        List<String> cmd = new ArrayList<>(List.of(python, AioquicPeers.script(dir, "grpc_client.py").toString(),
                "--proxy", "127.0.0.1:" + proxy.getPort(), "--target", target, "--ca", ca.toString()));
        if (cases.length > 0) cmd.addAll(List.of("--cases", String.join(",", cases)));
        Process p = process(cmd).redirectErrorStream(true).start();
        StringBuilder output = new StringBuilder();
        Thread reader = Thread.ofVirtual().start(() -> {
            try (InputStream in = p.getInputStream()) {
                output.append(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            } catch (IOException e) {
                // ended
            }
        });
        if (!p.waitFor(150, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new AssertionError("the grpcio client hung");
        }
        reader.join();
        String result = output.toString().lines().filter(l -> l.startsWith("RESULT ")).findFirst()
                .orElseThrow(() -> new AssertionError("no result from the grpcio client:\n" + output));
        Map<String, Object> json = (Map<String, Object>) AioquicPeers.parseJson(result.substring("RESULT ".length()));
        assertTrue(Boolean.TRUE.equals(json.get("ok")), "grpcio client failed: " + json.get("error") + "\n" + output);
        return (Map<String, Map<String, Object>>) (Map<String, ?>) json.get("results");
    }

    /**
     * Checks what every case of the client saw, and what the server saw of it: {@code via} is what
     * the proxy put in the request's {@code via} field.
     */
    @SuppressWarnings("unchecked")
    public static void checkCalls(Map<String, Map<String, Object>> results, Server server, String via)
            throws Exception {
        Map<String, Object> unary = results.get("unary");
        assertEquals("OK", unary.get("code"), unary.toString());
        assertEquals("hello grpc", unary.get("response"));
        Map<String, Object> initial = (Map<String, Object>) unary.get("initial");
        assertEquals(via, initial.get("x-echo-via"), unary.toString());
        // Binary metadata, base64 on the wire, arrives as it was sent.
        assertEquals(Base64.getEncoder().encodeToString(new byte[] {0, 1, (byte) 0xfe, (byte) 0xff}),
                initial.get("x-client-bin"));
        assertEquals("10", ((Map<String, Object>) unary.get("trailing")).get("x-length"));

        Map<String, Object> serverStreaming = results.get("server_streaming");
        assertEquals("OK", serverStreaming.get("code"));
        assertEquals(List.of(1000L, 1000L, 1000L, 1000L, 1000L), serverStreaming.get("sizes"));
        assertEquals(List.of(0L, 1L, 2L, 3L, 4L), serverStreaming.get("fills"));

        Map<String, Object> clientStreaming = results.get("client_streaming");
        assertEquals("OK", clientStreaming.get("code"));
        assertEquals(clientStreaming.get("expected"), clientStreaming.get("response"));

        Map<String, Object> bidi = results.get("bidi");
        assertEquals("OK", bidi.get("code"));
        assertEquals(List.of("ONE", "TWO", "THREE"), bidi.get("answers"));
        assertEquals(0L, bidi.get("rest"));

        Map<String, Object> error = results.get("error");
        assertEquals("INVALID_ARGUMENT", error.get("code"), error.toString());
        assertEquals("invalid: bad-input", error.get("details"));
        Map<String, Object> trailing = (Map<String, Object>) error.get("trailing");
        assertEquals("yes", trailing.get("x-failure"));
        String details = (String) trailing.get("grpc-status-details-bin");
        assertNotNull(details, error.toString());
        // google.rpc.Status{code, message, details: [Any{type_url, value: ErrorInfo{reason, domain}}]}
        Map<Object, Object> status = Protobuf.decode(Base64.getDecoder().decode(details)).toPlain();
        assertEquals(3L, status.get(1));
        assertEquals("invalid: bad-input", status.get(2));
        Map<Object, Object> any = (Map<Object, Object>) status.get(3);
        assertEquals("type.googleapis.com/google.rpc.ErrorInfo", any.get(1));
        assertEquals(Map.of(1, "BAD_INPUT", 2, "interop.test"), any.get(2));

        Map<String, Object> deadline = results.get("deadline");
        assertEquals("DEADLINE_EXCEEDED", deadline.get("code"), deadline.toString());
        // grpc-timeout reached the server: it saw the client's deadline (which the field's
        // encoding may round up a little), not none.
        double remaining = Double.parseDouble(server.await("WAIT remaining=").substring("WAIT remaining=".length()));
        assertTrue(remaining > 0 && remaining <= (Double) deadline.get("deadline") * 1.1, "remaining " + remaining);
        assertEquals("WAIT_ENDED active=False", server.await("WAIT_ENDED "));

        Map<String, Object> cancel = results.get("cancel");
        assertEquals("started", cancel.get("first"));
        assertEquals("CANCELLED", cancel.get("code"), cancel.toString());
        // No deadline, so only the client's cancellation (RST_STREAM CANCEL) ends the call.
        assertEquals("HOLD remaining=none", server.await("HOLD remaining="));
        assertEquals("HOLD_ENDED active=False", server.await("HOLD_ENDED "));

        Map<String, Object> large = results.get("large");
        assertEquals("OK", large.get("echo_code"));
        assertEquals(8L << 20, large.get("echo_length"));
        assertEquals(Boolean.TRUE, large.get("echo_intact"));
        assertEquals(List.of(2L << 20, 2L << 20, 2L << 20, 2L << 20), large.get("split_sizes"));
        assertEquals(Boolean.TRUE, large.get("split_intact"));
        assertEquals(large.get("collect_expected"), large.get("collected"));

        for (String line : List.of("CALL Echo 10", "CALL Split 5 1000", "CALL Collect 3 5009", "CALL Chat 3",
                "CALL Fail", "CALL Echo 8388608", "CALL Split 4 2097152", "CALL Collect 2 7340032")) {
            assertEquals(line, server.await(line));
        }
    }

    // ---------------------------------------------------------------------------------------
    // The server

    /** A running grpcio server. */
    public static final class Server implements AutoCloseable {
        private final Process process;
        private final ReentrantLock lock = new ReentrantLock();
        private final Condition added = lock.newCondition();
        private final List<String> lines = new ArrayList<>();
        private boolean ended;
        public final int port;

        /**
         * Starts the server on loopback with a certificate for {@code localhost} and {@code
         * 127.0.0.1} that {@code ca} issues, written to {@code dir}.
         */
        public Server(Path dir, CertificateAuthority ca) throws Exception {
            assumeAvailable();
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keys = g.generateKeyPair();
            X509Certificate leaf = ca.issue(keys.getPublic(), List.of("localhost", "127.0.0.1"));
            Path certificate = AioquicPeers.certificates(dir.resolve("grpc-server.pem"), leaf, ca.getCertificate());
            Path key = AioquicPeers.privateKey(dir.resolve("grpc-server-key.pem"), keys.getPrivate());
            process = process(List.of(python, AioquicPeers.script(dir, "grpc_server.py").toString(), "--certificate",
                    certificate.toString(), "--private-key", key.toString()))
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            Thread.ofVirtual().start(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    for (String line; (line = r.readLine()) != null; ) add(line);
                } catch (IOException e) {
                    // the process ended
                } finally {
                    lock.lock();
                    try {
                        ended = true;
                        added.signalAll();
                    } finally {
                        lock.unlock();
                    }
                }
            });
            String first = await(l -> true, 30);
            assertTrue(first.startsWith("LISTENING "), first);
            this.port = Integer.parseInt(first.substring("LISTENING ".length()).trim());
        }

        private void add(String line) {
            lock.lock();
            try {
                lines.add(line);
                added.signalAll();
            } finally {
                lock.unlock();
            }
        }

        /** The first line it printed that starts with {@code prefix}, waiting up to 30 seconds for it. */
        public String await(String prefix) throws InterruptedException {
            return await(l -> l.startsWith(prefix), 30);
        }

        private String await(Predicate<String> match, int seconds) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            lock.lock();
            try {
                while (true) {
                    for (String l : lines) {
                        if (match.test(l)) return l;
                    }
                    long left = deadline - System.nanoTime();
                    if (ended || left <= 0) throw new AssertionError("the grpcio server did not print it; it printed " + lines);
                    added.awaitNanos(left);
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void close() throws IOException {
            process.getOutputStream().close(); // the server exits when stdin closes
            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) process.destroyForcibly();
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }
}
