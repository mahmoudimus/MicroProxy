package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.management.HotSpotDiagnosticMXBean;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;

/**
 * aioquic, an independent HTTP/3 implementation, as a peer of the proxy's HTTP/3 tests: its HTTP/3
 * client ({@code interop/h3_requests.py}) and server ({@code interop/h3_origin.py}). The
 * interpreter is found as the QUIC module's {@code AioquicInteropTest} finds it: {@code
 * -Dquic.interop.python}, else {@code $QUIC_INTEROP_PYTHON}, else {@code python3}; tests that need
 * it are skipped when it lacks aioquic, unless {@code -Dquic.interop.required=true}.
 */
public final class AioquicPeers {

    private static volatile String python;
    private static volatile Boolean available;

    private AioquicPeers() {}

    /** Skips the calling test unless Python with aioquic is available (fails it if it is required). */
    public static void assumeAvailable() {
        Boolean known = available;
        if (known == null) {
            python = System.getProperty("quic.interop.python",
                    System.getenv().getOrDefault("QUIC_INTEROP_PYTHON", "python3"));
            known = hasAioquic(python);
            available = known;
        }
        if (Boolean.getBoolean("quic.interop.required")) {
            assertTrue(known, python + " with aioquic is required but not available");
        }
        Assumptions.assumeTrue(known, python + " with aioquic is not available");
    }

    private static boolean hasAioquic(String python) {
        try {
            Process p = new ProcessBuilder(python, "-c", "import aioquic").redirectErrorStream(true).start();
            p.getInputStream().transferTo(OutputStream.nullOutputStream());
            return p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** A peer script from the test resources, copied to {@code dir} (it may live in a jar). */
    public static Path script(Path dir, String name) throws IOException {
        Path target = dir.resolve(name);
        if (!Files.exists(target)) {
            try (InputStream in = AioquicPeers.class.getResourceAsStream("/interop/" + name)) {
                assertNotNull(in, "no test resource interop/" + name);
                Files.copy(in, target);
            }
        }
        return target;
    }

    /** Writes a PEM file of {@code type} ({@code CERTIFICATE}, {@code PRIVATE KEY}) holding {@code ders}. */
    public static Path pem(Path file, String type, byte[]... ders) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (byte[] der : ders) {
            sb.append("-----BEGIN ").append(type).append("-----\n")
                    .append(Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der))
                    .append("\n-----END ").append(type).append("-----\n");
        }
        return Files.writeString(file, sb);
    }

    /** Writes {@code chain} as a PEM certificate file. */
    public static Path certificates(Path file, X509Certificate... chain) throws IOException {
        byte[][] ders = new byte[chain.length][];
        try {
            for (int i = 0; i < chain.length; i++) ders[i] = chain[i].getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
        return pem(file, "CERTIFICATE", ders);
    }

    /** Writes {@code key} as a PEM PKCS#8 file. */
    public static Path privateKey(Path file, PrivateKey key) throws IOException {
        return pem(file, "PRIVATE KEY", key.getEncoded());
    }

    // ---------------------------------------------------------------------------------------
    // The client

    /** One request for {@link #requests}: method, path, fields, and a text body or a random one. */
    public static Map<String, Object> request(String method, String path) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("method", method);
        r.put("path", path);
        return r;
    }

    /**
     * Sends {@code requests} to an HTTP/3 server on loopback {@code port}, trusting {@code ca}, on
     * one connection (all at once if {@code concurrent}), and returns the responses: maps with
     * {@code status}, {@code headers} and {@code trailers} (lists of [name, value]), {@code
     * length}, {@code sha256}, {@code sent_sha256}, {@code text} for short text bodies, and {@code
     * reset} (an error code, or null).
     */
    public static List<Map<String, Object>> requests(Path dir, int port, Path ca, List<Map<String, Object>> requests,
            boolean concurrent) throws Exception {
        return requests(dir, port, ca, "localhost", requests, concurrent);
    }

    /** {@link #requests(Path, int, Path, List, boolean)} asking for {@code serverName} (SNI and {@code :authority}). */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> requests(Path dir, int port, Path ca, String serverName,
            List<Map<String, Object>> requests, boolean concurrent) throws Exception {
        assumeAvailable();
        Path file = Files.createTempFile(dir, "requests", ".json");
        Files.writeString(file, toJson(requests));
        List<String> cmd = new ArrayList<>(List.of(python, script(dir, "h3_requests.py").toString(), "127.0.0.1",
                Integer.toString(port), "--ca", ca.toString(), "--server-name", serverName, "--requests", file.toString()));
        if (concurrent) cmd.add("--concurrent");
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
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
            throw new AssertionError("the aioquic client hung");
        }
        reader.join();
        String result = output.toString().lines().filter(l -> l.startsWith("RESULT ")).findFirst()
                .orElseThrow(() -> new AssertionError("no result from the aioquic client:\n" + output));
        Map<String, Object> json = (Map<String, Object>) parseJson(result.substring("RESULT ".length()));
        if (!Boolean.TRUE.equals(json.get("ok"))) {
            String error = String.valueOf(json.get("error"));
            throw new AssertionError("aioquic client failed: " + error + "\n" + output
                    + (error.startsWith("TimeoutError") || error.startsWith("ConnectionError") ? proxyThreads(dir) : ""));
        }
        return (List<Map<String, Object>>) json.get("responses");
    }

    /**
     * The stacks of this JVM's threads, virtual ones included, that are in the proxy or its QUIC
     * stack: where the proxy was when a client timed out waiting on it.
     */
    static String proxyThreads(Path dir) {
        try {
            Path file = dir.resolve("threads-" + System.nanoTime() + ".txt").toAbsolutePath();
            ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class)
                    .dumpThreads(file.toString(), HotSpotDiagnosticMXBean.ThreadDumpFormat.TEXT_PLAIN);
            StringBuilder sb = new StringBuilder("\nproxy threads:\n");
            for (String block : Files.readString(file).split("\n\n")) {
                if (block.contains("org.microproxy.impl") || block.contains("io.github.mahmoudimus.quic")) {
                    sb.append(block).append("\n\n");
                }
            }
            return sb.toString();
        } catch (IOException | RuntimeException e) {
            return "\n(no thread dump: " + e + ")";
        }
    }

    /**
     * Runs aioquic's MASQUE client ({@code interop/h3_masque.py}) against a forward proxy's HTTP/3
     * listener on loopback {@code port}, trusting {@code ca}: a CONNECT to {@code tcpTarget}, a
     * WebSocket to {@code wsTarget} and CONNECT-UDP to {@code udpTarget}, each skipped when null.
     * Returns what each scenario saw: {@code connect_status}, {@code connect_echo}, {@code
     * ws_status}, {@code ws_echo}, {@code udp_status}, {@code udp_datagram_echoes}, {@code
     * udp_capsule_echo} and {@code udp_ended}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> masque(Path dir, int port, Path ca, String tcpTarget, String wsTarget,
            String udpTarget) throws Exception {
        assumeAvailable();
        List<String> cmd = new ArrayList<>(List.of(python, script(dir, "h3_masque.py").toString(), "127.0.0.1",
                Integer.toString(port), "--ca", ca.toString(), "--server-name", "localhost"));
        if (tcpTarget != null) cmd.addAll(List.of("--tcp-target", tcpTarget));
        if (wsTarget != null) cmd.addAll(List.of("--ws-target", wsTarget));
        if (udpTarget != null) cmd.addAll(List.of("--udp-target", udpTarget));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
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
            throw new AssertionError("the aioquic MASQUE client hung");
        }
        reader.join();
        String result = output.toString().lines().filter(l -> l.startsWith("RESULT ")).findFirst()
                .orElseThrow(() -> new AssertionError("no result from the aioquic MASQUE client:\n" + output));
        Map<String, Object> json = (Map<String, Object>) parseJson(result.substring("RESULT ".length()));
        assertTrue(Boolean.TRUE.equals(json.get("ok")), "aioquic MASQUE client failed: " + json.get("error") + "\n" + output);
        return (Map<String, Object>) json.get("results");
    }

    /**
     * Runs aioquic's raw QUIC client ({@code interop/quic_echo_client.py}) with {@code alpn},
     * asking for {@code serverName} and trusting {@code ca}: over UDP to loopback {@code port}, or,
     * with a {@code masqueTarget}, inside a CONNECT-UDP flow to it, opened on the forward proxy's
     * HTTP/3 listener at {@code port} (trusted with {@code proxyCa}). Returns what it saw: {@code
     * alpn}, {@code echoes}, {@code big_ok}, {@code big_length}, {@code uni_reply}, {@code datagram},
     * {@code reset_stream} and, inside a flow, {@code masque_status}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> quicEcho(Path dir, int port, Path ca, String serverName, String alpn,
            String masqueTarget, Path proxyCa) throws Exception {
        assumeAvailable();
        List<String> cmd = new ArrayList<>(List.of(python, script(dir, "quic_echo_client.py").toString(), "127.0.0.1",
                Integer.toString(port), "--ca", ca.toString(), "--server-name", serverName, "--alpn", alpn));
        if (masqueTarget != null) cmd.addAll(List.of("--masque-target", masqueTarget, "--proxy-ca", proxyCa.toString()));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
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
            throw new AssertionError("the aioquic QUIC client hung");
        }
        reader.join();
        String result = output.toString().lines().filter(l -> l.startsWith("RESULT ")).findFirst()
                .orElseThrow(() -> new AssertionError("no result from the aioquic QUIC client:\n" + output));
        Map<String, Object> json = (Map<String, Object>) parseJson(result.substring("RESULT ".length()));
        assertTrue(Boolean.TRUE.equals(json.get("ok")), "aioquic QUIC client failed: " + json.get("error") + "\n" + output);
        return (Map<String, Object>) json.get("results");
    }

    /**
     * Runs aioquic's DNS over QUIC client ({@code interop/doq_client.py}) over UDP to loopback
     * {@code port}, asking for {@code serverName} and trusting {@code ca}: one query for the A
     * records of each of {@code names}, on a stream each, all at once, written in pieces with
     * {@code split}. Returns what it saw: {@code alpn}, and {@code answers}, each name's {@code
     * rcode} and {@code addresses}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> doq(Path dir, int port, Path ca, String serverName, List<String> names,
            boolean split) throws Exception {
        assumeAvailable();
        List<String> cmd = new ArrayList<>(List.of(python, script(dir, "doq_client.py").toString(), "127.0.0.1",
                Integer.toString(port), "--ca", ca.toString(), "--server-name", serverName, "--names",
                String.join(",", names)));
        if (split) cmd.add("--split");
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        StringBuilder output = new StringBuilder();
        Thread reader = Thread.ofVirtual().start(() -> {
            try (InputStream in = p.getInputStream()) {
                output.append(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            } catch (IOException e) {
                // ended
            }
        });
        if (!p.waitFor(90, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new AssertionError("the aioquic DoQ client hung");
        }
        reader.join();
        String result = output.toString().lines().filter(l -> l.startsWith("RESULT ")).findFirst()
                .orElseThrow(() -> new AssertionError("no result from the aioquic DoQ client:\n" + output));
        Map<String, Object> json = (Map<String, Object>) parseJson(result.substring("RESULT ".length()));
        assertTrue(Boolean.TRUE.equals(json.get("ok")), "aioquic DoQ client failed: " + json.get("error") + "\n" + output);
        return (Map<String, Object>) json.get("results");
    }

    /** The value of the first field named {@code name} in a response's [name, value] list, or null. */
    @SuppressWarnings("unchecked")
    public static String field(Map<String, Object> response, String list, String name) {
        for (Object o : (List<Object>) response.get(list)) {
            List<Object> pair = (List<Object>) o;
            if (name.equals(pair.get(0))) return (String) pair.get(1);
        }
        return null;
    }

    // ---------------------------------------------------------------------------------------
    // The origin

    /** A running aioquic HTTP/3 origin. */
    public static final class Origin implements AutoCloseable {
        private final Process process;
        private final LinkedBlockingQueue<String> lines = new LinkedBlockingQueue<>();
        public final int port;

        /** Starts the origin with {@code certificate} (a PEM chain) and {@code key}, on any UDP port of loopback. */
        public Origin(Path dir, Path certificate, Path key) throws Exception {
            this(dir, certificate, key, 0);
        }

        /** Starts the origin on UDP {@code port}. */
        public Origin(Path dir, Path certificate, Path key, int port) throws Exception {
            assumeAvailable();
            process = new ProcessBuilder(python, script(dir, "h3_origin.py").toString(), "--port", Integer.toString(port),
                    "--certificate", certificate.toString(), "--private-key", key.toString())
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            Thread.ofVirtual().start(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    for (String line; (line = r.readLine()) != null; ) lines.add(line);
                } catch (IOException e) {
                    // the process ended
                }
            });
            String first = lines.poll(30, TimeUnit.SECONDS);
            assertNotNull(first, "the aioquic origin did not start");
            assertTrue(first.startsWith("LISTENING "), first);
            this.port = Integer.parseInt(first.substring("LISTENING ".length()).trim());
        }

        /** The "REQUEST method path" lines so far. */
        public List<String> requests() {
            return lines.stream().filter(l -> l.startsWith("REQUEST ")).map(l -> l.substring(8)).toList();
        }

        @Override
        public void close() throws IOException {
            process.getOutputStream().close(); // the origin exits when stdin closes
            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) process.destroyForcibly();
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }

    /** A running aioquic raw QUIC echo server ({@code interop/quic_echo_server.py}). */
    public static final class QuicEchoServer implements AutoCloseable {
        private final Process process;
        private final LinkedBlockingQueue<String> lines = new LinkedBlockingQueue<>();
        public final int port;

        /** Starts the server with {@code certificate} (a PEM chain) and {@code key}, speaking {@code alpn}. */
        public QuicEchoServer(Path dir, Path certificate, Path key, String alpn) throws Exception {
            assumeAvailable();
            process = new ProcessBuilder(python, script(dir, "quic_echo_server.py").toString(), "--certificate",
                    certificate.toString(), "--private-key", key.toString(), "--alpn", alpn)
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            Thread.ofVirtual().start(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    for (String line; (line = r.readLine()) != null; ) lines.add(line);
                } catch (IOException e) {
                    // the process ended
                }
            });
            String first = lines.poll(30, TimeUnit.SECONDS);
            assertNotNull(first, "the aioquic QUIC server did not start");
            assertTrue(first.startsWith("LISTENING "), first);
            this.port = Integer.parseInt(first.substring("LISTENING ".length()).trim());
        }

        /** The lines it printed after LISTENING: CONNECTED, RESET and TERMINATED events. */
        public List<String> events() {
            return List.copyOf(lines);
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

    /** A running aioquic DNS over QUIC server ({@code interop/doq_server.py}). */
    public static final class DoqServer implements AutoCloseable {
        private final Process process;
        private final LinkedBlockingQueue<String> lines = new LinkedBlockingQueue<>();
        public final int port;

        /**
         * Starts the server with {@code certificate} (a PEM chain) and {@code key}, answering from
         * {@code zone} (names and their IPv4 addresses).
         */
        public DoqServer(Path dir, Path certificate, Path key, Map<String, String> zone) throws Exception {
            assumeAvailable();
            List<String> pairs = new ArrayList<>();
            zone.forEach((name, address) -> pairs.add(name + "=" + address));
            process = new ProcessBuilder(python, script(dir, "doq_server.py").toString(), "--certificate",
                    certificate.toString(), "--private-key", key.toString(), "--zone", String.join(",", pairs))
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            Thread.ofVirtual().start(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    for (String line; (line = r.readLine()) != null; ) lines.add(line);
                } catch (IOException e) {
                    // the process ended
                }
            });
            String first = lines.poll(30, TimeUnit.SECONDS);
            assertNotNull(first, "the aioquic DoQ server did not start");
            assertTrue(first.startsWith("LISTENING "), first);
            this.port = Integer.parseInt(first.substring("LISTENING ".length()).trim());
        }

        /** The lines it printed after LISTENING: QUERY, RESET and BAD events. */
        public List<String> events() {
            return List.copyOf(lines);
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

    // ---------------------------------------------------------------------------------------
    // JSON, enough for the peers' requests and results

    static String toJson(Object value) {
        StringBuilder sb = new StringBuilder();
        writeJson(sb, value);
        return sb.toString();
    }

    private static void writeJson(StringBuilder sb, Object value) {
        switch (value) {
            case null -> sb.append("null");
            case String s -> {
                sb.append('"');
                for (char c : s.toCharArray()) {
                    if (c == '"' || c == '\\') sb.append('\\').append(c);
                    else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
                sb.append('"');
            }
            case Number n -> sb.append(n);
            case Boolean b -> sb.append(b);
            case Map<?, ?> m -> {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    writeJson(sb, String.valueOf(e.getKey()));
                    sb.append(':');
                    writeJson(sb, e.getValue());
                }
                sb.append('}');
            }
            case List<?> l -> {
                sb.append('[');
                for (int i = 0; i < l.size(); i++) {
                    if (i > 0) sb.append(',');
                    writeJson(sb, l.get(i));
                }
                sb.append(']');
            }
            default -> throw new IllegalArgumentException("not JSON: " + value);
        }
    }

    static Object parseJson(String text) {
        int[] at = {0};
        Object v = parseValue(text, at);
        return v;
    }

    private static void skip(String s, int[] at) {
        while (at[0] < s.length() && Character.isWhitespace(s.charAt(at[0]))) at[0]++;
    }

    private static Object parseValue(String s, int[] at) {
        skip(s, at);
        char c = s.charAt(at[0]);
        if (c == '{') {
            Map<String, Object> m = new LinkedHashMap<>();
            at[0]++;
            skip(s, at);
            if (s.charAt(at[0]) == '}') {
                at[0]++;
                return m;
            }
            while (true) {
                String key = (String) parseValue(s, at);
                skip(s, at);
                at[0]++; // ':'
                m.put(key, parseValue(s, at));
                skip(s, at);
                if (s.charAt(at[0]++) == '}') return m;
            }
        }
        if (c == '[') {
            List<Object> l = new ArrayList<>();
            at[0]++;
            skip(s, at);
            if (s.charAt(at[0]) == ']') {
                at[0]++;
                return l;
            }
            while (true) {
                l.add(parseValue(s, at));
                skip(s, at);
                if (s.charAt(at[0]++) == ']') return l;
            }
        }
        if (c == '"') {
            StringBuilder sb = new StringBuilder();
            at[0]++;
            while (true) {
                char ch = s.charAt(at[0]++);
                if (ch == '"') return sb.toString();
                if (ch == '\\') {
                    char e = s.charAt(at[0]++);
                    switch (e) {
                        case 'n' -> sb.append('\n');
                        case 't' -> sb.append('\t');
                        case 'r' -> sb.append('\r');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            sb.append((char) Integer.parseInt(s.substring(at[0], at[0] + 4), 16));
                            at[0] += 4;
                        }
                        default -> sb.append(e);
                    }
                } else {
                    sb.append(ch);
                }
            }
        }
        if (s.startsWith("true", at[0])) {
            at[0] += 4;
            return Boolean.TRUE;
        }
        if (s.startsWith("false", at[0])) {
            at[0] += 5;
            return Boolean.FALSE;
        }
        if (s.startsWith("null", at[0])) {
            at[0] += 4;
            return null;
        }
        int start = at[0];
        while (at[0] < s.length() && "+-0123456789.eE".indexOf(s.charAt(at[0])) >= 0) at[0]++;
        String number = s.substring(start, at[0]);
        if (number.isEmpty()) throw new UncheckedIOException(new IOException("bad JSON at " + start + ": " + s));
        return number.contains(".") || number.contains("e") || number.contains("E") ? (Object) Double.parseDouble(number)
                : (Object) Long.parseLong(number);
    }
}
