package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Stream;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.microproxy.ClientDetails;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.FlowRecord;
import org.microproxy.FlowTimings;
import org.microproxy.ProxyFailure;
import org.microproxy.ResponseFlag;
import org.microproxy.ResponseSource;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.tls.CertificateBuilder;

/** Every operator of {@link AccessLogFormat}, Envoy's default format, the JSON form and escaping. */
class AccessLogFormatTest {

    static final long START = Instant.parse("2026-10-08T12:34:56.789Z").toEpochMilli();
    static X509Certificate clientCert;
    static X509Certificate serverCert;

    @BeforeAll
    static void certificates() throws Exception {
        clientCert = certificate("client.test");
        serverCert = certificate("origin.test");
    }

    private static X509Certificate certificate(String name) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = g.generateKeyPair();
        return new CertificateBuilder().subject(name, "Example").publicKey(keys.getPublic())
                .validity(Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600)).sign(keys.getPrivate());
    }

    /** A client context with every value an operator may read. */
    static final class Context extends FlowContext {
        ClientHello hello = TlsFingerprintsTest.ja3Example();

        Context(InetSocketAddress client, SSLSession session) {
            super(7, () -> client, () -> session, details());
        }

        private static ClientDetails details() {
            ClientDetails d = new ClientDetails();
            d.setUserName("alice");
            return d;
        }

        @Override
        public ClientHello getClientHello() {
            return hello;
        }

        @Override
        public boolean isEarlyData() {
            return true;
        }

        @Override
        public OptionalInt socksVersion() {
            return OptionalInt.of(5);
        }

        @Override
        public Optional<String> forwardedVia() {
            return Optional.of("corp.test:3128");
        }

        @Override
        public OptionalInt upstreamStatus() {
            return OptionalInt.of(503);
        }
    }

    static final FlowTimings TIMINGS = new FlowTimings(START, 0, 1_000_000, 1_000_000, 3_000_000, 3_000_000,
            6_000_000, 7_000_000, 10_000_000, 25_000_000, 2_000_000);

    static FlowRecord.Builder builder(FlowContext context) {
        HttpHeaders headers = new HttpHeaders()
                .set("Host", "example.test:8080")
                .set("User-Agent", "curl/8.0")
                .set("X-Request-ID", "req-1")
                .set("Referer", "http://ref.test/");
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET,
                "http://example.test:8080/a/b?c=d", headers);
        DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                new HttpHeaders().set("Content-Type", "text/plain"));
        return FlowRecord.builder(context, FlowRecord.Kind.HTTP1)
                .request(request)
                .response(response, ResponseSource.SERVER)
                .trailers(new HttpHeaders().set("grpc-status", "0"))
                .time(START, 25_000_000)
                .timings(TIMINGS)
                .bytes(11, 22)
                .upstreamBytes(33, 44)
                .upstream(new InetSocketAddress("192.0.2.1", 443), new InetSocketAddress("10.0.0.2", 40000),
                        "proxy.test:3128", new Session("TLSv1.3", "TLS_AES_128_GCM_SHA256", serverCert))
                .upstreamTransportFailureReason("handshake failed")
                .downstreamLocalAddress(new InetSocketAddress("10.0.0.2", 8080))
                .outcome(EnumSet.of(ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED, ResponseFlag.UPSTREAM_CONNECTION_FAILURE),
                        new ProxyFailure.ConnectFailed("example.test:8080", new java.net.ConnectException("refused")),
                        "proxy_failure:connect_failed")
                .uniqueId("fixed-id");
    }

    static FlowRecord record() {
        return builder(new Context(new InetSocketAddress("10.0.0.1", 5555),
                new Session("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", clientCert))).build();
    }

    static String render(String format, FlowRecord record) {
        return AccessLogFormat.envoy(format).format(record);
    }

    static Stream<Arguments> operators() throws Exception {
        String clientSubject = clientCert.getSubjectX500Principal().getName();
        String fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(clientCert.getEncoded()));
        return Stream.of(
                // Time
                Arguments.of("%START_TIME%", "2026-10-08T12:34:56.789Z"),
                Arguments.of("%START_TIME(%Y/%m/%d %H:%M:%S %z)%", "2026/10/08 12:34:56 +0000"),
                Arguments.of("%START_TIME(%s.%3f %6f %9f %f)%", "1791462896.789 789000 789000000 789000000"),
                Arguments.of("%START_TIME(%a %A %b %B %e %j %I %p %y %C %u %w %Z)%",
                        "Thu Thursday Oct October  8 281 12 PM 26 20 4 4 UTC"),
                Arguments.of("%START_TIME(%T|%F|%D|%R|%%|%n)%", "12:34:56|2026-10-08|10/08/26|12:34|%|\\n"),
                Arguments.of("%START_TIME(%Y-%m-%dT%H:%M:%S.%3fZ)%", "2026-10-08T12:34:56.789Z"),
                // Headers
                Arguments.of("%REQ(USER-AGENT)%", "curl/8.0"),
                Arguments.of("%REQ(user-agent)%", "curl/8.0"),
                Arguments.of("%REQ(X-MISSING?USER-AGENT)%", "curl/8.0"),
                Arguments.of("%REQ(X-REQUEST-ID?USER-AGENT)%", "req-1"),
                Arguments.of("%REQ(X-MISSING)%", "-"),
                Arguments.of("%REQ(USER-AGENT):4%", "curl"),
                Arguments.of("%REQUEST_HEADER(:METHOD)%", "GET"),
                Arguments.of("%REQ(:PATH)%", "/a/b?c=d"),
                Arguments.of("%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%", "/a/b?c=d"),
                Arguments.of("%REQ(:AUTHORITY)%", "example.test:8080"),
                Arguments.of("%REQ(:SCHEME)%", "http"),
                Arguments.of("%RESP(CONTENT-TYPE)%", "text/plain"),
                Arguments.of("%RESPONSE_HEADER(:STATUS)%", "200"),
                Arguments.of("%RESP(X-MISSING)%", "-"),
                Arguments.of("%TRAILER(GRPC-STATUS)%", "0"),
                Arguments.of("%RESPONSE_TRAILER(grpc-message)%", "-"),
                // Request and response
                Arguments.of("%PROTOCOL%", "HTTP/1.1"),
                Arguments.of("%RESPONSE_CODE%", "200"),
                Arguments.of("%RESPONSE_CODE_DETAILS%", "proxy_failure:connect_failed"),
                Arguments.of("%RESPONSE_FLAGS%", "UF,URX"),
                Arguments.of("%RESPONSE_FLAGS_LONG%", "UpstreamConnectionFailure,UpstreamRetryLimitExceeded"),
                // Durations
                Arguments.of("%DURATION%", "25"),
                Arguments.of("%REQUEST_DURATION%", "7"),
                Arguments.of("%RESPONSE_DURATION%", "10"),
                Arguments.of("%RESPONSE_TX_DURATION%", "15"),
                Arguments.of("%COMMON_DURATION(US_CX_BEG:US_CX_END:us)%", "2000"),
                Arguments.of("%COMMON_DURATION(START_TIME:DS_TX_END:ms)%", "25"),
                Arguments.of("%COMMON_DURATION(DS_RX_BEG:US_RX_BEG:ns)%", "10000000"),
                Arguments.of("%COMMON_DURATION(US_HS_END:US_RX_END:ms)%", "19"),
                Arguments.of("%COMMON_DURATION(NOWHERE:DS_TX_END:ms)%", "-"),
                Arguments.of("%COMMON_DURATION(START_TIME:DS_TX_END:days)%", "-"),
                Arguments.of("%DOWNSTREAM_HANDSHAKE_DURATION%", "2"),
                // Bytes
                Arguments.of("%BYTES_RECEIVED%", "11"),
                Arguments.of("%BYTES_SENT%", "22"),
                Arguments.of("%UPSTREAM_WIRE_BYTES_SENT%", "33"),
                Arguments.of("%UPSTREAM_WIRE_BYTES_RECEIVED%", "44"),
                // Upstream
                Arguments.of("%UPSTREAM_HOST%", "192.0.2.1:443"),
                Arguments.of("%UPSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%", "192.0.2.1"),
                Arguments.of("%UPSTREAM_CLUSTER%", "proxy.test:3128"),
                Arguments.of("%UPSTREAM_LOCAL_ADDRESS%", "10.0.0.2:40000"),
                Arguments.of("%UPSTREAM_TRANSPORT_FAILURE_REASON%", "handshake failed"),
                Arguments.of("%UPSTREAM_TLS_VERSION%", "TLSv1.3"),
                Arguments.of("%UPSTREAM_TLS_CIPHER%", "TLS_AES_128_GCM_SHA256"),
                Arguments.of("%UPSTREAM_PEER_SUBJECT%", serverCert.getSubjectX500Principal().getName()),
                Arguments.of("%UPSTREAM_PEER_ISSUER%", serverCert.getIssuerX500Principal().getName()),
                // Downstream
                Arguments.of("%DOWNSTREAM_REMOTE_ADDRESS%", "10.0.0.1:5555"),
                Arguments.of("%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%", "10.0.0.1"),
                Arguments.of("%DOWNSTREAM_REMOTE_PORT%", "5555"),
                Arguments.of("%DOWNSTREAM_LOCAL_ADDRESS%", "10.0.0.2:8080"),
                Arguments.of("%DOWNSTREAM_LOCAL_ADDRESS_WITHOUT_PORT%", "10.0.0.2"),
                Arguments.of("%DOWNSTREAM_LOCAL_PORT%", "8080"),
                Arguments.of("%DOWNSTREAM_TLS_VERSION%", "TLSv1.2"),
                Arguments.of("%DOWNSTREAM_TLS_CIPHER%", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                Arguments.of("%DOWNSTREAM_PEER_SUBJECT%", clientSubject),
                Arguments.of("%DOWNSTREAM_PEER_ISSUER%", clientCert.getIssuerX500Principal().getName()),
                Arguments.of("%DOWNSTREAM_PEER_FINGERPRINT_256%", fingerprint),
                Arguments.of("%REQUESTED_SERVER_NAME%", "example.test"),
                // Identity
                Arguments.of("%CONNECTION_ID%", "7"),
                Arguments.of("%STREAM_ID%", "0"),
                Arguments.of("%UNIQUE_ID%", "fixed-id"),
                // TLS fingerprints
                Arguments.of("%TLS_JA3_FINGERPRINT%", TlsFingerprintsTest.JA3_EXAMPLE_MD5),
                Arguments.of("%TLS_JA4_FINGERPRINT%", "t10d120300_d94e65cdb899_33a13ba74d1c"),
                // MicroProxy's own
                Arguments.of("%MP_RESPONSE_SOURCE%", "SERVER"),
                Arguments.of("%MP_EARLY_DATA%", "true"),
                Arguments.of("%MP_TRANSPARENT_QUIC%", "false"),
                Arguments.of("%MP_SOCKS_VERSION%", "5"),
                Arguments.of("%MP_FORWARDED_VIA%", "corp.test:3128"),
                Arguments.of("%MP_FLOW%", "h1"),
                Arguments.of("%MP_USER%", "alice"),
                Arguments.of("%MP_URL%", "http://example.test:8080/a/b?c=d"),
                Arguments.of("%MP_UPSTREAM_STATUS%", "503"),
                Arguments.of("%MP_TIMING(dns)% %MP_TIMING(connect)% %MP_TIMING(tls)% %MP_TIMING(client_tls)%"
                        + " %MP_TIMING(ttfb)% %MP_TIMING(total)% %MP_TIMING(nope)%",
                        "1.000 2.000 3.000 2.000 10.000 25.000 -"),
                // Unknown operators, literals
                Arguments.of("%NOT_AN_OPERATOR%", "-"),
                Arguments.of("%REQ%", "-"),
                Arguments.of("100%% sure", "100% sure"),
                Arguments.of("a % b %lower% 50%", "a % b %lower% 50%"),
                Arguments.of("[%RESPONSE_CODE%]%RESPONSE_FLAGS%|", "[200]UF,URX|"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("operators")
    void operator(String format, String expected) {
        assertEquals(expected, render(format, record()));
    }

    @Test
    void hostnameIsThisHosts() throws Exception {
        String name = render("%HOSTNAME%", record());
        assertFalse(name.isBlank());
        assertNotEquals("-", name);
    }

    @Test
    void theUniqueIdIsMadeOnceAndOnlyWhenAsked() {
        FlowRecord r = builder(new Context(new InetSocketAddress("10.0.0.1", 1), null)).uniqueId(null).build();
        String id = render("%UNIQUE_ID%", r);
        assertEquals(36, id.length(), id);
        assertEquals(id, render("%UNIQUE_ID%", r), "the same id for the same record");
        FlowRecord other = builder(new Context(new InetSocketAddress("10.0.0.1", 1), null)).uniqueId(null).build();
        assertNotEquals(id, render("%UNIQUE_ID%", other));
    }

    @Test
    void unavailableValuesAreDashes() {
        FlowRecord bare = FlowRecord.builder(new FlowContext(1, () -> null, () -> null, new ClientDetails()),
                FlowRecord.Kind.QUIC_RELAY).build();
        assertEquals("- - 0 - - - - - - - - - - - - - - - - false quic_relay",
                render("%START_TIME% %REQ(:METHOD)% %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_SENT% %DURATION%"
                        + " %UPSTREAM_HOST% %UPSTREAM_CLUSTER% %DOWNSTREAM_REMOTE_ADDRESS% %DOWNSTREAM_LOCAL_ADDRESS%"
                        + " %DOWNSTREAM_TLS_VERSION% %DOWNSTREAM_PEER_SUBJECT% %REQUESTED_SERVER_NAME%"
                        + " %TLS_JA3_FINGERPRINT% %MP_RESPONSE_SOURCE% %MP_SOCKS_VERSION% %MP_URL% %PROTOCOL%"
                        + " %RESPONSE_CODE_DETAILS% %MP_EARLY_DATA% %MP_FLOW%", bare));
    }

    @Test
    void ipv6AddressesAreBracketedWithTheirPort() {
        FlowRecord r = builder(new Context(new InetSocketAddress("::1", 5555), null)).build();
        assertEquals("[0:0:0:0:0:0:0:1]:5555 0:0:0:0:0:0:0:1",
                render("%DOWNSTREAM_REMOTE_ADDRESS% %DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%", r));
    }

    @Test
    void protocolNamesTheClientsHttpVersion() {
        FlowContext h2 = new FlowContext(1, () -> null, () -> null, new ClientDetails()) {
            @Override
            public HttpVersion getHttpVersion() {
                return HttpVersion.HTTP_2_0;
            }
        };
        assertEquals("HTTP/2", render("%PROTOCOL%", builder(h2).build()));
        DefaultHttpRequest http10 = new DefaultHttpRequest(HttpVersion.HTTP_1_0, HttpMethod.GET, "/");
        assertEquals("HTTP/1.0", render("%PROTOCOL%", builder(new Context(null, null)).request(http10).build()));
    }

    @Test
    void connectRequestsHaveAnAuthorityAndNoPath() {
        DefaultHttpRequest connect = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.CONNECT, "example.test:443");
        FlowRecord r = FlowRecord.builder(new Context(null, null), FlowRecord.Kind.TUNNEL).request(connect).build();
        assertEquals("CONNECT example.test:443 - - example.test:443 tunnel",
                render("%REQ(:METHOD)% %REQ(:AUTHORITY)% %REQ(:PATH)% %REQ(:SCHEME)% %MP_URL% %MP_FLOW%", r));
    }

    @Test
    void originFormRequestsGetTheirUrlFromHost() {
        HttpHeaders headers = new HttpHeaders().set("Host", "example.test");
        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/x?y", headers);
        FlowRecord r = builder(new Context(null, new Session("TLSv1.3", "X", clientCert))).request(request).build();
        assertEquals("/x?y https https://example.test/x?y", render("%REQ(:PATH)% %REQ(:SCHEME)% %MP_URL%", r));
        assertEquals("/", AccessLogFormat.Operators.path("http://example.test"));
        assertEquals("/?q", AccessLogFormat.Operators.path("http://example.test?q"));
    }

    @Test
    void envoysDefaultFormatRenders() {
        String expected = "[2026-10-08T12:34:56.789Z] \"GET /a/b?c=d HTTP/1.1\" 200 UF,URX 11 22 25 - \"-\" \"curl/8.0\""
                + " \"req-1\" \"example.test:8080\" \"192.0.2.1:443\"";
        assertEquals(expected, AccessLogFormat.envoy(AccessLogFormat.ENVOY_DEFAULT).format(record()));
        assertEquals(expected, LogFormat.ENVOY.formatter().format(record()));
        assertEquals(expected, LogFormat.parse("envoy").format(record()));
    }

    @Test
    void controlCharactersInValuesAreEscapedAndLiteralsKept() {
        // (Header values cannot hold control characters; a failure reason, from an exception, can.)
        FlowRecord r = builder(new Context(null, null))
                .upstreamTransportFailureReason("evil\nline\tand\u0001bell \"quoted\"").build();
        assertEquals("why=evil\\nline\\tand\\u0001bell \"quoted\"\tend",
                render("why=%UPSTREAM_TRANSPORT_FAILURE_REASON%\tend", r));
        assertEquals("why=evil\\nl", render("why=%UPSTREAM_TRANSPORT_FAILURE_REASON:6%", r),
                "truncated before it is escaped");
    }

    @Test
    void csvAndSquidPresetsQuoteOrJoinTheirValues() {
        HttpHeaders headers = new HttpHeaders().set("User-Agent", "say \"hi\"");
        FlowRecord r = builder(new Context(new InetSocketAddress("10.0.0.1", 5555), null))
                .request(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://h.test/", headers))
                .response(new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                        new HttpHeaders().set("Content-Type", "text/html; charset=utf-8")), ResponseSource.SERVER)
                .build();
        assertEquals("\"2026-10-08T12:34:56.789+0000\",\"10.0.0.1\",\"GET\",\"http://h.test/\",\"200\",\"22\",\"25\","
                + "\"say \"\"hi\"\"\"", LogFormat.CSV.formatter().format(r));
        assertEquals("1791462896.789 25 10.0.0.1 TCP_MISS/200 22 GET http://h.test/ alice DIRECT/192.0.2.1"
                + " text/html;_charset=utf-8", LogFormat.SQUID.formatter().format(r));
    }

    @Test
    void namedPresetsAndFormatStringsParse() {
        assertEquals(LogFormat.CLF.formatter(), LogFormat.parse(" clf "));
        assertEquals("200", LogFormat.parse("%RESPONSE_CODE%").format(record()));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> LogFormat.parse("fancy"));
        assertTrue(e.getMessage().contains("ENVOY"), e.getMessage());
        assertEquals("200", AccessLogFormat.envoy("%RESPONSE_CODE%\n").format(record()), "Envoy's trailing newline");
    }

    // -------------------------------------------------------------------------------------------
    // JSON
    // -------------------------------------------------------------------------------------------

    @Test
    void jsonValuesKeepTheirTypes() {
        Map<String, Object> dict = new LinkedHashMap<>();
        dict.put("start", "%START_TIME%");
        dict.put("status", "%RESPONSE_CODE%");
        dict.put("bytes", "%BYTES_SENT%");
        dict.put("duration", "%DURATION%");
        dict.put("flags", "%RESPONSE_FLAGS%");
        dict.put("early", "%MP_EARLY_DATA%");
        dict.put("ttfb", "%MP_TIMING(ttfb)%");
        dict.put("missing", "%REQ(X-MISSING)%");
        dict.put("missing_number", "%MP_TIMING(nope)%");
        dict.put("mixed", "%REQ(:METHOD)% %REQ(X-MISSING)% %RESPONSE_CODE%");
        dict.put("ua", "%REQ(USER-AGENT):4%");
        dict.put("nested", Map.of("conn", "%CONNECTION_ID%"));
        dict.put("constant", 42);
        dict.put("flag", true);
        dict.put("nothing", null);
        assertEquals("{\"start\":\"2026-10-08T12:34:56.789Z\",\"status\":200,\"bytes\":22,\"duration\":25,"
                + "\"flags\":\"UF,URX\",\"early\":true,\"ttfb\":10.000,\"missing\":null,\"missing_number\":null,"
                + "\"mixed\":\"GET - 200\",\"ua\":\"curl\",\"nested\":{\"conn\":7},\"constant\":42,\"flag\":true,"
                + "\"nothing\":null}", AccessLogFormat.envoyJson(dict).format(record()));
    }

    @Test
    void jsonStringsAreEscaped() {
        FlowRecord r = builder(new Context(null, null)).upstreamTransportFailureReason("a\"b\\c\nd\u0001").build();
        assertEquals("{\"ua\":\"a\\\"b\\\\c\\nd\\u0001\",\"line\":\"ua=a\\\"b\\\\c\\nd\\u0001!\",\"k\\\"ey\":\"x\"}",
                AccessLogFormat.envoyJson("{\"ua\":\"%UPSTREAM_TRANSPORT_FAILURE_REASON%\","
                        + "\"line\":\"ua=%UPSTREAM_TRANSPORT_FAILURE_REASON%!\",\"k\\\"ey\":\"x\"}").format(r));
    }

    @Test
    void jsonFormatsMustBeObjects() {
        assertThrows(IllegalArgumentException.class, () -> AccessLogFormat.envoyJson("[\"%RESPONSE_CODE%\"]"));
        assertThrows(IllegalArgumentException.class, () -> AccessLogFormat.envoyJson("{\"a\":"));
        assertThrows(IllegalArgumentException.class, () -> AccessLogFormat.envoyJson(Map.of("a", List.of())));
        assertTrue(AccessLogFormat.envoyJson("{}").isJson());
    }

    // -------------------------------------------------------------------------------------------
    // Cost
    // -------------------------------------------------------------------------------------------

    @Test
    void theFormatterUsesNoRegularExpressions() throws Exception {
        Path dir = Path.of(AccessLogFormat.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .resolve("org/microproxy/extras");
        List<Path> classes;
        try (Stream<Path> files = Files.list(dir)) {
            classes = files.filter(p -> {
                String n = p.getFileName().toString();
                return n.startsWith("AccessLogFormat") || n.startsWith("Strftime") || n.startsWith("TlsFingerprints");
            }).toList();
        }
        assertTrue(classes.size() > 5, classes.toString());
        for (Path c : classes) {
            String bytes = new String(Files.readAllBytes(c), StandardCharsets.ISO_8859_1);
            assertFalse(bytes.contains("java/util/regex"), c + " refers to java.util.regex");
        }
    }

    @Test
    void renderingAllocatesLittle() {
        com.sun.management.ThreadMXBean threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        AccessLogFormat format = AccessLogFormat.envoy(AccessLogFormat.ENVOY_DEFAULT);
        FlowRecord r = record();
        StringBuilder sb = new StringBuilder(1024);
        for (int i = 0; i < 20_000; i++) {
            sb.setLength(0);
            format.formatTo(r, sb);
        }
        int n = 50_000;
        long before = threads.getCurrentThreadAllocatedBytes();
        for (int i = 0; i < n; i++) {
            sb.setLength(0);
            format.formatTo(r, sb);
        }
        long perLine = (threads.getCurrentThreadAllocatedBytes() - before) / n;
        // Addresses and the flags make a few small strings; parsing, regex or copies would be far more.
        assertTrue(perLine < 512, perLine + " bytes allocated per line");
    }

    // -------------------------------------------------------------------------------------------
    // A TLS session to read
    // -------------------------------------------------------------------------------------------

    /** The parts of a TLS session the operators read. */
    record Session(String protocol, String cipherSuite, X509Certificate peer) implements SSLSession {
        @Override
        public String getProtocol() {
            return protocol;
        }

        @Override
        public String getCipherSuite() {
            return cipherSuite;
        }

        @Override
        public Certificate[] getPeerCertificates() {
            return new Certificate[] {peer};
        }

        @Override
        public byte[] getId() {
            return new byte[0];
        }

        @Override
        public SSLSessionContext getSessionContext() {
            return null;
        }

        @Override
        public long getCreationTime() {
            return 0;
        }

        @Override
        public long getLastAccessedTime() {
            return 0;
        }

        @Override
        public void invalidate() {}

        @Override
        public boolean isValid() {
            return true;
        }

        @Override
        public void putValue(String name, Object value) {}

        @Override
        public Object getValue(String name) {
            return null;
        }

        @Override
        public void removeValue(String name) {}

        @Override
        public String[] getValueNames() {
            return new String[0];
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return null;
        }

        @Override
        public java.security.Principal getPeerPrincipal() {
            return peer.getSubjectX500Principal();
        }

        @Override
        public java.security.Principal getLocalPrincipal() {
            return null;
        }

        @Override
        public String getPeerHost() {
            return null;
        }

        @Override
        public int getPeerPort() {
            return 0;
        }

        @Override
        public int getPacketBufferSize() {
            return 0;
        }

        @Override
        public int getApplicationBufferSize() {
            return 0;
        }
    }
}
