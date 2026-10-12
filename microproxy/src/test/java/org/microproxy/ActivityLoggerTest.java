package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.extras.ActivityLogger;
import org.microproxy.extras.LogFormat;

class ActivityLoggerTest {

    private static final String CLF_DATE = "\\d\\d/[A-Z][a-z]{2}/\\d{4}:\\d\\d:\\d\\d:\\d\\d \\+0000";
    private static final String ISO_DATE = "\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}\\+0000";

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final Map<LogFormat, List<String>> lines = new EnumMap<>(LogFormat.class);

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.fixed(200, "hello"));
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withPort(0);
        for (LogFormat format : LogFormat.values()) {
            List<String> sink = new CopyOnWriteArrayList<>();
            lines.put(format, sink);
            bootstrap.plusActivityTracker(new ActivityLogger(format, sink::add));
        }
        proxy = bootstrap.start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
        origin.stop(0);
    }

    /** Lines are written once the exchange is over, which the client may not wait for. */
    private void await(int n) {
        TestSupport.eventually(n + " lines in every format",
                () -> lines.values().stream().allMatch(l -> l.size() >= n));
    }

    private static void assertMatches(String regex, String line) {
        assertTrue(Pattern.matches(regex, line), line);
    }

    @Test
    void everyFormatLogsTheExchange() {
        String target = url(origin, "/path?q=\"x\"".replace("\"", "%22"));
        assertEquals(200, get(client(proxy), target).statusCode());
        await(1);
        for (LogFormat format : LogFormat.values()) {
            assertEquals(1, lines.get(format).size(), format + ": " + lines.get(format));
        }
        String request = "\"GET " + Pattern.quote(target) + " HTTP/1.1\"";
        assertMatches("127\\.0\\.0\\.1 - - \\[" + CLF_DATE + "\\] " + request + " 200 5", lines.get(LogFormat.CLF).get(0));
        assertMatches("127\\.0\\.0\\.1 - - \\[" + CLF_DATE + "\\] " + request + " 200 5 \"-\" \"Java-http-client/.*\"",
                lines.get(LogFormat.ELF).get(0));
        assertMatches("\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d 127\\.0\\.0\\.1 GET " + Pattern.quote(target)
                + " 200 5 \"Java-http-client/.*\"", lines.get(LogFormat.W3C).get(0));
        assertMatches("\\{\"timestamp\":\"" + ISO_DATE + "\",\"client_ip\":\"127\\.0\\.0\\.1\","
                + "\"user\":null,\"method\":\"GET\",\"uri\":\"[^\"]+\",\"protocol\":\"HTTP/1\\.1\",\"status\":200,"
                + "\"bytes\":5,\"duration\":\\d+,\"user_agent\":\"Java-http-client/[^\"]+\"}", lines.get(LogFormat.JSON).get(0));
        assertMatches("time:" + ISO_DATE + "\thost:127\\.0\\.0\\.1\tuser:-\tmethod:GET\turi:\\S+\tstatus:200\tsize:5"
                + "\tduration:\\d+\tua:Java-http-client/.*", lines.get(LogFormat.LTSV).get(0));
        assertMatches("\"" + ISO_DATE + "\",\"127\\.0\\.0\\.1\",\"GET\",\"[^\"]+\",\"200\",\"5\",\"\\d+\",\"Java-http-client/.*\"",
                lines.get(LogFormat.CSV).get(0));
        assertMatches("\\d{10}\\.\\d{3} \\d+ 127\\.0\\.0\\.1 TCP_MISS/200 5 GET \\S+ - DIRECT/127\\.0\\.0\\.1 -",
                lines.get(LogFormat.SQUID).get(0));
        assertMatches("127\\.0\\.0\\.1 \\[\\d\\d/[A-Z][a-z]{2}/\\d{4}:\\d\\d:\\d\\d:\\d\\d\\.\\d{3}\\] " + request
                + " 200 5 \\d+", lines.get(LogFormat.HAPROXY).get(0));
        assertMatches("\\[\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}Z\\] \"GET /path\\?q=%22x%22 HTTP/1\\.1\" 200 - 0 5"
                + " \\d+ - \"-\" \"Java-http-client/[^\"]+\" \"-\" \"127\\.0\\.0\\.1:\\d+\" \"127\\.0\\.0\\.1:\\d+\"",
                lines.get(LogFormat.ENVOY).get(0));
    }

    @Test
    void extendedJsonAddsSourceTimingsAndFlags() {
        String target = url(origin, "/timed");
        assertEquals(200, get(client(proxy), target).statusCode());
        await(1);
        String line = lines.get(LogFormat.JSON_EXTENDED).get(0);
        assertTrue(line.startsWith(lines.get(LogFormat.JSON).get(0).replaceAll("}$", "")), line);
        assertMatches(".*,\"source\":\"SERVER\",\"upstream_status\":200,\"ttfb_ms\":\\d+\\.\\d{3},"
                + "\"total_ms\":\\d+\\.\\d{3},\"dns_ms\":\\d+\\.\\d{3},\"connect_ms\":\\d+\\.\\d{3},\"tls_ms\":null,"
                + "\"response_flags\":\"-\",\"response_code_details\":\"via_upstream\",\"flow\":\"h1\"}", line);

        assertEquals(502, get(client(proxy), "http://no-such-host.invalid/x").statusCode());
        await(2);
        line = lines.get(LogFormat.JSON_EXTENDED).get(1);
        assertTrue(line.contains(",\"status\":502,"), line);
        assertTrue(line.contains(",\"source\":\"PROXY\",\"upstream_status\":null,\"ttfb_ms\":null,\"total_ms\":"), line);
        assertTrue(line.contains("\"response_flags\":\"DF\",\"response_code_details\":\"proxy_failure:unresolved_host\""),
                line);
    }

    @Test
    void proxyGeneratedResponsesAreLoggedToo() {
        assertEquals(502, get(client(proxy), "http://no-such-host.invalid/x").statusCode());
        await(1);
        assertTrue(lines.get(LogFormat.CLF).get(0).endsWith("\"GET http://no-such-host.invalid/x HTTP/1.1\" 502 "
                + "Bad Gateway".length()), lines.get(LogFormat.CLF).get(0));
        assertTrue(lines.get(LogFormat.ENVOY).get(0).contains("\" 502 DF 0 11 "), lines.get(LogFormat.ENVOY).get(0));
    }
}
