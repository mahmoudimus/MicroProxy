package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final Map<LogFormat, List<String>> lines = new EnumMap<>(LogFormat.class);

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.fixed(200, "hello"));
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withPort(0);
        Clock clock = Clock.fixed(Instant.parse("2026-10-08T12:34:56.789Z"), ZoneOffset.UTC);
        for (LogFormat format : LogFormat.values()) {
            List<String> sink = new CopyOnWriteArrayList<>();
            lines.put(format, sink);
            bootstrap.plusActivityTracker(new ActivityLogger(format, sink::add, clock));
        }
        proxy = bootstrap.start();
    }

    @AfterEach
    void tearDown() {
        proxy.abort();
        origin.stop(0);
    }

    @Test
    void everyFormatLogsTheExchange() {
        String target = url(origin, "/path?q=\"x\"".replace("\"", "%22"));
        assertEquals(200, get(client(proxy), target).statusCode());
        awaitExtended(1);
        for (LogFormat format : LogFormat.values()) {
            assertEquals(1, lines.get(format).size(), format + ": " + lines.get(format));
        }
        String request = "\"GET " + target + " HTTP/1.1\"";
        assertEquals("127.0.0.1 - - [08/Oct/2026:12:34:56 +0000] " + request + " 200 5", lines.get(LogFormat.CLF).get(0));
        assertTrue(lines.get(LogFormat.ELF).get(0).startsWith("127.0.0.1 - - [08/Oct/2026:12:34:56 +0000] " + request
                + " 200 5 \"-\" \"Java-http-client/"), lines.get(LogFormat.ELF).get(0));
        assertTrue(lines.get(LogFormat.W3C).get(0).startsWith("2026-10-08 12:34:56 127.0.0.1 GET " + target + " 200 5 "));
        assertTrue(Pattern.matches("\\{\"timestamp\":\"2026-10-08T12:34:56\\.789\\+0000\",\"client_ip\":\"127\\.0\\.0\\.1\","
                + "\"user\":null,\"method\":\"GET\",\"uri\":\"[^\"]+\",\"protocol\":\"HTTP/1\\.1\",\"status\":200,"
                + "\"bytes\":5,\"duration\":0,\"user_agent\":\"Java-http-client/[^\"]+\"}", lines.get(LogFormat.JSON).get(0)),
                lines.get(LogFormat.JSON).get(0));
        assertTrue(lines.get(LogFormat.LTSV).get(0).startsWith("time:2026-10-08T12:34:56.789+0000\thost:127.0.0.1\t"));
        assertTrue(lines.get(LogFormat.CSV).get(0).startsWith("\"2026-10-08T12:34:56.789+0000\",\"127.0.0.1\",\"GET\","));
        assertTrue(Pattern.matches("1791462896\\.789 +0 127\\.0\\.0\\.1 TCP_MISS/200 5 GET \\S+ - DIRECT/127\\.0\\.0\\.1 -",
                lines.get(LogFormat.SQUID).get(0)), lines.get(LogFormat.SQUID).get(0));
        assertEquals("127.0.0.1 [08/Oct/2026:12:34:56.789] " + request + " 200 5 0", lines.get(LogFormat.HAPROXY).get(0));
    }

    /** JSON_EXTENDED lines are written once the response is complete, which the client may not wait for. */
    private void awaitExtended(int n) {
        for (int i = 0; i < 200 && lines.get(LogFormat.JSON_EXTENDED).size() < n; i++) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    @Test
    void extendedJsonAddsSourceAndTimings() {
        String target = url(origin, "/timed");
        assertEquals(200, get(client(proxy), target).statusCode());
        awaitExtended(1);
        String line = lines.get(LogFormat.JSON_EXTENDED).get(0);
        assertTrue(line.startsWith(lines.get(LogFormat.JSON).get(0).replaceAll("}$", "")), line);
        assertTrue(Pattern.matches(".*,\"source\":\"SERVER\",\"upstream_status\":200,\"ttfb_ms\":\\d+\\.\\d{3},"
                + "\"total_ms\":\\d+\\.\\d{3},\"dns_ms\":\\d+\\.\\d{3},\"connect_ms\":\\d+\\.\\d{3},\"tls_ms\":null}", line),
                line);

        assertEquals(502, get(client(proxy), "http://no-such-host.invalid/x").statusCode());
        awaitExtended(2);
        line = lines.get(LogFormat.JSON_EXTENDED).get(1);
        assertTrue(line.contains(",\"status\":502,"), line);
        assertTrue(line.contains(",\"source\":\"PROXY\",\"upstream_status\":null,\"ttfb_ms\":null,\"total_ms\":"), line);
    }

    @Test
    void proxyGeneratedResponsesAreLoggedToo() {
        assertEquals(502, get(client(proxy), "http://no-such-host.invalid/x").statusCode());
        assertTrue(lines.get(LogFormat.CLF).get(0).endsWith("\"GET http://no-such-host.invalid/x HTTP/1.1\" 502 "
                + "Bad Gateway".length()), lines.get(LogFormat.CLF).get(0));
    }
}
