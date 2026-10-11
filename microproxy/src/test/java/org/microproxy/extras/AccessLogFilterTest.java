package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.microproxy.FlowRecord;
import org.microproxy.ResponseFlag;
import org.microproxy.ResponseSource;
import org.microproxy.extras.AccessLogFilter.Comparison;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/** The access-log filters, built in Java and parsed from the compact syntax. */
class AccessLogFilterTest {

    private static FlowRecord record(int status, long durationMillis, String path, Set<ResponseFlag> flags,
            String... headers) {
        HttpHeaders h = new HttpHeaders();
        for (int i = 0; i < headers.length; i += 2) h.add(headers[i], headers[i + 1]);
        return AccessLogFormatTest.builder(new AccessLogFormatTest.Context(new InetSocketAddress("10.0.0.1", 1), null))
                .request(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://h.test" + path, h))
                .response(status == 0 ? null : new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(status)),
                        ResponseSource.SERVER)
                .time(1, durationMillis * 1_000_000)
                .outcome(flags, null, null)
                .build();
    }

    private static FlowRecord status(int status) {
        return record(status, 10, "/", Set.of());
    }

    @Test
    void statusCode() {
        AccessLogFilter errors = AccessLogFilter.statusCode(Comparison.GE, 500);
        assertTrue(errors.test(status(500)));
        assertTrue(errors.test(status(503)));
        assertFalse(errors.test(status(404)));
        assertTrue(AccessLogFilter.statusCode(Comparison.EQ, 404).test(status(404)));
        assertTrue(AccessLogFilter.statusCode(Comparison.NE, 200).test(status(404)));
        assertTrue(AccessLogFilter.statusCode(Comparison.LE, 299).test(status(204)));
        assertTrue(AccessLogFilter.statusCode(Comparison.LT, 300).test(status(0)), "no response is status 0");
        assertFalse(AccessLogFilter.statusCode(Comparison.GT, 500).test(status(500)));
    }

    @Test
    void duration() {
        AccessLogFilter slow = AccessLogFilter.duration(Comparison.GE, 1000);
        assertTrue(slow.test(record(200, 1500, "/", Set.of())));
        assertFalse(slow.test(record(200, 999, "/", Set.of())));
        FlowRecord unknown = AccessLogFormatTest.builder(new AccessLogFormatTest.Context(null, null)).time(1, -1).build();
        assertFalse(slow.test(unknown), "an unknown duration never passes");
    }

    @Test
    void notHealthCheck() {
        AccessLogFilter f = AccessLogFilter.notHealthCheck();
        assertFalse(f.test(record(200, 1, "/healthz", Set.of())));
        assertFalse(f.test(record(200, 1, "/healthz?verbose", Set.of())));
        assertTrue(f.test(record(200, 1, "/healthzz", Set.of())));
        assertTrue(f.test(record(200, 1, "/api", Set.of())));
        assertFalse(f.test(record(200, 1, "/api", Set.of(), "User-Agent", "Envoy/HC")));
        assertFalse(AccessLogFilter.notHealthCheckPath("/ready").test(record(200, 1, "/ready", Set.of())));
        assertTrue(AccessLogFilter.notHealthCheckPath("/ready").test(record(200, 1, "/healthz", Set.of())));
        AccessLogFilter header = AccessLogFilter.notHealthCheckHeader("X-Health-Check");
        assertFalse(header.test(record(200, 1, "/", Set.of(), "x-health-check", "1")));
        assertTrue(header.test(record(200, 1, "/", Set.of())));
    }

    @Test
    void responseFlag() {
        FlowRecord uf = record(502, 1, "/", EnumSet.of(ResponseFlag.UPSTREAM_CONNECTION_FAILURE));
        FlowRecord none = record(200, 1, "/", Set.of());
        assertTrue(AccessLogFilter.responseFlag().test(uf));
        assertFalse(AccessLogFilter.responseFlag().test(none));
        assertTrue(AccessLogFilter.responseFlag(ResponseFlag.UPSTREAM_OVERFLOW, ResponseFlag.UPSTREAM_CONNECTION_FAILURE)
                .test(uf));
        assertFalse(AccessLogFilter.responseFlag(ResponseFlag.UPSTREAM_OVERFLOW).test(uf));
    }

    @Test
    void header() {
        FlowRecord curl = record(200, 1, "/", Set.of(), "User-Agent", "curl/8.0", "X-Debug", "");
        assertTrue(AccessLogFilter.header("x-debug").test(curl), "present, even empty");
        assertFalse(AccessLogFilter.header("x-other").test(curl));
        assertTrue(AccessLogFilter.header("user-agent", "curl/.*").test(curl));
        assertFalse(AccessLogFilter.header("user-agent", "curl").test(curl), "the whole value must match");
        assertTrue(AccessLogFilter.headerEquals("User-Agent", "curl/8.0").test(curl));
        assertTrue(AccessLogFilter.header(":method", "GET|HEAD").test(curl), "pseudo-headers too");
    }

    @Test
    void runtimeSamplesAPercentage() {
        assertFalse(AccessLogFilter.runtime(0).test(status(200)));
        assertTrue(AccessLogFilter.runtime(100).test(status(200)));
        AccessLogFilter half = AccessLogFilter.runtime(50);
        int passed = 0;
        for (int i = 0; i < 2000; i++) {
            if (half.test(status(200))) passed++;
        }
        assertTrue(passed > 800 && passed < 1200, passed + " of 2000");
        // By X-Request-ID: every log samples the same requests.
        FlowRecord byId = record(200, 1, "/", Set.of(), "X-Request-ID", "abc");
        boolean first = AccessLogFilter.runtime(50).test(byId);
        for (int i = 0; i < 20; i++) assertEquals(first, AccessLogFilter.runtime(50).test(byId));
        assertThrows(IllegalArgumentException.class, () -> AccessLogFilter.runtime(101));
    }

    @Test
    void combinators() {
        AccessLogFilter errorsOrFlags = AccessLogFilter.anyOf(AccessLogFilter.statusCode(Comparison.GE, 500),
                AccessLogFilter.responseFlag());
        AccessLogFilter both = AccessLogFilter.allOf(errorsOrFlags, AccessLogFilter.notHealthCheck());
        assertTrue(both.test(status(500)));
        assertFalse(both.test(record(500, 1, "/healthz", Set.of())));
        assertTrue(both.test(record(200, 1, "/", EnumSet.of(ResponseFlag.DOWNSTREAM_CONNECTION_TERMINATION))));
        assertFalse(both.test(status(200)));
        assertTrue(AccessLogFilter.statusCode(Comparison.EQ, 200).or(AccessLogFilter.statusCode(Comparison.EQ, 201))
                .test(status(201)));
        assertFalse(AccessLogFilter.statusCode(Comparison.EQ, 200).and(AccessLogFilter.duration(Comparison.GT, 100))
                .test(status(200)));
        assertTrue(AccessLogFilter.statusCode(Comparison.EQ, 200).negate().test(status(404)));
        assertTrue(AccessLogFilter.ALL.test(status(0)));
    }

    @Test
    void theCompactSyntax() {
        assertTrue(AccessLogFilter.parse("status>=500").test(status(502)));
        assertFalse(AccessLogFilter.parse("status_code >= 500").test(status(404)));
        assertTrue(AccessLogFilter.parse("status=404").test(status(404)));
        assertTrue(AccessLogFilter.parse("status==404").test(status(404)));
        assertTrue(AccessLogFilter.parse("status!=200").test(status(404)));
        assertTrue(AccessLogFilter.parse("status<300").test(status(200)));
        assertTrue(AccessLogFilter.parse("duration>=1s").test(record(200, 1000, "/", Set.of())));
        assertFalse(AccessLogFilter.parse("duration > 1000ms").test(record(200, 1000, "/", Set.of())));
        assertFalse(AccessLogFilter.parse("not_health_check").test(record(200, 1, "/healthz", Set.of())));
        assertFalse(AccessLogFilter.parse("not_health_check(/ready)").test(record(200, 1, "/ready", Set.of())));
        assertFalse(AccessLogFilter.parse("not_health_check(header=x-hc)").test(record(200, 1, "/", Set.of(), "X-HC", "1")));
        FlowRecord uf = record(502, 1, "/", EnumSet.of(ResponseFlag.UPSTREAM_CONNECTION_FAILURE));
        assertTrue(AccessLogFilter.parse("response_flag").test(uf));
        assertTrue(AccessLogFilter.parse("response_flag(UO, uf)").test(uf));
        assertTrue(AccessLogFilter.parse("response_flag(UpstreamConnectionFailure)").test(uf));
        assertFalse(AccessLogFilter.parse("response_flag(DC)").test(uf));
        FlowRecord curl = record(200, 1, "/", Set.of(), "User-Agent", "curl/8.0");
        assertTrue(AccessLogFilter.parse("header(user-agent)").test(curl));
        assertTrue(AccessLogFilter.parse("header(user-agent~curl/(7|8)\\.0)").test(curl), "parentheses inside a regex");
        assertTrue(AccessLogFilter.parse("header(user-agent=curl/8.0)").test(curl));
        assertTrue(AccessLogFilter.parse("sample(100%)").test(curl));
        assertFalse(AccessLogFilter.parse("runtime(0)").test(curl));

        AccessLogFilter expr = AccessLogFilter.parse("(status>=500 || response_flag) && not_health_check");
        assertTrue(expr.test(uf));
        assertFalse(expr.test(record(502, 1, "/healthz", Set.of())));
        assertFalse(expr.test(status(200)));
        AccessLogFilter words = AccessLogFilter.parse("status >= 500 or response_flag and not not_health_check");
        assertTrue(words.test(status(500)), "and binds tighter than or");
        assertTrue(words.test(record(200, 1, "/healthz", EnumSet.of(ResponseFlag.DOWNSTREAM_CONNECTION_TERMINATION))));
        assertFalse(words.test(record(200, 1, "/x", EnumSet.of(ResponseFlag.DOWNSTREAM_CONNECTION_TERMINATION))));
        assertTrue(AccessLogFilter.parse("!status=200").test(status(404)));
    }

    @Test
    void malformedExpressionsAreExplained() {
        for (String bad : new String[] {"", "status", "status>=", "status>=x", "fancy", "header()", "status>=500 ||",
            "(status>=500", "status>=500)", "response_flag(XX)", "sample(lots)", "runtime(200)"}) {
            assertThrows(IllegalArgumentException.class, () -> AccessLogFilter.parse(bad), bad);
        }
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> AccessLogFilter.parse("fancy"));
        assertTrue(e.getMessage().contains("unknown filter 'fancy'"), e.getMessage());
    }
}
