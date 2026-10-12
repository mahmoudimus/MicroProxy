package org.microproxy.otel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.http.HttpHeaders;

/**
 * Context propagation: {@code traceparent} and {@code tracestate} against the cases of the W3C
 * Trace Context test suite (the valid ones and the invalid ones that must restart the trace), and
 * B3 (single and multiple headers) and Jaeger round trips.
 */
class PropagatorsTest {

    private static final String TRACE = "0af7651916cd43dd8448eb211c80319c";
    private static final String PARENT = "b7ad6b7169203331";

    @Test
    void aVersion00TraceparentIsParsed() {
        SpanContext c = Propagators.parseTraceparent("00-" + TRACE + "-" + PARENT + "-01");
        assertNotNull(c);
        assertEquals(TRACE, c.traceIdHex());
        assertEquals(PARENT, c.spanIdHex());
        assertTrue(c.isSampled());
        assertTrue(c.remote());
        assertFalse(Propagators.parseTraceparent("00-" + TRACE + "-" + PARENT + "-00").isSampled());
        // Unknown flags are kept; only the sampled bit means anything.
        assertTrue(Propagators.parseTraceparent("00-" + TRACE + "-" + PARENT + "-09").isSampled());
        // Optional whitespace around the value (OWS) is not part of it.
        assertEquals(TRACE, Propagators.parseTraceparent(" \t00-" + TRACE + "-" + PARENT + "-01\t ").traceIdHex());
    }

    @Test
    void aLaterVersionIsReadAsVersion00WhenItContinuesAfterADash() {
        SpanContext c = Propagators.parseTraceparent("cc-" + TRACE + "-" + PARENT + "-01-what-the-future-will-be-like");
        assertNotNull(c);
        assertEquals(PARENT, c.spanIdHex());
        assertNotNull(Propagators.parseTraceparent("cc-" + TRACE + "-" + PARENT + "-01"));
        assertNull(Propagators.parseTraceparent("cc-" + TRACE + "-" + PARENT + "-01.what-the-future-will-be-like"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "00",
        // version ff is forbidden; version 00 has exactly four fields
        "ff-" + TRACE + "-" + PARENT + "-01",
        "00-" + TRACE + "-" + PARENT + "-01-what-the-future-will-be-like",
        // version: illegal characters, too long, too short, upper case
        ".0-" + TRACE + "-" + PARENT + "-01",
        "0.-" + TRACE + "-" + PARENT + "-01",
        "000-" + TRACE + "-" + PARENT + "-01",
        "0-" + TRACE + "-" + PARENT + "-01",
        "0A-" + TRACE + "-" + PARENT + "-01",
        // trace id: all zero, illegal characters, upper case, too long, too short
        "00-00000000000000000000000000000000-" + PARENT + "-01",
        "00-.af7651916cd43dd8448eb211c80319c-" + PARENT + "-01",
        "00-0af7651916cd43dd8448eb211c80319.-" + PARENT + "-01",
        "00-0AF7651916CD43DD8448EB211C80319C-" + PARENT + "-01",
        "00-0af7651916cd43dd8448eb211c80319c0-" + PARENT + "-01",
        "00-0af7651916cd43dd8448eb211c80319-" + PARENT + "-01",
        // parent id: all zero, illegal characters, upper case, too long, too short
        "00-" + TRACE + "-0000000000000000-01",
        "00-" + TRACE + "-.7ad6b7169203331-01",
        "00-" + TRACE + "-b7ad6b716920333.-01",
        "00-" + TRACE + "-B7AD6B7169203331-01",
        "00-" + TRACE + "-b7ad6b71692033310-01",
        "00-" + TRACE + "-b7ad6b716920333-01",
        // flags: illegal characters, too long, too short
        "00-" + TRACE + "-" + PARENT + "-.0",
        "00-" + TRACE + "-" + PARENT + "-0.",
        "00-" + TRACE + "-" + PARENT + "-001",
        "00-" + TRACE + "-" + PARENT + "-1",
        // separators
        "00_" + TRACE + "-" + PARENT + "-01",
        "00-" + TRACE + "_" + PARENT + "-01",
        "00-" + TRACE + "-" + PARENT + "_01",
    })
    void anInvalidTraceparentRestartsTheTrace(String value) {
        assertNull(Propagators.parseTraceparent(value), value);
    }

    @Test
    void twoTraceparentHeadersRestartTheTrace() {
        HttpHeaders h = new HttpHeaders();
        h.add("traceparent", "00-" + TRACE + "-" + PARENT + "-01");
        h.add("traceparent", "00-" + TRACE + "-" + PARENT + "-01");
        assertNull(Propagators.TRACE_CONTEXT.extract(h));
    }

    @Test
    void tracestateIsNormalizedAndJoinedAcrossHeaders() {
        assertEquals("foo=1,bar=2", Propagators.parseTracestate(List.of("foo=1,bar=2")));
        assertEquals("foo=1,bar=2", Propagators.parseTracestate(List.of("foo=1 \t , \t bar=2")));
        assertEquals("foo=1,bar=2", Propagators.parseTracestate(List.of("foo=1", "bar=2")));
        assertEquals("foo=1", Propagators.parseTracestate(List.of("foo=1", "")));
        assertEquals("foo=1,bar=2", Propagators.parseTracestate(List.of("foo=1,,bar=2")));
        assertEquals("", Propagators.parseTracestate(List.of()));
        assertEquals("foo=b a r", Propagators.parseTracestate(List.of("foo=b a r")));
        assertEquals("tenant@system=1,0tenant@s=2", Propagators.parseTracestate(List.of("tenant@system=1,0tenant@s=2")));
        assertEquals("foo=!\"#$%&'()*+-./0:;<>?@[\\]^_`{|}~",
                Propagators.parseTracestate(List.of("foo=!\"#$%&'()*+-./0:;<>?@[\\]^_`{|}~")));
    }

    @Test
    void anInvalidTracestateIsDropped() {
        for (String bad : List.of("foo=1,foo=2", "foo=1,foo=1", "FOO=1", "foo.bar=1", "foo =1", "=1", "foo",
                "foo=bar=baz", "foo=", "foo=,bar=3", "1foo=1", "t@s@x=1", "@s=1", "t@=1", "t@1s=1", "foo=é")) {
            assertNull(Propagators.parseTracestate(List.of(bad)), bad);
        }
    }

    @Test
    void tracestateLimitsAreTheSpecifications() {
        List<String> members = new ArrayList<>();
        for (int i = 0; i < 32; i++) members.add("k" + i + "=" + i);
        assertNotNull(Propagators.parseTracestate(List.of(String.join(",", members))));
        members.add("k32=32");
        assertNull(Propagators.parseTracestate(List.of(String.join(",", members))));
        String key256 = "k" + "a".repeat(255);
        assertNotNull(Propagators.parseTracestate(List.of(key256 + "=1")));
        assertNull(Propagators.parseTracestate(List.of(key256 + "a=1")));
        assertNotNull(Propagators.parseTracestate(List.of("t".repeat(241) + "@s=1")));
        assertNull(Propagators.parseTracestate(List.of("t".repeat(242) + "@s=1")));
        assertNotNull(Propagators.parseTracestate(List.of("t@" + "s".repeat(14) + "=1")));
        assertNull(Propagators.parseTracestate(List.of("t@" + "s".repeat(15) + "=1")));
        assertNotNull(Propagators.parseTracestate(List.of("foo=" + "v".repeat(256))));
        assertNull(Propagators.parseTracestate(List.of("foo=" + "v".repeat(257))));
    }

    @Test
    void anInvalidTracestateLeavesTheTraceparent() {
        HttpHeaders h = new HttpHeaders();
        h.set("traceparent", "00-" + TRACE + "-" + PARENT + "-01");
        h.set("tracestate", "foo=1,foo=2");
        SpanContext c = Propagators.TRACE_CONTEXT.extract(h);
        assertEquals(TRACE, c.traceIdHex());
        assertEquals("", c.traceState());
        h.set("tracestate", "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7");
        assertEquals("congo=t61rcWkgMzE,rojo=00f067aa0ba902b7", Propagators.TRACE_CONTEXT.extract(h).traceState());
    }

    @Test
    void traceContextRoundTrips() {
        SpanContext c = new SpanContext(0x0af7651916cd43ddL, 0x8448eb211c80319cL, 0x00f067aa0ba902b7L, 1, "rojo=1", false);
        HttpHeaders h = new HttpHeaders();
        Propagators.TRACE_CONTEXT.inject(c, h);
        assertEquals("00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01", h.get("traceparent"));
        assertEquals("rojo=1", h.get("tracestate"));
        SpanContext back = Propagators.TRACE_CONTEXT.extract(h);
        assertEquals(c.withSpan(c.spanId(), true), back.withSpan(back.spanId(), true));
        // No tracestate: the header goes.
        Propagators.TRACE_CONTEXT.inject(new SpanContext(1, 2, 3, 0, "", false), h);
        assertEquals("00-00000000000000010000000000000002-0000000000000003-00", h.get("traceparent"));
        assertNull(h.get("tracestate"));
    }

    @Test
    void b3SingleHeader() {
        HttpHeaders h = new HttpHeaders();
        h.set("b3", "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1-05e3ac9a4f6e3b90");
        SpanContext c = Propagators.B3.extract(h);
        assertEquals("80f198ee56343ba864fe8b2a57d3eff7", c.traceIdHex());
        assertEquals("e457b5a2e4d86bd1", c.spanIdHex());
        assertTrue(c.isSampled());
        // A 64-bit trace id is padded; "d" (debug) is sampled; no sampling state is not.
        h.set("b3", "64fe8b2a57d3eff7-e457b5a2e4d86bd1-d");
        c = Propagators.B3.extract(h);
        assertEquals("000000000000000064fe8b2a57d3eff7", c.traceIdHex());
        assertTrue(c.isSampled());
        h.set("b3", "64fe8b2a57d3eff7-e457b5a2e4d86bd1");
        assertFalse(Propagators.B3.extract(h).isSampled());
        for (String bad : List.of("0", "1", "d", "64fe8b2a57d3eff7", "64fe8b2a57d3eff7-e457b5a2e4d86bd1-x",
                "64FE8B2A57D3EFF7-e457b5a2e4d86bd1-1", "64fe8b2a57d3eff-e457b5a2e4d86bd1-1",
                "0000000000000000-e457b5a2e4d86bd1-1", "64fe8b2a57d3eff7-0000000000000000-1",
                "64fe8b2a57d3eff7-e457b5a2e4d86bd1-1-05e3ac9a", "a-b-c-d-e")) {
            h.set("b3", bad);
            assertNull(Propagators.B3.extract(h), bad);
        }
    }

    @Test
    void b3RoundTripsInBothForms() {
        SpanContext c = new SpanContext(0x80f198ee56343ba8L, 0x64fe8b2a57d3eff7L, 0xe457b5a2e4d86bd1L, 1, "", false);
        for (Propagator p : List.of(Propagators.B3, Propagators.B3_MULTI)) {
            for (boolean sampled : List.of(true, false)) {
                HttpHeaders h = new HttpHeaders();
                h.set("X-B3-ParentSpanId", "05e3ac9a4f6e3b90");
                SpanContext sent = c.withSpan(c.spanId(), sampled);
                p.inject(sent, h);
                SpanContext back = p.extract(h);
                assertEquals(sent.traceIdHex(), back.traceIdHex(), p.name());
                assertEquals(sent.spanIdHex(), back.spanIdHex(), p.name());
                assertEquals(sampled, back.isSampled(), p.name());
            }
        }
        HttpHeaders h = new HttpHeaders();
        Propagators.B3.inject(c, h);
        assertEquals("80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1", h.get("b3"));
        h = new HttpHeaders();
        h.set("X-B3-ParentSpanId", "05e3ac9a4f6e3b90");
        Propagators.B3_MULTI.inject(c, h);
        assertEquals("80f198ee56343ba864fe8b2a57d3eff7", h.get("x-b3-traceid"));
        assertEquals("e457b5a2e4d86bd1", h.get("x-b3-spanid"));
        assertEquals("1", h.get("x-b3-sampled"));
        assertNull(h.get("x-b3-parentspanid"));
    }

    @Test
    void b3MultipleHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.set("X-B3-TraceId", "64fe8b2a57d3eff7");
        h.set("X-B3-SpanId", "e457b5a2e4d86bd1");
        h.set("X-B3-Sampled", "true");
        assertTrue(Propagators.B3_MULTI.extract(h).isSampled());
        h.set("X-B3-Sampled", "0");
        assertFalse(Propagators.B3_MULTI.extract(h).isSampled());
        h.set("X-B3-Flags", "1");
        assertTrue(Propagators.B3_MULTI.extract(h).isSampled(), "debug is sampled");
        h.remove("X-B3-Flags");
        h.set("X-B3-Sampled", "maybe");
        assertNull(Propagators.B3_MULTI.extract(h));
        h.remove("X-B3-Sampled");
        h.remove("X-B3-SpanId");
        assertNull(Propagators.B3_MULTI.extract(h));
    }

    @Test
    void jaeger() {
        HttpHeaders h = new HttpHeaders();
        h.set("uber-trace-id", TRACE + ":" + PARENT + ":0:1");
        SpanContext c = Propagators.JAEGER.extract(h);
        assertEquals(TRACE, c.traceIdHex());
        assertEquals(PARENT, c.spanIdHex());
        assertTrue(c.isSampled());
        // URL-encoded separators, short ids padded with zeros, debug (2) sampled, 0 not.
        h.set("uber-trace-id", "6d1f%3A1a%3A0%3A3");
        c = Propagators.JAEGER.extract(h);
        assertEquals("00000000000000000000000000006d1f", c.traceIdHex());
        assertEquals("000000000000001a", c.spanIdHex());
        assertTrue(c.isSampled());
        h.set("uber-trace-id", "6d1f:1a:0:0");
        assertFalse(Propagators.JAEGER.extract(h).isSampled());
        for (String bad : List.of("6d1f:1a:0", "6d1f:1a:0:1:2", "0:1a:0:1", "6d1f:0:0:1", ":1a:0:1", "6d1f:1a:0:",
                "6d1f:1a:0:zz", "6D1F:1a:0:1", "1" + TRACE + ":1a:0:1", "6d1f:1" + PARENT + ":0:1")) {
            h.set("uber-trace-id", bad);
            assertNull(Propagators.JAEGER.extract(h), bad);
        }
    }

    @Test
    void jaegerRoundTrips() {
        SpanContext c = new SpanContext(0x0af7651916cd43ddL, 0x8448eb211c80319cL, 0x00f067aa0ba902b7L, 1, "", false);
        for (boolean sampled : List.of(true, false)) {
            HttpHeaders h = new HttpHeaders();
            SpanContext sent = c.withSpan(c.spanId(), sampled);
            Propagators.JAEGER.inject(sent, h);
            assertEquals(TRACE + ":00f067aa0ba902b7:0:" + (sampled ? "1" : "0"), h.get("uber-trace-id"));
            SpanContext back = Propagators.JAEGER.extract(h);
            assertEquals(sent.traceIdHex(), back.traceIdHex());
            assertEquals(sent.spanIdHex(), back.spanIdHex());
            assertEquals(sampled, back.isSampled());
        }
    }

    @Test
    void propagatorsAreNamedAsOtelPropagatorsNamesThem() {
        assertEquals(List.of(Propagators.TRACE_CONTEXT), Propagators.parse("tracecontext,baggage"));
        assertEquals(List.of(Propagators.B3, Propagators.B3_MULTI, Propagators.JAEGER, Propagators.TRACE_CONTEXT),
                Propagators.parse(" b3 , b3multi,jaeger,tracecontext,b3"));
        assertEquals(List.of(), Propagators.parse("none"));
        assertThrows(IllegalArgumentException.class, () -> Propagators.parse("xray"));
    }
}
