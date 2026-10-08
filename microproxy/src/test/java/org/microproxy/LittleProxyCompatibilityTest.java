package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;
import static org.microproxy.TestSupport.write;

import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** {@code withLittleProxyCompatibility()} restores LittleProxy's behaviour where MicroProxy differs. */
class LittleProxyCompatibilityTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = origin(echo());
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    private RecordingFilters start(boolean compatible) {
        RecordingFilters filters = new RecordingFilters();
        proxy = MicroProxy.bootstrap().withPort(0).withLittleProxyCompatibility(compatible)
                .withFiltersSource(RecordingFilters.sourceOf(filters)).start();
        return filters;
    }

    /** The recorded hooks up to the request being sent, in order. */
    private static List<String> untilSending(RecordingFilters filters) {
        List<String> events = filters.events;
        return events.subList(0, events.indexOf("proxyToServerRequestSending"));
    }

    @Test
    void byDefaultFiltersSeeTheRequestBeforeAnyLookup() {
        RecordingFilters filters = start(false);
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
        assertEquals(List.of("clientToProxyRequest:head", "proxyToServerRequest:head",
                "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded",
                "proxyToServerConnectionStarted", "proxyToServerConnectionSucceeded"), untilSending(filters));
    }

    @Test
    void compatibleOrderResolvesFirst() {
        RecordingFilters filters = start(true);
        assertEquals(200, get(client(proxy), url(origin, "/")).statusCode());
        assertEquals(List.of("clientToProxyRequest:head",
                "proxyToServerResolutionStarted", "proxyToServerResolutionSucceeded", "proxyToServerRequest:head",
                "proxyToServerConnectionStarted", "proxyToServerConnectionSucceeded"), untilSending(filters));
    }

    @Test
    void compatibleModeAnswersUnresolvableNamesBeforeProxyToServerRequest() {
        RecordingFilters filters = start(true);
        assertEquals(502, get(client(proxy), "http://no-such-host.invalid/").statusCode());
        assertTrue(filters.saw("proxyToServerResolutionFailed"), filters.events.toString());
        assertFalse(filters.saw("proxyToServerRequest:head"), filters.events.toString());

        RecordingFilters defaults = start(false);
        assertEquals(502, get(client(proxy), "http://no-such-host.invalid/").statusCode());
        assertTrue(defaults.saw("proxyToServerRequest:head"), defaults.events.toString());
    }

    @Test
    void keepAliveRequestsDoNotResolveAgain() {
        RecordingFilters filters = start(true);
        var client = client(proxy);
        get(client, url(origin, "/a"));
        get(client, url(origin, "/b"));
        assertEquals(1, filters.events.stream().filter("proxyToServerResolutionStarted"::equals).count(),
                filters.events.toString());
        assertEquals(2, filters.events.stream().filter("proxyToServerRequest:head"::equals).count());
    }

    /** The PROXY header the origin received, from a server that echoes it back as the body. */
    private String proxyHeaderSentTo(boolean compatible) throws Exception {
        try (TestSupport.RawServer raw = TestSupport.rawServer(socket -> {
                    InputStream in = socket.getInputStream();
                    String header = TestSupport.readUntil(in, "\r\n").strip();
                    TestSupport.readUntil(in, "\r\n\r\n");
                    write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                            + header.length() + "\r\n\r\n" + header);
                })) {
            proxy = MicroProxy.bootstrap().withPort(0).withSendProxyProtocol(true)
                    .withLittleProxyCompatibility(compatible).start();
            String header = get(client(proxy), "http://127.0.0.1:" + raw.port() + "/").body();
            proxy.abort();
            return header + "|" + raw.port() + "|" + proxy.getListenAddress().getPort();
        }
    }

    @Test
    void proxyHeaderDestination() throws Exception {
        // PROXY TCP4 <src> <dst> <srcport> <dstport>
        String[] byDefault = proxyHeaderSentTo(false).split("\\|");
        assertEquals(byDefault[2], byDefault[0].split(" ")[5], "default: the address the client connected to");
        String[] compatible = proxyHeaderSentTo(true).split("\\|");
        assertEquals(compatible[1], compatible[0].split(" ")[5], "LittleProxy: the server connection's remote end");
    }
}
