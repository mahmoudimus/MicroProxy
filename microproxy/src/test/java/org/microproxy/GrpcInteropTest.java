package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.Http2Frame;

/**
 * gRPC through the intercepting proxy between real gRPC peers, grpcio's client and server (see
 * {@link GrpcPeers}), where {@link GrpcThroughProxyTest} has only the wire format. The proxy is
 * what {@code --mitm --http2 --http2-upstream} makes it: the client's {@code CONNECT} is
 * intercepted with the proxy's CA, which the client trusts, and the calls go on over HTTP/2 on
 * both sides, to a server whose CA the proxy trusts. Each test runs every call of the client:
 * unary, server, client and bidirectional streaming, an error with {@code grpc-status-details-bin},
 * a deadline and a cancellation reaching the server, and messages of several megabytes across the
 * flow-control windows; once as they are, once through a frame interceptor that passes every frame
 * on unchanged.
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class GrpcInteropTest {

    /** RST_STREAM's CANCEL (RFC 9113 section 7), which gRPC sends to cancel a call. */
    private static final long CANCEL = 0x8;

    @TempDir
    Path dir;

    private GrpcPeers.Server server;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        server = new GrpcPeers.Server(dir, Http2UpstreamTest.originCa);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (proxy != null) proxy.abort();
        if (server != null) server.close();
    }

    private Map<String, Map<String, Object>> call() throws Exception {
        return GrpcPeers.call(dir, proxy.getListenAddress(), "localhost:" + server.port,
                GrpcPeers.trust(dir, Http2UpstreamTest.proxyCa));
    }

    @Test
    void grpcioCallsThroughTheProxy() throws Exception {
        proxy = Http2UpstreamTest.mitm().withHttp2(true).start();
        GrpcPeers.checkCalls(call(), server, "2 h2up");
    }

    @Test
    void grpcioCallsThroughAFrameInterceptorThatPassesFramesOn() throws Exception {
        Map<FrameDirection, LongAdder> dataBytes = new ConcurrentHashMap<>();
        List<String> seen = new CopyOnWriteArrayList<>();
        FrameInterceptor passOn = (frame, direction, ctx) -> {
            switch (frame) {
                case Http2Frame.Data d -> dataBytes.computeIfAbsent(direction, k -> new LongAdder()).add(d.data().length);
                case Http2Frame.RstStream r -> seen.add(direction + " RST_STREAM " + r.errorCode());
                case Http2Frame.Headers h when h.get("grpc-timeout") != null ->
                        seen.add(direction + " grpc-timeout " + h.get(":path") + " " + h.get("grpc-timeout"));
                case Http2Frame.Headers h when h.get("grpc-status") != null ->
                        seen.add(direction + " grpc-status " + h.get("grpc-status"));
                default -> {}
            }
            return frame;
        };
        proxy = Http2UpstreamTest.mitm().withHttp2(true).withFrameInterceptor(passOn).start();
        GrpcPeers.checkCalls(call(), server, "2 h2up");

        // Both hops of every call went through it: the large messages, the deadline, the
        // trailers, and the cancellations (the deadline's and the client's), as RST_STREAM CANCEL.
        String timeout = seen.stream().filter(s -> s.startsWith("FROM_CLIENT grpc-timeout /interop.Interop/Wait "))
                .findFirst().orElseThrow(() -> new AssertionError(seen.toString()))
                .substring("FROM_CLIENT ".length());
        assertTrue(seen.contains("TO_SERVER " + timeout), seen.toString());
        for (FrameDirection d : List.of(FrameDirection.FROM_CLIENT, FrameDirection.TO_SERVER)) {
            assertTrue(dataBytes.get(d).sum() > 15L << 20, d + " " + dataBytes.get(d));
            assertTrue(seen.contains(d + " RST_STREAM " + CANCEL), seen.toString());
        }
        for (FrameDirection d : List.of(FrameDirection.FROM_SERVER, FrameDirection.TO_CLIENT)) {
            assertTrue(dataBytes.get(d).sum() > 16L << 20, d + " " + dataBytes.get(d));
            assertTrue(seen.contains(d + " grpc-status 0"), seen.toString());
            assertTrue(seen.contains(d + " grpc-status 3"), seen.toString());
        }
    }
}
