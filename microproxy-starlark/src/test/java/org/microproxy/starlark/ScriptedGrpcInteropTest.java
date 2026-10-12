package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.GrpcPeers;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The calls of the core's {@code GrpcInteropTest}, grpcio's client and server on either side of
 * the intercepting proxy with HTTP/2 both ways, through a script's {@code on_frame} that passes
 * every frame on unchanged and only notes the {@code grpc-status} of each call.
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class ScriptedGrpcInteropTest {

    static final String PASS_ON = """
            def on_frame(frame, ctx):
                if frame.type == "HEADERS" and frame.direction == "from_server" and "grpc-status" in frame.headers:
                    log.info("grpc-status %s" % frame.headers["grpc-status"])
                return None
            """;

    private static final CertificateAuthority originCa = CertificateAuthority.generate("Scripted gRPC Origin CA");
    private static final CertificateAuthority proxyCa = CertificateAuthority.generate("Scripted gRPC Proxy CA");

    @TempDir
    Path dir;

    private GrpcPeers.Server server;
    private HttpProxyServer proxy;
    private final List<String> logs = new CopyOnWriteArrayList<>();
    private final Logger scriptLog = Logger.getLogger("microproxy.script");
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord r) {
            logs.add(MessageFormat.format(r.getMessage(), r.getParameters()));
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    };

    private Level scriptLevel;

    @BeforeEach
    void setUp() throws Exception {
        scriptLevel = scriptLog.getLevel();
        scriptLog.setLevel(Level.INFO);
        scriptLog.addHandler(capture);
        server = new GrpcPeers.Server(dir, originCa);
    }

    @AfterEach
    void tearDown() throws Exception {
        scriptLog.setLevel(scriptLevel);
        scriptLog.removeHandler(capture);
        if (proxy != null) proxy.abort();
        if (server != null) server.close();
    }

    @Test
    void grpcioCallsThroughAnOnFrameScriptThatPassesFramesOn() throws Exception {
        ScriptedProxy script = ScriptedProxy.builder(PASS_ON, "grpc.star").build();
        proxy = MicroProxy.bootstrap().withPort(0).withProxyAlias("scripted")
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp2(true)
                .withHttp2Upstream(true)
                .withFrameInterceptor(script.frameInterceptor())
                .start();
        GrpcPeers.checkCalls(GrpcPeers.call(dir, proxy.getListenAddress(), "localhost:" + server.port,
                GrpcPeers.trust(dir, proxyCa)), server, "2 scripted");
        // The script saw the trailers of the calls that succeeded and of the one that failed.
        assertTrue(logs.stream().anyMatch(l -> l.endsWith("grpc-status 0")), logs.toString());
        assertTrue(logs.stream().anyMatch(l -> l.endsWith("grpc-status 3")), logs.toString());
    }
}
