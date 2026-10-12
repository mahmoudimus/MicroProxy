package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.otel.OtelLauncherExtension;

/**
 * The launcher with the OpenTelemetry module on the class path: {@code --otel} and its options,
 * the environment turning it on, and {@code OTEL_SDK_DISABLED} keeping it off.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class OtelLauncherTest {

    private final ByteArrayOutputStream console = new ByteArrayOutputStream();

    private PrintStream out() {
        return new PrintStream(console, true, StandardCharsets.UTF_8);
    }

    @Test
    void theOptionsAreListedInTheHelp() throws Exception {
        assertEquals(null, Launcher.start(new String[] {"--help"}, out()));
        String help = console.toString(StandardCharsets.UTF_8);
        assertTrue(help.contains("--otel-endpoint <url>"), help);
        assertTrue(help.contains("--otel-sampler"), help);
    }

    @Test
    void otelExportsTheLaunchedProxysSpansMetricsAndLogs() throws Exception {
        List<String> paths = new CopyOnWriteArrayList<>();
        HttpServer collector = HttpServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 0);
        collector.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        collector.createContext("/", exchange -> {
            paths.add(exchange.getRequestURI().getPath() + " " + exchange.getRequestHeaders().getFirst("Content-Type")
                    + " " + exchange.getRequestHeaders().getFirst("X-Token"));
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        collector.start();
        HttpServer origin = TestSupport.origin(TestSupport.echo());
        HttpProxyServer proxy = null;
        try {
            proxy = Launcher.start(new String[] {"--port", "0", "--otel",
                "--otel-endpoint", "http://127.0.0.1:" + collector.getAddress().getPort(),
                "--otel-protocol", "http/json", "--otel-header", "x-token=abc%20def",
                "--otel-service-name", "edge", "--otel-sampler", "traceidratio:1",
                "--otel-propagators", "tracecontext,b3", "--otel-metric-interval", "100",
                "--otel-request-id", "replace"}, out());
            String output = console.toString(StandardCharsets.UTF_8);
            assertTrue(output.contains("OpenTelemetry: traces to http://127.0.0.1:"), output);
            assertTrue(output.contains("(http/json); service edge; sampler TraceIdRatioBased{1.0}; propagators tracecontext,b3"),
                    output);
            assertTrue(proxy.getStats().enabled(), "metrics export turns the stats on");
            String body = TestSupport.send(TestSupport.client(proxy), java.net.http.HttpRequest.newBuilder(
                    java.net.URI.create(TestSupport.url(origin, "/launched"))).header("X-Request-Id", "mine").build()).body();
            assertTrue(TestSupport.echoedHeader(body, "traceparent").getFirst().endsWith("-01"));
            assertEquals(1, TestSupport.echoedHeader(body, "b3").size());
            String requestId = TestSupport.echoedHeader(body, "x-request-id").getFirst();
            assertTrue(!requestId.equals("mine") && requestId.length() == 36, requestId);
            // Stopping exports what is queued, without waiting for the batches' 5 s delay.
            proxy.stop();
            proxy = null;
            TestSupport.eventually("traces, metrics and logs at the collector " + paths,
                    () -> paths.contains("/v1/traces application/json abc def")
                            && paths.contains("/v1/metrics application/json abc def")
                            && paths.contains("/v1/logs application/json abc def"));
        } finally {
            if (proxy != null) proxy.stop();
            origin.stop(0);
            collector.stop(0);
        }
    }

    @Test
    void theEnvironmentTurnsItOnAndOff() throws Exception {
        HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap();
        new OtelLauncherExtension(Map.of()).configure(bootstrap, out());
        assertSame(FlowTracer.NOOP, bootstrap.getTracer(), "off without --otel or an endpoint");

        OtelLauncherExtension fromEnv = new OtelLauncherExtension(Map.of("OTEL_EXPORTER_OTLP_ENDPOINT",
                "http://127.0.0.1:1", "OTEL_SERVICE_NAME", "from-env", "OTEL_METRICS_EXPORTER", "none"));
        bootstrap = MicroProxy.bootstrap();
        fromEnv.configure(bootstrap, out());
        assertTrue(bootstrap.getTracer() instanceof org.microproxy.otel.Telemetry, bootstrap.getTracer().toString());
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("service from-env"));
        ((AutoCloseable) bootstrap.getTracer()).close();

        OtelLauncherExtension disabled = new OtelLauncherExtension(Map.of("OTEL_SDK_DISABLED", "true",
                "OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1"));
        assertTrue(disabled.parseOption("--otel", new ArrayDeque<>()));
        bootstrap = MicroProxy.bootstrap();
        disabled.configure(bootstrap, out());
        assertSame(FlowTracer.NOOP, bootstrap.getTracer());
        assertTrue(console.toString(StandardCharsets.UTF_8).contains("OpenTelemetry: off"));

        OtelLauncherExtension optionsAlone = new OtelLauncherExtension(Map.of());
        assertTrue(optionsAlone.parseOption("--otel-service-name", new ArrayDeque<>(List.of("x"))));
        assertThrows(IllegalArgumentException.class, () -> optionsAlone.configure(MicroProxy.bootstrap(), out()));
        assertThrows(IllegalArgumentException.class,
                () -> optionsAlone.parseOption("--otel-protocol", new ArrayDeque<>(List.of("grpc"))));
    }
}
