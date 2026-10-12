/**
 * OpenTelemetry for MicroProxy, with no dependencies but the JDK: W3C Trace Context, B3 and Jaeger
 * propagation ({@link org.microproxy.otel.Propagators}), sampling ({@link
 * org.microproxy.otel.Sampler}), a SERVER span per exchange and a CLIENT span per attempt to reach
 * the server, INTERNAL spans for tunnels and flows, and OTLP/HTTP export of traces, metrics (the
 * proxy's {@link org.microproxy.stats.StatsRegistry}) and access logs, as protobuf or JSON ({@link
 * org.microproxy.otel.Telemetry}). It plugs into the core as its {@link org.microproxy.FlowTracer},
 * and into the launcher as {@code --otel} ({@link org.microproxy.otel.OtelLauncherExtension}).
 */
package org.microproxy.otel;
