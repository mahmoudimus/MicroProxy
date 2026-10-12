package org.microproxy.otel;

import java.io.PrintStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import org.microproxy.HttpProxyServerBootstrap;
import org.microproxy.LauncherExtension;
import org.microproxy.extras.LogFormat;

/**
 * Adds {@code --otel} and its options to the command line when this module is on the class path.
 * OpenTelemetry's {@code OTEL_*} environment variables configure it first, and the options
 * override them; setting {@code OTEL_EXPORTER_OTLP_ENDPOINT} (or a signal's endpoint) turns it on
 * without {@code --otel}, and {@code OTEL_SDK_DISABLED=true} keeps it off.
 */
public final class OtelLauncherExtension implements LauncherExtension {

    private final Map<String, String> env;
    private boolean on;
    /** The options, applied in order to the builder from the environment. */
    private final List<Consumer<Telemetry.Builder>> options = new ArrayList<>();

    /** Creates the extension, reading the process's environment. */
    public OtelLauncherExtension() {
        this(System.getenv());
    }

    /**
     * Creates the extension with another environment, for tests.
     *
     * @param env the environment variables
     */
    public OtelLauncherExtension(Map<String, String> env) {
        this.env = Map.copyOf(env);
    }

    @Override
    public String usage() {
        return """
                  --otel                       trace with OpenTelemetry and export traces, metrics and access
                                               logs over OTLP/HTTP; OTEL_* variables configure it, and
                                               OTEL_EXPORTER_OTLP_ENDPOINT alone turns it on (see README)
                  --otel-endpoint <url>        the collector's OTLP/HTTP base URL (http://localhost:4318)
                  --otel-protocol <p>          http/protobuf (default) or http/json
                  --otel-header <name=value>   a header on every export, e.g. for authentication (repeatable)
                  --otel-compression <c>       gzip or none
                  --otel-service-name <name>   service.name (microproxy)
                  --otel-resource <k=v,...>    more resource attributes
                  --otel-signals <list>        what to export: traces,metrics,logs (default all of them)
                  --otel-sampler <name[:arg]>  parentbased_always_on (default), always_on, always_off,
                                               traceidratio:<r>, parentbased_traceidratio:<r>, ...
                  --otel-propagators <list>    tracecontext (default), b3, b3multi, jaeger, baggage, none
                  --otel-force-trace-header <h> sample every request that has this header
                  --otel-request-id <mode>     keep (default: add X-Request-Id when missing), replace, off
                  --otel-when-stripped <mode>  with --strip-tracing-headers, send the proxy's own context
                                               (own, the default) or none
                  --otel-ignore-incoming       start a new trace per request, ignoring the clients' context
                  --otel-metric-interval <ms>  how often metrics are exported (60000)
                  --otel-log-format <format>   the body of exported access-log records: a preset or an
                                               Envoy format string (Envoy's default)
                """;
    }

    @Override
    public boolean parseOption(String option, Deque<String> args) {
        switch (option) {
            case "--otel" -> on = true;
            case "--otel-endpoint" -> {
                String v = value(option, args);
                option(b -> b.endpoint(v));
            }
            case "--otel-protocol" -> {
                Telemetry.Protocol p = Telemetry.Protocol.of(value(option, args));
                option(b -> b.protocol(p));
            }
            case "--otel-header" -> {
                Map<String, String> h = Telemetry.parseList(value(option, args), option);
                option(b -> h.forEach(b::header));
            }
            case "--otel-compression" -> {
                boolean gzip = Telemetry.compression(value(option, args));
                option(b -> b.compression(gzip));
            }
            case "--otel-service-name" -> {
                String v = value(option, args);
                option(b -> b.serviceName(v));
            }
            case "--otel-resource" -> {
                Map<String, String> r = Telemetry.parseList(value(option, args), option);
                option(b -> r.forEach(b::resourceAttribute));
            }
            case "--otel-signals" -> {
                List<String> signals = new ArrayList<>();
                for (String s : value(option, args).split(",")) {
                    String n = s.strip().toLowerCase(Locale.ROOT);
                    if (!List.of("traces", "metrics", "logs").contains(n)) {
                        throw new IllegalArgumentException(option + ": traces, metrics or logs, not " + s.strip());
                    }
                    signals.add(n);
                }
                option(b -> b.traces(signals.contains("traces")).metrics(signals.contains("metrics"))
                        .logs(signals.contains("logs")));
            }
            case "--otel-sampler" -> {
                String v = value(option, args);
                int colon = v.indexOf(':');
                Sampler s = Sampler.of(colon < 0 ? v : v.substring(0, colon), colon < 0 ? null : v.substring(colon + 1));
                option(b -> b.sampler(s));
            }
            case "--otel-propagators" -> {
                List<Propagator> p = Propagators.parse(value(option, args));
                option(b -> b.propagators(p));
            }
            case "--otel-force-trace-header" -> {
                String v = value(option, args);
                option(b -> b.forceTraceHeader(v));
            }
            case "--otel-request-id" -> {
                Telemetry.RequestIdMode mode = switch (value(option, args).strip().toLowerCase(Locale.ROOT)) {
                    case "keep" -> Telemetry.RequestIdMode.KEEP;
                    case "replace" -> Telemetry.RequestIdMode.REPLACE;
                    case "off" -> Telemetry.RequestIdMode.OFF;
                    default -> throw new IllegalArgumentException(option + ": keep, replace or off");
                };
                option(b -> b.requestId(mode));
            }
            case "--otel-when-stripped" -> {
                Telemetry.WhenStripped mode = switch (value(option, args).strip().toLowerCase(Locale.ROOT)) {
                    case "own" -> Telemetry.WhenStripped.OWN;
                    case "none" -> Telemetry.WhenStripped.NONE;
                    default -> throw new IllegalArgumentException(option + ": own or none");
                };
                option(b -> b.whenStripped(mode));
            }
            case "--otel-ignore-incoming" -> option(b -> b.trustIncoming(false));
            case "--otel-metric-interval" -> {
                String v = value(option, args);
                Duration interval;
                try {
                    interval = Duration.ofMillis(Long.parseLong(v));
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException(option + " needs milliseconds, not " + v);
                }
                option(b -> b.metricInterval(interval));
            }
            case "--otel-log-format" -> {
                String v = value(option, args);
                option(b -> b.logFormat(LogFormat.parse(v)));
            }
            default -> {
                return false;
            }
        }
        return true;
    }

    private void option(Consumer<Telemetry.Builder> option) {
        options.add(option);
    }

    private static String value(String option, Deque<String> args) {
        String value = args.poll();
        if (value == null) throw new IllegalArgumentException(option + " needs a value");
        return value;
    }

    @Override
    public void configure(HttpProxyServerBootstrap bootstrap, PrintStream console) {
        boolean fromEnv = Telemetry.configuredBy(env);
        if (!on && !fromEnv) {
            if (!options.isEmpty()) throw new IllegalArgumentException("the --otel-* options need --otel");
            return;
        }
        Telemetry.Builder builder = Telemetry.fromEnvironment(env);
        for (Consumer<Telemetry.Builder> option : options) option.accept(builder);
        Telemetry telemetry = builder.build();
        if (!telemetry.isEnabled()) {
            console.println("OpenTelemetry: off (OTEL_SDK_DISABLED=true)");
            return;
        }
        telemetry.install(bootstrap);
        console.println("OpenTelemetry: " + telemetry.description());
    }
}
