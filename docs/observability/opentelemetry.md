# OpenTelemetry

Trace the proxy with OpenTelemetry and export traces, metrics and access logs over OTLP/HTTP to a
collector, with W3C Trace Context, B3 or Jaeger propagation, using only the JDK. Use this page to
connect MicroProxy to Jaeger, Tempo, Prometheus or a vendor through an OpenTelemetry Collector.

The optional `microproxy-otel` module (`io.github.mahmoudimus:microproxy-otel`) traces the proxy
with [OpenTelemetry](https://opentelemetry.io) and exports traces, metrics and logs over OTLP,
using nothing but the JDK: W3C Trace Context (and B3 or Jaeger) propagation, a SERVER span per
exchange with a CLIENT span per attempt to reach the server, and OTLP/HTTP export, as protobuf or
JSON, through the JDK's `HttpClient` on virtual threads.

It is a module of its own, like the codecs, and not a package of the core: the core only defines
a small hook, `FlowTracer` (`withTracer`), which costs nothing when unused, and calls it where an
exchange starts, where each attempt to reach the server starts, where the request head is about to
go upstream (after the stripped headers are gone) and where the exchange's record is made. The
module implements it, so the core stays free of OTLP, and the launcher finds the module by class
presence (`ServiceLoader`, as it finds the Starlark module): with its jar on the class path,
`--otel` and the `OTEL_*` variables work. The `microproxy-starlark` `-all` jar bundles it.

## Setup with an OpenTelemetry Collector

The collector receives OTLP/HTTP on port 4318 and
forwards to whatever backends it is configured for (Jaeger, Tempo, Prometheus, a vendor):

```yaml
# otel-collector.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: detailed
  otlp/jaeger:
    endpoint: jaeger:4317
    tls:
      insecure: true
service:
  pipelines:
    traces: {receivers: [otlp], exporters: [otlp/jaeger, debug]}
    metrics: {receivers: [otlp], exporters: [debug]}
    logs: {receivers: [otlp], exporters: [debug]}
```

```sh
docker run -p 4318:4318 -v $PWD/otel-collector.yaml:/etc/otelcol/config.yaml otel/opentelemetry-collector

# OTEL_EXPORTER_OTLP_ENDPOINT alone turns the export on:
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 OTEL_SERVICE_NAME=edge \
    java -cp microproxy.jar:microproxy-otel.jar org.microproxy.Launcher --port 8080
# or with flags, from the -all jar:
java -jar microproxy-starlark-all.jar --port 8080 --otel --otel-endpoint http://localhost:4318 \
    --otel-sampler parentbased_traceidratio:0.1 --otel-propagators tracecontext,b3multi
```

```java
Telemetry otel = Telemetry.fromEnvironment()                 // the OTEL_* variables, then:
        .serviceName("edge")
        .sampler(Sampler.parentBased(Sampler.traceIdRatio(0.1)))
        .propagators(List.of(Propagators.TRACE_CONTEXT, Propagators.B3_MULTI))
        .header("authorization", "Bearer " + token)
        .build();
HttpProxyServer proxy = otel.install(MicroProxy.bootstrap().withPort(8080)).start();
```

`install` sets the tracer, turns the proxy's metrics on when they are exported, and adds the
access-log exporter as an `ActivityTracker`. The proxy closes the telemetry when it stops, after
its exchanges ended: what is queued is exported then.

| variable | meaning | default |
|---|---|---|
| `OTEL_SDK_DISABLED` | `true`: nothing at all, even with `--otel` | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | the collector's base URL; signals go to `<endpoint>/v1/traces`, `/v1/metrics`, `/v1/logs` | `http://localhost:4318` |
| `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT` | one signal's full URL, used as it is | |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `http/json` (`grpc` is refused) | `http/protobuf` |
| `OTEL_EXPORTER_OTLP_HEADERS` | `key=value,...` (percent-decoded) on every export, e.g. `authorization=Bearer%20...` | |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | `gzip` or `none` | `none` |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | milliseconds for one export attempt | `10000` |
| `OTEL_SERVICE_NAME` | `service.name` | `microproxy` |
| `OTEL_RESOURCE_ATTRIBUTES` | `key=value,...` more resource attributes | |
| `OTEL_{TRACES,METRICS,LOGS}_EXPORTER` | `otlp` or `none` per signal (without traces, the proxy still propagates) | `otlp` |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | see Sampling | `parentbased_always_on` |
| `OTEL_PROPAGATORS` | `tracecontext`, `b3`, `b3multi`, `jaeger`, `baggage`, `none` | `tracecontext` |
| `OTEL_METRIC_EXPORT_INTERVAL` | milliseconds between metric exports | `60000` |
| `OTEL_BSP_SCHEDULE_DELAY`, `_MAX_QUEUE_SIZE`, `_MAX_EXPORT_BATCH_SIZE` | the span queue | `5000`, `2048`, `512` |
| `OTEL_BLRP_SCHEDULE_DELAY`, `_MAX_QUEUE_SIZE`, `_MAX_EXPORT_BATCH_SIZE` | the log record queue | `1000`, `2048`, `512` |
| `OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT`, `OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT`, `OTEL_SPAN_EVENT_COUNT_LIMIT`, `OTEL_EVENT_ATTRIBUTE_COUNT_LIMIT` (and `OTEL_ATTRIBUTE_*`) | span limits | `128`, `4096`, `128`, `128` |

| flag | meaning |
|---|---|
| `--otel` | turn it on (the variables above configure it; the flags below override them) |
| `--otel-endpoint <url>`, `--otel-protocol <p>`, `--otel-header <k=v>`, `--otel-compression <c>` | the export |
| `--otel-service-name <name>`, `--otel-resource <k=v,...>` | the resource |
| `--otel-signals traces,metrics,logs` | what is exported |
| `--otel-sampler <name>[:<arg>]`, `--otel-force-trace-header <h>` | sampling |
| `--otel-propagators <list>`, `--otel-ignore-incoming`, `--otel-when-stripped own\|none` | propagation |
| `--otel-request-id keep\|replace\|off` | `X-Request-Id` |
| `--otel-metric-interval <ms>`, `--otel-log-format <format>` | metrics, and the body of log records |

## What is traced

| span | kind | name | when |
|---|---|---|---|
| an HTTP exchange (HTTP/1.x, an HTTP/2 or HTTP/3 stream) | SERVER | the method (`GET`) | from its request head to the end of its response, or until it was abandoned |
| an attempt to reach the server, a child of the exchange's span | CLIENT | the method | from the connection attempt (directly, or through a chained proxy) or, on a connection at hand, from the request, to the response; each chained proxy tried and each request sent again after a stale keep-alive connection is one more, with `http.request.resend_count` |
| a `CONNECT` tunnel, a SOCKS client, a WebSocket session, a TCP-hook tunnel, a CONNECT-UDP flow | INTERNAL | `tunnel example.com:443`, `socks ...`, `websocket ...`, `udp ...` | until it closes; its connection's CLIENT span lasts as long |
| a QUIC flow relayed or intercepted stream by stream, a request a transport answered itself | INTERNAL (SERVER for HTTP) | `quic_relay ...`, `quic ...` | a span of its own, under the context its request carried |
| a call into a [script's](../guides/scripting.md) hook, a child of its exchange's (tunnel's, flow's) span | INTERNAL | `starlark on_request`, `starlark on_tcp_message`, ... | the call, with `starlark.hook`, `starlark.script`, `starlark.steps`, `starlark.alloc_bytes` and `starlark.budget_exceeded` |

The server sees the CLIENT span as its parent: the proxy writes its own `traceparent` (and the
configured propagators' headers) on each request it sends, after the filters, so the trace goes
client → proxy SERVER span → proxy CLIENT span → server. Requests inside an intercepted session
are exchanges of their own, with the context they carry.

| attribute | on | value |
|---|---|---|
| `http.request.method` (`_OTHER` and `http.request.method_original` for others) | all | the method |
| `url.full` | CLIENT; SERVER for absolute-form (proxy) requests | the URL; a CLIENT span's scheme is `https` when the proxy speaks TLS to the server itself (an `https://` URI a client asked for without `CONNECT`, an intercepted session's server, a reverse proxy's `https://` upstream, HTTP/2 and HTTP/3), on any port, and `http` otherwise |
| `url.scheme`, `url.path`, `url.query` | SERVER | the request target |
| `server.address`, `server.port` | all | the target (CLIENT: the server the attempt was for) |
| `client.address`, `client.port` | SERVER, INTERNAL | the client (the PROXY protocol's source, when there was one) |
| `user_agent.original` | SERVER | `User-Agent` |
| `network.protocol.name`, `network.protocol.version` | SERVER; CLIENT once its request went out | `http`, `1.1`, `2`, `3`: the client's; a CLIENT span's, the connection's to the server |
| `http.response.status_code` | all | the status the client got (CLIENT: the server's) |
| `http.request.body.size`, `http.response.body.size` | SERVER | body bytes from and to the client |
| `error.type` | all | the status for a 5xx (CLIENT: 4xx too), else the failure (`connect_failed`, `server_timeout`, `unresolved_host`, `tls_failed`, `stale_connection`, ...) |
| `response_flags`, `upstream_cluster`, `upstream_address`, `guid:x-request-id` | as Envoy's tracing tags | `UF,URX`; the chained proxy or server; its address; the request id |
| `microproxy.response_source`, `microproxy.response_code_details`, `microproxy.flow` | SERVER, INTERNAL | `SERVER`, `PROXY`, ...; `via_upstream`, `proxy_failure:connect_failed`, ...; `h1`, `h2`, `tunnel`, ... |
| `microproxy.connection_id`, `microproxy.stream_id`, `microproxy.socks_version`, `microproxy.chained_proxy` | | the client connection and stream; the SOCKS version; a CLIENT span's chained proxy |
| `network.transport`, `microproxy.bytes_received`, `microproxy.bytes_sent`, `microproxy.upstream_bytes_sent`, `microproxy.upstream_bytes_received` | INTERNAL | `tcp` or `udp`, and the payload each way |

The SERVER (or INTERNAL) span's events come from the exchange's [timings](activity-tracking.md#observability):
`dns_lookup`, `connect` and `tls_handshake` at the end of each phase, with
`microproxy.duration_ms`; `request_sent`; `first_byte`; and `downstream_tls_handshake` for the
client's handshake. Its status is ERROR on a 5xx, on a failure of the proxy's (`ctx.failure()`),
and on the flags that say the server or the proxy failed (`UF`, `UT`, `UR`, `UC`, `UO`, `NR`,
`URX`, `UPE`, `DF`, ...), with the response code details as its message; a CLIENT span's is ERROR
on a 4xx or 5xx and on a failed attempt. A client that went away (`DC`, `DR`) is not an error of
the proxy's. Filters and scripts add attributes and events with `ctx.trace().setAttribute(key,
value)` and `addEvent(name, attributes)` (Starlark's `trace` module); the span limits bound them:
past them attributes and events are dropped and counted (`droppedAttributesCount`), and strings
are cut.

## Propagation

The configured propagators work as OpenTelemetry's composite propagator: they
extract in the configured order, each over what the ones before it found, so when a request
carries several contexts the last propagator that finds a valid one gives the parent (with
`OTEL_PROPAGATORS=b3multi,tracecontext`, a valid `traceparent` wins over `X-B3-*`); every
configured propagator writes the proxy's context upstream, replacing the client's headers it
owns. `tracecontext` follows the W3C specification: version `00` and later
versions, lower-case hex only, no all-zero ids, two `traceparent` headers restart the trace, and a
`tracestate` that is not valid (a bad key or value, a duplicate key, more than 32 members) is
dropped while the `traceparent` is kept; a valid one is sent on as it came. `b3` is B3's single
header (`{trace}-{span}-{1|0|d}`, 64-bit trace ids padded), `b3multi` its `X-B3-*` headers, and
`jaeger` `uber-trace-id` (separators URL-encoded or not). `baggage` is accepted and leaves the
`baggage` header alone. `--otel-ignore-incoming` (`trustIncoming(false)`) makes the proxy a trust
boundary: each request starts a new trace.

`X-Request-Id`: kept when the client sent one and made (a random UUID, version 4) when it did not,
before filters, trackers and the access log see the request, so the server, the span
(`guid:x-request-id`), the log record and the access log's `%REQ(X-REQUEST-ID)%` and
`%UNIQUE_ID%` all show the same id; `replace` always makes a new one, `off` leaves the header
alone. `%TRACE_ID%` and `%SPAN_ID%` put the ids in access-log lines.

With [`withoutTracingHeadersUpstream()`](../guides/forward-proxy.md#removing-tracing-headers) (`--strip-tracing-headers`),
the client's tracing headers are removed first; then the proxy writes only its own span context
(`own`, the default: the propagators' headers with the trace id, the proxy's span id and the
sampled flag, and no `tracestate` or `baggage` of the client's) or nothing at all (`none`,
`--otel-when-stripped none`, `whenStripped(WhenStripped.NONE)`): the server then never learns of
the trace, which is still recorded. With `own`, the trace id continues the client's; add
`--otel-ignore-incoming` to keep even that inside.

## Sampling

`parentbased_always_on` (the default) follows the sampled flag of the context that
came with the request, and samples new traces; `parentbased_traceidratio` with an argument of
`0.1` samples a tenth of the new ones, deciding by the trace id, so every process of a trace
decides alike; `always_on`, `always_off`, `traceidratio` and `parentbased_always_off` are the
others. `--otel-force-trace-header x-envoy-force-trace` (`forceTraceHeader`) samples every request
that has the header, whatever the sampler says. A request that is not sampled is still given ids
and propagated, with the sampled flag off, so the servers behind follow the decision.

## Export

Spans and log records wait in bounded queues and leave in batches, as soon as a batch
is full or after the schedule delay, one virtual thread per signal; metrics are read from the
registry every interval. Each batch is one POST with the configured headers, gzipped when asked,
within the timeout; `429`, `502`, `503`, `504` and failed connections are retried, up to five
attempts, with exponential backoff and jitter (1 s, growing by half, up to 5 s), waiting at least
what `Retry-After` says (up to 30 s). Other answers fail the batch. When the collector is down or
slow and a queue is full, new spans and records are dropped, never waited for, and counted. With
metrics on, the module's own stats are in the registry: `otel.spans_exported`,
`otel.spans_dropped`, `otel.spans_failed`, `otel.spans_queued`, `otel.spans_export_retries`, the
same for `otel.logs_*`, and `otel.metrics_exports`, `otel.metrics_failed`.

- **Resource:** `service.name`, `service.version` (the proxy's), `host.name`, `process.pid`,
  `process.runtime.name`, `process.runtime.version`, `process.runtime.description`,
  `telemetry.sdk.*`, and `OTEL_RESOURCE_ATTRIBUTES`; the instrumentation scope is
  `org.microproxy`.
- **Metrics:** the [stats](metrics.md#metrics-envoy-compatible-stats) as Prometheus sees them: one metric per
  tag-extracted name, prefixed (`envoy.cluster.upstream_rq_xx`), with the tags as attributes
  (`envoy_cluster_name`, `envoy_response_code_class`); counters are monotonic cumulative sums,
  gauges are gauges, histograms are cumulative histograms with the registry's explicit bounds
  (Envoy's, in milliseconds; `ms`, `us` or `By` units by name). Exporting metrics turns the stats
  on.
- **Logs:** one log record per access-log record (exchange, tunnel or flow): the body is the
  access-log line (Envoy's default format, or `--otel-log-format`), the attributes are the span's,
  plus `microproxy.duration_ms`; the severity is ERROR when the span would be an error, WARN for a
  4xx, INFO otherwise; the trace and span ids tie it to the SERVER span.
- **Encodings:** the OTLP messages are written by hand with opentelemetry-proto's field numbers
  (protobuf), or in the OTLP/JSON mapping (ids in hex, 64-bit numbers as strings). The tests
  decode both with the core's [schema-less protobuf decoder](../guides/content-views.md#protobuf-without-a-schema) and JSON
  parser, and, when Python has `opentelemetry-proto`, with its generated classes, which must
  accept every field and find both encodings equal (CI runs this with the interop job).

## Overhead

Without the module, or disabled (`OTEL_SDK_DISABLED=true`, `enabled(false)`), the
tracer is `FlowTracer.NOOP` and the proxy skips every call: no work, no allocation. Enabled, a
request that is not sampled costs its ids, a small object and the headers written upstream (and
the request id); only sampled exchanges allocate spans, attributes and events, and the request
head's attributes are read once, when it arrives. Spans are built when the exchange ends, on its
thread, and handed to the queue; encoding and sending happen on the exporters' threads.

## Limitations

OTLP over gRPC is not supported (it needs gRPC's framing over HTTP/2; the proxy's
own HTTP/2 client could carry it later); use the collector's OTLP/HTTP receiver. Metrics are
cumulative only, without exemplars; spans have no links; baggage is passed on, not read. The
partial-success part of a collector's answer is not read. A span starts when the proxy has read
the request head, a few microseconds after its first byte.
