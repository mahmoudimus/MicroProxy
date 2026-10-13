# Command-line flags

Every option of the `org.microproxy.Launcher` command line (`java -jar microproxy.jar`, or the
`-all` jar), grouped by topic, with the [configuration property](properties.md) that sets the same
thing in a `--config` file and a link to the guide that explains it. `--help` prints the same list;
a test fails when a flag the launcher accepts is missing from this page.

```bash
java -jar microproxy.jar --help
java -jar microproxy.jar --config proxy.properties --port 9090   # flags override the file
```

- Flags that take a value take it as the next argument (`--port 8080`, not `--port=8080`).
- Flags marked *repeatable* may be given more than once; the others keep their last value.
- Boolean flags take no value. Their properties take `true`, `on` or `1`.
- The *Scripting* and *OpenTelemetry* options exist only when the `microproxy-starlark` or
  `microproxy-otel` jar is on the class path (the `-all` jar has both).
- The addon, HAR and replay options are command-line flags only.

## General and listener

See [Quick start](../getting-started/quick-start.md), [configuration properties](properties.md), [TLS listener](../guides/forward-proxy.md#tls-listener), [TLS protocol versions](../guides/mitm.md#tls-protocol-versions), [LittleProxy compatibility](../migrating-from-littleproxy.md).

| Flag | Meaning | Property |
|---|---|---|
| `--config <file>` | properties file (docs/reference/properties.md); flags override it |  |
| `--port <port>` | listen port (default 8080) | `port` |
| `--address <host:port>` | listen address | `address` |
| `--server` | listen on all interfaces, not just loopback | `allow_local_only=false` |
| `--name <name>` | server name for logs and threads | `name` |
| `--idle-timeout <seconds>` | idle connection timeout (default 70, 0 = none) | `idle_connection_timeout` |
| `--connect-timeout <millis>` | outbound connect timeout (default 40000) | `connect_timeout` |
| `--tls-handshake-timeout <millis>` | longest TLS handshake (default 10000, 0 = none) | `tls_handshake_timeout` |
| `--tls-protocols <list>` | TLS versions allowed on every TLS connection (default TLSv1.3,TLSv1.2; "" = JDK defaults) | `tls_protocols` |
| `--littleproxy-compat` | behave like LittleProxy where MicroProxy differs | `littleproxy_compatibility` |
| `--proxy-alias <alias>` | name used in Via headers | `proxy_alias` |
| `--listener-keystore <file>` | serve TLS on the listener with this PKCS#12 or JKS key store's first key entry (HTTPS, HTTP/2, and the certificate --http3 presents) | `listener_keystore` |
| `--listener-keystore-password <pw>` | the key store's password (default empty) | `listener_keystore_password` |
| `--help` | show this help |  |
| `-h` | the same as `--help` | |

## Modes

See [Transparent mode](../guides/transparent-mode.md), [Reverse proxy](../guides/reverse-proxy.md), [SOCKS](../guides/socks.md), [TLS origination](../guides/forward-proxy.md#tls-origination-https-uris-without-connect).

| Flag | Meaning | Property |
|---|---|---|
| `--mode <mode>` | regular, transparent, socks5 or reverse:<scheme>://<host>[:<port>] (scheme http, https or tcp; default https) | `mode` |
| `--transparent` | do not add Via / strip hop-by-hop headers, and route TLS that arrives without CONNECT by its SNI | `transparent` |
| `--transparent-tls-port <port>` | port SNI-routed TLS and QUIC go to (default 443) | `transparent_tls_port` |
| `--allow-requests-to-origin-server` | accept origin-form requests, routed by Host (for transparent HTTP) | `allow_requests_to_origin_server` |
| `--reverse <spec>` | reverse proxy to one upstream: [scheme://]host[:port] | `mode=reverse:...` |
| `--keep-host-header` | in reverse mode, keep the client's Host | `keep_host_header` |
| `--socks` | also serve SOCKS5 and SOCKS4(a) clients on the listener, told apart by their first byte | `socks` |
| `--no-originate-tls` | refuse https:// requests sent without CONNECT (absolute URIs over plain HTTP, :scheme https on h2c) instead of opening TLS to the server for them, which --originate-tls (the default) does | `originate_tls=false` |
| `--originate-tls` | fetch `https://` requests sent without CONNECT over TLS the proxy opens to the server (the default; overrides `originate_tls=false` from `--config`) | `originate_tls=true` |

## Upstreams and routing

See [Chained proxies](../guides/chained-proxies.md), [DNSSEC](../guides/dnssec.md), [Forward proxy](../guides/forward-proxy.md), [Concurrency limiting](../guides/concurrency-limiting.md).

| Flag | Meaning | Property |
|---|---|---|
| `--upstream-proxy <url>` | chain to http(s)://[user:pw@]host:port or socks5://...; h2://... (TLS, ALPN h2) or h2c://... (prior knowledge) speaks HTTP/2 to it, tunnels and requests as streams ([HTTP/2 to chained proxies](../guides/chained-proxies.md#http2-to-chained-proxies)) | `upstream_proxy` |
| `--upstream-https-proxy <url>` | different upstream for HTTPS / CONNECT | `upstream_https_proxy` |
| `--no-proxy <list>` | hosts to reach directly (NO_PROXY syntax) | `no_proxy` |
| `--env-proxy` | take upstream proxies from http_proxy/https_proxy/no_proxy | `use_env_proxy` |
| `--chained-proxy-backoff` | <initial>[:<max>]  millis to wait between failed chained proxy attempts, doubling up to max (default 8 x initial; 0 = no waiting, the default) | `chained_proxy_backoff_initial_ms`, `chained_proxy_backoff_max_ms` |
| `--dnssec` | resolve server names with DNSSEC validation | `dnssec` |
| `--dnssec-resolver <spec>` | DoH URL or comma-separated resolver IPs for --dnssec | `dnssec_resolver` |
| `--shared-pool` | share server connections between clients | `use_shared_server_connection_pool` |
| `--accept-proxy-protocol` | require a PROXY protocol header on inbound connections | `allow_proxy_protocol` |
| `--proxy-protocol-mode <mode>` | `off`, `required` or `optional` (a header is read if one comes; any client can then claim any address) | `allow_proxy_protocol` |
| `--proxy-protocol-trusted-sources <list>` | IP addresses or CIDR ranges whose PROXY headers count | `proxy_protocol_trusted_sources` |
| `--send-proxy-protocol` | send a PROXY protocol v1 header upstream | `send_proxy_protocol` |
| `--throttle <read> <write>` | global server bandwidth limits in bytes/s | `throttle_read_bytes_per_second`, `throttle_write_bytes_per_second` |
| `--max-concurrent-per-client <n>` | exchanges each client IP may run at once; more get 429 (CONNECT tunnels count while open) | `max_concurrent_per_client` |
| `--strip-tracing-headers` | remove traceparent, tracestate, baggage, B3 and other tracing headers from requests sent upstream | `strip_tracing_headers` |
| `--strip-request-headers <list>` | also remove these comma-separated request headers | `strip_request_headers` |

## Interception

See [MITM, certificates and TLS](../guides/mitm.md), [TCP hosts](../guides/tcp-hooks.md#tcp-hosts), [Alt-Svc](../guides/http3.md#alt-svc-which-clients-may-move-to-http3).

| Flag | Meaning | Property |
|---|---|---|
| `--mitm` | intercept HTTPS with a generated CA |  |
| `--mitm-ca <file.p12>` | CA key store for --mitm (created if missing; default ./microproxy-ca.p12) |  |
| `--mitm-ca-password <pw>` | key store password (default "microproxy") |  |
| `--mitm-trust-all` | do not validate upstream server certificates |  |
| `--ignore-hosts <regex>` | tunnel TLS to matching host:port names (CONNECT target or SNI) untouched; repeatable | `ignore_hosts` |
| `--allow-hosts <regex>` | intercept only TLS to matching host:port names; repeatable | `allow_hosts` |
| `--tcp-hosts <regex>` | relay matching hosts (target host or SNI) as raw TCP even when they look like HTTP; TLS is still intercepted; repeatable | `tcp_hosts` |
| `--no-alt-svc-h3` | remove h3 (HTTP/3, QUIC) alternatives from Alt-Svc response headers, so clients stay on TCP through the proxy (default with --mitm or --transparent) | `strip_alt_svc_h3=true` |
| `--keep-alt-svc-h3` | pass Alt-Svc h3 alternatives on even with --mitm or --transparent | `strip_alt_svc_h3=false` |

## HTTP/2

See [HTTP/2](../guides/http2.md).

| Flag | Meaning | Property |
|---|---|---|
| `--http2` | serve HTTP/2 to clients that offer it (ALPN h2) on intercepted TLS and the proxy TLS listener (the default); needs the http2-codec jar: without it the default falls back to HTTP/1.1, the flag fails to start the proxy; overrides `http2=false` from `--config` | `http2=true` |
| `--no-http2` | serve clients HTTP/1.1 only | `http2=false` |
| `--http2-upstream` | speak HTTP/2 to servers that offer it over TLS (ALPN h2), one shared connection per server (the default); needs the http2-codec jar, as --http2 does | `http2_upstream=true` |
| `--no-http2-upstream` | speak HTTP/1.1 only to servers | `http2_upstream=false` |
| `--http2-cleartext` | serve HTTP/2 with prior knowledge (h2c) on the plain listener (off by default); needs the http2-codec jar | `http2_cleartext` |
| `--http2-cleartext-only` | serve only h2c on the plain listener: a connection without the HTTP/2 preface gets GOAWAY PROTOCOL_ERROR instead of HTTP/1.x (implies --http2-cleartext; [h2c-only listener](../guides/http2.md#h2c-only-listener)) | `http2_cleartext_only` |
| `--http2-max-streams <n>` | concurrent HTTP/2 streams per client connection (default 100) | `http2_max_concurrent_streams` |
| `--http2-coalesce` | with HTTP/2 to servers, let an HTTP/2 connection to a server carry requests for other names its certificate covers that resolve to its address, or that it names in an ORIGIN frame (RFC 9113 9.1.1, RFC 8336) | `http2_coalesce` |

## HTTP/3, QUIC and CONNECT-UDP

See [HTTP/3 and QUIC](../guides/http3.md), [Transparent QUIC](../guides/transparent-mode.md#transparent-quic), [CONNECT-UDP (MASQUE)](../guides/masque.md), [QUIC stream hooks](../guides/quic-hooks.md).

| Flag | Meaning | Property |
|---|---|---|
| `--http3` | also serve HTTP/3 (QUIC) on the UDP port with the listener's number: in reverse mode, advertised with Alt-Svc on TCP responses; in forward mode next to the TLS listener (--listener-keystore), with CONNECT, WebSockets and CONNECT-UDP (MASQUE); needs the quic and http3-codec jars, and a certificate (--listener-keystore, or --mitm's CA in reverse mode) | `http3` |
| `--http3-upstream` | speak HTTP/3 to servers that advertise it (Alt-Svc h3), one shared QUIC connection per server, falling back to TCP; needs the quic and http3-codec jars | `http3_upstream` |
| `--http3-upstream-hosts <regex>` | reach matching host:port names over HTTP/3 without waiting for Alt-Svc (with --http3-upstream); repeatable | `http3_upstream_hosts` |
| `--http3-max-streams <n>` | concurrent HTTP/3 requests per client connection (default 100) | `http3_max_concurrent_streams` |
| `--no-http3-alt-svc` | with --http3, do not advertise it with Alt-Svc | `http3_alt_svc=false` |
| `--http3-retry` | validate QUIC clients' addresses with a Retry first (--http3 and --transparent-quic-port) | `http3_retry` |
| `--http3-0rtt` | accept 0-RTT early data from resuming HTTP/3 clients (--http3, --transparent-quic-port and --masque-intercept-quic): replayable, so unsafe methods get 425 and the rest go on with Early-Data: 1 | `http3_0rtt` |
| `--no-http3-upstream-0rtt` | never send requests to HTTP/3 servers as 0-RTT data (by default GET, HEAD and OPTIONS without a body may go) | `http3_upstream_0rtt=false` |
| `--quic-congestion <name>` | congestion control of the proxy's QUIC connections: cubic (default), newreno or bbr (experimental) | `quic_congestion` |
| `--transparent-quic-port <port>` | with --transparent, also take QUIC (UDP) redirected to this UDP port: route it by the SNI of its ClientHello, intercept HTTP/3 (with --mitm) or relay it untouched; needs the quic and http3-codec jars | `transparent_quic_port` |
| `--transparent-quic-relay-idle-timeout <seconds>` | close a relayed QUIC flow after this long without a datagram (default 60) | `transparent_quic_relay_idle_timeout` |
| `--masque` | serve CONNECT-UDP (MASQUE) on the TCP listener, also without --http3: over HTTP/2 (h2, --http2-cleartext) and as HTTP/1.1 Upgrade: connect-udp, in DATAGRAM capsules; a forward proxy with --http3 serves it there anyway; needs the quic and http3-codec jars | `masque` |
| `--masque-udp-template <t>` | the URI template of CONNECT-UDP requests (default /.well-known/masque/udp/{target_host}/{target_port}/) | `masque_udp_template` |
| `--masque-udp-idle-timeout <seconds>` | close a CONNECT-UDP flow after this long without a datagram either way (default 60) | `masque_udp_idle_timeout` |
| `--masque-max-udp-flows <n>` | CONNECT-UDP flows at once (default 4096) | `masque_max_udp_flows` |
| `--masque-max-udp-flows-per-connection <n>` | CONNECT-UDP flows of one client connection (default 64) | `masque_max_udp_flows_per_connection` |
| `--masque-release-wait <millis>` | how long a CONNECT-UDP request that finds --masque-max-udp-flows reached waits for flows already ending to give their places back (default 250, 0 = none) | `masque_release_wait` |
| `--masque-intercept-quic` | decide on QUIC inside CONNECT-UDP flows as on transparent QUIC: intercept HTTP/3 (and other QUIC with the QUIC hooks) unless the host rules or hooks decline, else relay | `masque_intercept_quic` |
| `--masque-quic-ports <list>` | the target ports whose flows --masque-intercept-quic inspects: comma-separated, or "any" (default 443) | `masque_quic_ports` |
| `--quic-hosts <regex>` | relay matching hosts' intercepted QUIC (server host or SNI) stream by stream through the QUIC hooks, even HTTP/3, and intercept their other QUIC; repeatable | `quic_hosts` |
| `--quic-framing <rules>` | cut intercepted QUIC streams into messages for the message hooks, by ALPN or host: key=framer pairs, such as doq=u16,myproto=varint,*=none; framers u16, u32, varint, lf, crlf, none, script (default doq=u16) | `quic_framing` |
| `--quic-max-message-size <n>` | the largest QUIC message framed, in bytes (default 1048576); a larger one resets its stream | `quic_max_message_size` |
| `--quic-message-error-code <n>` | the error code of that reset (default 2) | `quic_message_error_code` |

## Logs, metrics and admin

See [Access logs](../observability/access-logs.md), [Request/response logging](../observability/request-logging.md), [Metrics](../observability/metrics.md), [qlog](../observability/qlog.md), [Admin, readiness and draining](../observability/admin.md).

| Flag | Meaning | Property |
|---|---|---|
| `--activity-log-format <fmt>` | access log to the System.Logger: CLF, ELF, JSON, JSON_EXTENDED, SQUID, W3C, LTSV, CSV, HAPROXY, ENVOY | `activity_log_format` |
| `--access-log <path|->` | write an access log line per exchange or flow to a file, or - for standard output (Envoy's default format unless --access-log-format or -json says) | `access_log` |
| `--access-log-format <fmt>` | a preset name, or an Envoy format string such as '%START_TIME% %REQ(:METHOD)% %RESPONSE_CODE% %RESPONSE_FLAGS%' | `access_log_format` |
| `--access-log-json <dict>` | a JSON object of keys and Envoy format strings, one JSON line per exchange | `access_log_json` |
| `--access-log-filter <expr>` | log only what passes, e.g. 'status>=500 \|\| response_flag' (repeatable: all must pass) | `access_log_filter` |
| `--log-http <level>` | log whole requests and responses: basic, headers or body (to the System.Logger org.microproxy.http) | `log_http` |
| `--log-http-json` | write --log-http as JSON lines (headers if no level) | `log_http_format=json` |
| `--log-http-view <name>` | render logged bodies through content views: auto (the best view per body), or grpc, protobuf, json, msgpack, ... (body if no level) | `log_http_view` |
| `--proto-descriptors <file>` | a protobuf FileDescriptorSet (protoc --descriptor_set_out) for field names in the protobuf and gRPC views (implies --log-http-view auto) | `proto_descriptors` |
| `--metrics` | keep Envoy-style stats (http.*, cluster.*, listener.*, server.*; docs/reference/stats.md) for Prometheus, statsd, scripts | `metrics` |
| `--statsd <host:port>` | push the stats to statsd over UDP every 5 seconds (implies --metrics) |  |
| `--dogstatsd <host:port>` | the same, with DogStatsD tags |  |
| `--stats-prefix <prefix>` | prefix of exported stat names (default envoy: envoy_http_downstream_rq_total, envoy.http....) | `stats_prefix` |
| `--stats-max-clusters <n>` | clusters with stats of their own (default 100); more share cluster "other" unless --stats-cluster-lru |  |
| `--stats-cluster-lru` | evict the least recently used cluster's stats instead |  |
| `--stats-per-host` | a cluster per server of direct connections (host_port), not one "direct" cluster, bounded by --stats-max-clusters |  |
| `--qlog-dir <dir>` | write a qlog file (JSON-SEQ, .sqlog) per QUIC connection, to clients and to servers, into <dir> (for debugging) | `qlog_dir` |
| `--qlog-max-files <n>` | qlog files the directory keeps, the oldest deleted past it (default 1000) | `qlog_max_files` |
| `--admin-port <port>` | serve Envoy's admin API (/stats, /stats/prometheus, /ready, /server_info, /config_dump, /drain_listeners, ...; see docs/reference/admin-api.md) on this port of 127.0.0.1 (implies --metrics) | `admin_port` |
| `--admin-address <host:port>` | the same on another address, such as 0.0.0.0:9901 (then set --admin-token) | `admin_address` |
| `--admin-token <token>` | require this bearer token (or basic password) on every admin path but /ready | `admin_token` |
| `--admin-token-file <file>` | the same, read from the file's first line |  |
| `--drain-time <seconds>` | how long a drain lasts, and how long stopping (SIGTERM) lets exchanges in progress finish (default 10) | `drain_time` |
| `--drain-strategy <strategy>` | gradual (default: more and more new requests are told to go elsewhere) or immediate (all at once) | `drain_strategy` |
| `--health-check-path <path>` | answer health checks on the proxy's listener: 200, or 503 when failed (admin /healthcheck/fail) or draining | `health_check_path` |
| `--health-check-pass-through` | forward a healthy health check to the server instead | `health_check_pass_through` |

## Cache and recording

See [HTTP cache](../guides/caching.md), [WARC recording](../guides/warc.md), [HAR files](../guides/addons.md#har-files).

| Flag | Meaning | Property |
|---|---|---|
| `--cache-dir <dir>` | cache responses on disk (RFC 9111); survives restarts | `cache_dir` |
| `--cache-size <MB>` | disk cache limit (default 1024) | `cache_max_mb` |
| `--cache-memory <MB>` | cache responses in memory instead | `cache_memory_mb` |
| `--offline` | answer only from the cache (needs --cache-dir or --cache-memory) | `offline` |
| `--warc-dir <dir>` | record traffic with servers as WARC files |  |
| `--save-har <file>` | record exchanges as a HAR file, written on exit (.zhar: zlib-compressed) |  |
| `--save-har-filter <filter>` | record only the exchanges a filter expression matches |  |
| `--save-har-stream` | write HAR entries as they complete, not on exit |  |
| `--save-har-max-body <bytes>` | bytes kept of each body (default 1048576; 0 = none) |  |

## Addons and replay

See [Addons, HAR and replay](../guides/addons.md).

| Flag | Meaning | Property |
|---|---|---|
| `--map-local <spec>` | answer from local files: [\|filter]\|url-regex\|file-or-dir |  |
| `--map-remote <spec>` | send requests elsewhere: [\|filter]\|url-regex\|replacement |  |
| `--modify-body <spec>` | replace in bodies: [\|filter]\|regex\|[@]replacement |  |
| `--modify-headers <spec>` | set headers: [\|filter]\|name\|[@]value (empty removes) |  |
| `--block-list <spec>` | answer \|filter\|status (444: close without a response) |  |
| `--anticache` | remove If-None-Match and If-Modified-Since from requests |  |
| `--stickycookie <filter>` | add remembered cookies to requests the filter matches |  |
| `--server-replay <path>` | answer from responses recorded in HAR or WARC files (a file or a directory of them) |  |
| `--server-replay-reuse` | let each recording answer any number of times |  |
| `--server-replay-nopop` | the same as `--server-replay-reuse` (mitmproxy's older name) | |
| `--server-replay-extra <x>` | unmatched requests: forward (default), kill or a status |  |
| `--server-replay-kill-extra` | the same as --server-replay-extra kill |  |
| `--server-replay-no-refresh` | keep the recorded Date, Expires, Last-Modified and cookie expiry instead of shifting them to now |  |
| `--server-replay-ignore-content` | match without comparing request bodies |  |
| `--server-replay-ignore-host` | match without comparing hosts |  |
| `--server-replay-ignore-port` | match without comparing ports |  |
| `--server-replay-ignore-params <list>` | query parameters left out of the match |  |
| `--server-replay-ignore-payload-params <list>` | form fields left out of the match |  |
| `--server-replay-use-headers <list>` | request headers that must match too |  |
| `--client-replay <path>` | send the requests recorded in HAR or WARC files through the proxy once it runs, then exit |  |
| `--client-replay-concurrency <n>` | requests replayed at once (default 1) |  |
| `--keepserving` | keep running after --client-replay |  |

## Scripting (microproxy-starlark)

See [Scripting with Starlark](../guides/scripting.md), [Budgets and measurements](starlark-api.md#script-budgets).

| Flag | Meaning | Property |
|---|---|---|
| `--script <file.star>` | drive the proxy with a Starlark script (docs/guides/scripting.md) |  |
| `--script-no-reload` | do not re-read the script when it changes |  |
| `--script-var <NAME=VALUE>` | a string constant for the script (repeatable) |  |
| `--script-var-file <file>` | string constants for the script, from a properties file |  |
| `--script-name <name>` | the name the script's hooks.starlark stats are tagged with |  |
| `--script-max-steps <n>` | interpreter steps a hook call may run (default 10000000) |  |
| `--script-max-time <time>` | wall-clock budget of a hook call: 250ms, 5s, 1m (default 5s; 0 = none) |  |
| `--script-max-alloc <bytes>` | bytes of values a hook call may create, an estimate: 512k, 64m, 1g (default 256m; 0 = no limit) |  |

## OpenTelemetry (microproxy-otel)

See [OpenTelemetry](../observability/opentelemetry.md).

| Flag | Meaning | Property |
|---|---|---|
| `--otel` | trace with OpenTelemetry and export traces, metrics and access logs over OTLP/HTTP; OTEL_* variables configure it, and OTEL_EXPORTER_OTLP_ENDPOINT alone turns it on (docs/observability/opentelemetry.md) |  |
| `--otel-endpoint <url>` | the collector's OTLP/HTTP base URL (http://localhost:4318) |  |
| `--otel-protocol <p>` | http/protobuf (default) or http/json |  |
| `--otel-header <name=value>` | a header on every export, e.g. for authentication (repeatable) |  |
| `--otel-compression <c>` | gzip or none |  |
| `--otel-service-name <name>` | service.name (microproxy) |  |
| `--otel-resource <k=v,...>` | more resource attributes |  |
| `--otel-signals <list>` | what to export: traces,metrics,logs (default all of them) |  |
| `--otel-sampler <name[:arg]>` | parentbased_always_on (default), always_on, always_off, traceidratio:<r>, parentbased_traceidratio:<r>, ... |  |
| `--otel-propagators <list>` | tracecontext (default), b3, b3multi, jaeger, baggage, none |  |
| `--otel-force-trace-header <h>` | sample every request that has this header |  |
| `--otel-request-id <mode>` | keep (default: add X-Request-Id when missing), replace, off |  |
| `--otel-when-stripped <mode>` | with --strip-tracing-headers, send the proxy's own context (own, the default) or none |  |
| `--otel-ignore-incoming` | start a new trace per request, ignoring the clients' context |  |
| `--otel-metric-interval <ms>` | how often metrics are exported (60000) |  |
| `--otel-log-format <format>` | the body of exported access-log records: a preset or an Envoy format string (Envoy's default) |  |
