# Configuration properties

Every key a MicroProxy properties file accepts, with its meaning and default. Use this page when
writing a `--config` file or calling `MicroProxy.bootstrapFromFile(path)`; the [command-line
flags](cli.md) set the same options, and the linked guides explain them.

## Properties file

Pass a properties file with `--config file.properties` or `MicroProxy.bootstrapFromFile(path)`.
Command-line flags override values from the file.

```properties
# proxy.properties
port = 8080
allow_local_only = false
http2_cleartext = true
access_log = -
metrics = true
admin_port = 9901
```

```bash
java -jar microproxy.jar --config proxy.properties --mitm
```

Boolean keys take `true`, `on` or `1`; anything else is false. Lists are comma-separated. The
addon, HAR and replay options are command-line flags only (see [Addons, HAR and
replay](../guides/addons.md)), and so are `--mitm` and its CA options.

## Keys

| key | meaning | default |
|---|---|---|
| `name` | thread / log name | `MicroProxy` |
| `port` / `address` | listen port / `host:port` | `8080` |
| `allow_local_only` | listen on loopback only | `true` |
| `transparent` | don't add `Via` or strip hop-by-hop headers, and route TLS that arrives without `CONNECT` by its SNI (see [Transparent mode](../guides/transparent-mode.md)) | `false` |
| `transparent_tls_port` | the port SNI-routed transparent TLS (and QUIC) goes to | `443` |
| `transparent_quic_port` | with `transparent`, a UDP port for redirected QUIC, intercepted or relayed by its SNI (see [Transparent QUIC](../guides/transparent-mode.md#transparent-quic)) | none |
| `transparent_quic_relay_idle_timeout` | seconds a relayed QUIC flow lives without a datagram | `60` |
| `mode` | `regular`, `transparent`, `socks5` (see [SOCKS5 mode](../guides/socks.md#socks5-mode)), or `reverse:<scheme>://<host>[:<port>]` with `http`, `https` or `tcp` (see [Reverse proxy mode](../guides/reverse-proxy.md#reverse-proxy-mode)) | `regular` |
| `socks` | also serve SOCKS5 and SOCKS4(a) clients on the regular listener, told apart by their first byte | `false` |
| `keep_host_header` | in reverse mode, keep the client's `Host` | `false` |
| `ignore_hosts` / `allow_hosts` | comma-separated regular expressions for `host:port` names (CONNECT target, SNI) whose TLS is tunnelled untouched / the only ones intercepted (see [Ignoring and allowing hosts](../guides/mitm.md#ignoring-and-allowing-hosts)) | none |
| `tcp_hosts` | comma-separated regular expressions for host names (CONNECT target, SNI) relayed as raw TCP even when they look like HTTP (see [Raw TCP streams](../guides/tcp-hooks.md#raw-tcp-streams)) | none |
| `quic_hosts` | comma-separated regular expressions for host names (server, SNI) whose intercepted QUIC is relayed stream by stream, even HTTP/3 (see [QUIC stream hooks](../guides/quic-hooks.md)) | none |
| `quic_framing` | comma-separated `key=framer` rules choosing, by ALPN or host, how the streams of QUIC intercepted stream by stream are cut into messages for the message hooks (see [QUIC message framing](../guides/quic-hooks.md#quic-message-framing)); added to the default | `doq=u16` |
| `quic_max_message_size` / `quic_message_error_code` | the largest framed QUIC message, in bytes, and the error code of the reset of a stream that sends a larger one | `1048576` / `2` |
| `idle_connection_timeout` | seconds, 0 = none | `70` |
| `connect_timeout` | milliseconds; filters can shorten it per request (`proxyToServerConnectTimeout`) | `40000` |
| `littleproxy_compatibility` | behave like LittleProxy where MicroProxy differs | `false` |
| `tls_handshake_timeout` | milliseconds for a whole TLS handshake, with clients or servers (`0` = none) | `10000` |
| `tls_protocols` | TLS versions allowed on every TLS connection the proxy makes (empty = each context's defaults; see [TLS protocol versions](../guides/mitm.md#tls-protocol-versions)) | `TLSv1.3,TLSv1.2` |
| `max_initial_line_length` / `max_header_size` / `max_chunk_size` | parser limits in bytes | `8192` / `16384` / `16384` |
| `nic` | local address for outbound connections | any |
| `proxy_alias` | name in `Via` | host name |
| `allow_requests_to_origin_server` | accept origin-form requests | `false` |
| `originate_tls` | fetch `https://` URIs that clients ask a forward proxy for without `CONNECT` over TLS the proxy opens itself; `false` refuses them with `400` (see [TLS origination](../guides/forward-proxy.md#tls-origination-https-uris-without-connect)) | `true` |
| `allow_proxy_protocol` / `send_proxy_protocol` | PROXY protocol in / out | `false` |
| `throttle_read_bytes_per_second` / `throttle_write_bytes_per_second` | global server bandwidth | `0` (unlimited) |
| `use_shared_server_connection_pool` | share server connections between clients | `false` |
| `server_connection_pool_type` | pool implementation (`CONCURRENT_MAP`) | `CONCURRENT_MAP` |
| `max_connections_per_host` / `max_total_connections` | pool limits | `10` / `200` |
| `max_concurrent_per_client` | exchanges each client IP may run at once; more get `429` (see [Concurrency limiting](../guides/concurrency-limiting.md)) | off |
| `pool_idle_timeout` | seconds before idle pooled connections close | none |
| `pool_shared_mitm_connections` / `pool_per_request_in_mitm` | pool intercepted TLS connections, per session / per request | `false` |
| `upstream_proxy` / `upstream_https_proxy` | chain to `http(s)://[user:pw@]host:port`, `h2://...` or `h2c://...` ([HTTP/2 to the proxy](../guides/chained-proxies.md#http2-to-chained-proxies)) or `socks4/5://...` (HTTPS / CONNECT may use a different upstream) | none |
| `no_proxy` | hosts reached directly, curl `NO_PROXY` syntax | none |
| `use_env_proxy` | take upstreams from `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy` | `false` |
| `upstream_fallback_to_direct` | connect directly if the upstream is unreachable | `false` |
| `chained_proxy_backoff_initial_ms` / `chained_proxy_backoff_max_ms` | wait between failed chained proxy attempts, doubling from the initial value up to the maximum, with full jitter (see [Retries and backoff](../guides/chained-proxies.md#retries-and-backoff)) | off / 8 × initial |
| `strip_tracing_headers` | remove `traceparent`, `tracestate`, `baggage`, B3 and other tracing headers from requests sent upstream (see [Removing tracing headers](../guides/forward-proxy.md#removing-tracing-headers)) | `false` |
| `strip_request_headers` | comma-separated request headers to remove as well | none |
| `strip_alt_svc_h3` | remove `h3` (HTTP/3) alternatives from `Alt-Svc` response headers (see [Alt-Svc](../guides/http3.md#alt-svc-which-clients-may-move-to-http3)) | `true` with interception or `transparent`, except for redirected clients with `transparent_quic_port`; else `false` |
| `http2` | serve HTTP/2 to clients that offer `h2` on intercepted TLS and the proxy TLS listener; `false` serves them HTTP/1.1 only (needs the `http2-codec` jar: unset, it falls back to HTTP/1.1 without it, while `true` fails to start; see [HTTP/2](../guides/http2.md)) | `true` (with the `http2-codec` jar) |
| `http2_upstream` | speak HTTP/2 to servers that negotiate `h2` on TLS, sharing connections between exchanges; `false` speaks HTTP/1.1 only (the `http2-codec` jar as for `http2`; see [HTTP/2 to servers](../guides/http2.md#http2-to-servers)) | `true` (with the `http2-codec` jar) |
| `http2_coalesce` | with HTTP/2 to servers, let an HTTP/2 connection to a server carry requests for other names its certificate covers that resolve to its address or that it names in an ORIGIN frame (see [Connection coalescing](../guides/http2.md#connection-coalescing)) | `false` |
| `http2_cleartext` | serve HTTP/2 with prior knowledge (`h2c`) on the plain listener (see [h2c](../guides/http2.md#h2c-with-prior-knowledge)) | `false` |
| `http2_cleartext_only` | serve only `h2c` on the plain listener: a connection without the HTTP/2 preface gets `GOAWAY` `PROTOCOL_ERROR` instead of HTTP/1.x (implies `http2_cleartext`; see [h2c-only listener](../guides/http2.md#h2c-only-listener)) | `false` |
| `http2_max_concurrent_streams` | streams an HTTP/2 client may have open at once | `100` |
| `http2_initial_window_size` / `http2_connection_window_size` | request bytes buffered per HTTP/2 stream / per connection | `262144` / `1048576` |
| `http3` | serve HTTP/3 on the UDP port with the listener's number: in reverse mode, or in forward mode next to the TLS listener (`listener_keystore`) for `CONNECT`, WebSockets and CONNECT-UDP (needs the `quic` and `http3-codec` jars and a certificate; see [HTTP/3 and QUIC](../guides/http3.md)) | `false` |
| `http3_upstream` | speak HTTP/3 to servers known to support it, from `Alt-Svc` or `http3_upstream_hosts` (see [HTTP/3 to servers](../guides/http3.md#http3-to-servers)) | `false` |
| `http3_upstream_hosts` | comma-separated regular expressions for `host:port` names reached over HTTP/3 without waiting for `Alt-Svc` | none |
| `http3_max_concurrent_streams` | request streams an HTTP/3 client may have open at once | `100` |
| `http3_alt_svc` | with `http3`, advertise it with `Alt-Svc: h3=":<port>"` on TCP responses | `true` |
| `http3_retry` | validate QUIC clients' addresses with a Retry first (`http3` and intercepted `transparent_quic_port` clients) | `false` |
| `masque` | serve CONNECT-UDP on a forward proxy's TCP listener, also without `http3`: over HTTP/2 (`h2`, `http2_cleartext`) and as an HTTP/1.1 upgrade (needs the `quic` and `http3-codec` jars; see [CONNECT-UDP](../guides/masque.md)); a forward proxy with `http3` serves it there anyway | `false` |
| `masque_udp_template` | the URI template CONNECT-UDP requests name their target with (see [CONNECT-UDP](../guides/masque.md)) | `/.well-known/masque/udp/{target_host}/{target_port}/` |
| `masque_udp_idle_timeout` | seconds a CONNECT-UDP flow lives without a datagram either way | `60` |
| `masque_max_udp_flows` / `masque_max_udp_flows_per_connection` | CONNECT-UDP flows at once, and per client connection | `4096` / `64` |
| `masque_release_wait` | milliseconds a CONNECT-UDP request that finds `masque_max_udp_flows` reached waits for flows already ending to give their places back (see [CONNECT-UDP](../guides/masque.md); `0` = none) | `250` |
| `masque_intercept_quic` | decide on the QUIC inside CONNECT-UDP flows as on transparent QUIC (see [QUIC inside CONNECT-UDP flows](../guides/masque.md#quic-inside-connect-udp-flows)) | `false` |
| `masque_quic_ports` | the target ports of the flows `masque_intercept_quic` inspects: comma-separated, or `any` | `443` |
| `http3_0rtt` | accept 0-RTT early data from resuming HTTP/3 clients (`http3`, and HTTP/3 intercepted from `transparent_quic_port` clients or inside CONNECT-UDP flows; see [Session resumption and 0-RTT](../guides/http3.md#session-resumption-and-0-rtt)) | `false` |
| `http3_upstream_0rtt` | send requests safe to replay (`GET`, `HEAD`, `OPTIONS` without a body) to HTTP/3 servers as 0-RTT data when resuming | `true` |
| `quic_congestion` | congestion control of the proxy's QUIC connections, to clients and to servers: `cubic`, `newreno` or `bbr` (experimental; see [Congestion control](../guides/http3.md#http3-congestion-control)) | `cubic` |
| `qlog_dir` / `qlog_max_files` | write a qlog file per QUIC connection into this directory (see [qlog](../observability/qlog.md#qlog-files)) / how many it keeps | off / `1000` |
| `listener_keystore` / `listener_keystore_password` | serve TLS on the listener with this PKCS#12 or JKS key store's first key entry (HTTPS, HTTP/2 unless `http2=false`, and the certificate `http3` presents) | none / empty |
| `dnssec` | resolve server names with DNSSEC validation | `false` |
| `dnssec_resolver` | DoH URL or comma-separated resolver IPs for `dnssec` | `/etc/resolv.conf` |
| `activity_log_format` | access log to the `System.Logger`: `CLF`, `ELF`, `JSON`, `JSON_EXTENDED`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY`, `ENVOY` | off |
| `access_log` | write the access log to this file, or `-` for standard output (see [Access logs](../observability/access-logs.md#access-logs-envoy-compatible)) | off |
| `access_log_format` | an Envoy format string, or a preset's name, for the access log | Envoy's default |
| `access_log_json` | a JSON object of keys and Envoy format strings: one JSON line per exchange | off |
| `access_log_filter` | log only what passes, e.g. `status>=500 \|\| response_flag` | everything |
| `metrics` | keep Envoy-style stats for Prometheus and statsd (see [Metrics](../observability/metrics.md#metrics-envoy-compatible-stats)) | `false` |
| `stats_prefix` | prefix of exported stat names (implies `metrics`) | `envoy` |
| `admin_port` / `admin_address` | serve the [admin API](../observability/admin.md#admin-interface) on this port of `127.0.0.1` / on this `host:port` (implies `metrics`) | off |
| `admin_token` | the token the admin API requires on every path but `/ready` | none |
| `drain_time` | seconds a drain lasts, and stopping lets exchanges finish (see [Lifecycle, draining and shutdown](../observability/admin.md#lifecycle-draining-and-shutdown)) | `10` |
| `drain_strategy` | `gradual` or `immediate` | `gradual` |
| `health_check_path` / `health_check_pass_through` | answer health checks on the proxy's listener / forward healthy ones to the server | off / `false` |
| `log_http` | log whole requests and responses: `basic`, `headers` or `body` (see [Request/response logging](../observability/request-logging.md)) | off |
| `log_http_format` | `text` or `json` (one object per line) for `log_http` | `text` |
| `log_http_view` | render bodies logged by `log_http` through [content views](../guides/content-views.md#content-views): `auto` or a view's name | off |
| `proto_descriptors` | a protobuf `FileDescriptorSet` (`protoc --descriptor_set_out`) for field names in the protobuf and gRPC views of `log_http` (turns `log_http_view` on) | none |
| `cache_dir` / `cache_max_mb` | cache responses on disk (see [HTTP cache](../guides/caching.md)) / its size | off / `1024` |
| `cache_memory_mb` | cache responses in memory instead | off |
| `cache_max_entry_mb` | largest response body cached | `8` |
| `offline` | answer only from the cache | `false` |
