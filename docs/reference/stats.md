# Stats and metrics names

Every stat MicroProxy keeps with metrics on, by name, type and meaning, under Envoy's names where
Envoy has them. Use this page to write dashboards and alerts; [Metrics, Prometheus and
statsd](../observability/metrics.md) explains how to turn metrics on, how names become Prometheus
labels, and how clusters are chosen.

`<name>` is the proxy's name (`--name`, `withName`), `<address>` the listener's address
(`0.0.0.0_8080`), and `<cluster>` the cluster ([Clusters and
cardinality](../observability/metrics.md#clusters-and-cardinality)).

## HTTP, listener, cluster and server stats

| stat | type | meaning |
|---|---|---|
| `http.<name>.downstream_rq_total` | counter | requests from clients (a `CONNECT` is one request, until its tunnel closes) |
| `http.<name>.downstream_rq_active` | gauge | requests in progress |
| `http.<name>.downstream_rq_1xx` ... `_5xx` | counter | responses by class (tag `envoy_response_code_class`) |
| `http.<name>.downstream_rq_time` | histogram | from a request's first byte to its response's last |
| `http.<name>.downstream_rq_http1_total`, `_http2_total`, `_http3_total` | counter | requests by protocol |
| `http.<name>.downstream_rq_rx_reset` / `_tx_reset` | counter | requests the client reset (`DR`) / the proxy reset or cut off after its response started |
| `http.<name>.downstream_rq_too_large` | counter | requests the proxy answered `413` |
| `http.<name>.downstream_rq_head_timeout` | counter | HTTP/1 request heads that exceeded their total deadline and received `408` |
| `http.<name>.downstream_rq_chunked_length` | counter | MicroProxy's: HTTP/1.1 requests with both `Transfer-Encoding` and `Content-Length` accepted by `--allow-chunked-length` (a request smuggling signal) |
| `http.<name>.downstream_rq_response_flag.<flag>` | counter | MicroProxy's: requests that ended with a 4xx or 5xx response, or none, by [response flag](response-flags.md#response-flags-and-details) (tag `microproxy_response_flag`: `UF`, `UT`, `DC`, ...) |
| `http.<name>.downstream_cx_total`, `_active` | counter, gauge | client connections (TCP, and QUIC connections of the HTTP/3 listener) |
| `http.<name>.downstream_cx_http1_total`, `_http2_total`, `_http3_total` | counter | connections by the protocols they carried (once each) |
| `http.<name>.downstream_cx_ssl_total` | counter | connections that completed a TLS handshake (TLS listener or interception) |
| `http.<name>.downstream_cx_destroy`, `_destroy_remote`, `_destroy_local` | counter | connections closed: by the client, or by the proxy (timeouts, `Connection: close`, stopping) |
| `http.<name>.downstream_cx_length_ms` | histogram | how long connections were open |
| `http.<name>.downstream_cx_rx_bytes_total`, `_tx_bytes_total` | counter | bytes read from / written to clients (decrypted, over TLS; HTTP/1 and HTTP/2) |
| `listener.<address>.downstream_cx_total`, `_active`, `_destroy` | counter, gauge | the TCP listener's connections |
| `listener.<address>.downstream_pre_cx_active` | gauge | connections not yet past the PROXY header, the TLS listener's handshake or protocol detection |
| `listener.<address>.ssl.handshake`, `ssl.connection_error` | counter | TLS handshakes with clients that succeeded / failed (the TLS listener and intercepted sessions) |
| `cluster.<cluster>.upstream_cx_total`, `_active` | counter, gauge | connections to servers or chained proxies |
| `cluster.<cluster>.upstream_cx_connect_fail`, `_connect_timeout` | counter | connection attempts that failed (TCP, TLS, a chained proxy's refusal) / timed out |
| `cluster.<cluster>.upstream_cx_connect_ms` | histogram | TCP connect time (QUIC: the handshake) |
| `cluster.<cluster>.upstream_cx_http1_total`, `_http2_total`, `_http3_total` | counter | connections by protocol (a chained proxy's HTTP/2 connections carry its tunnels and requests as streams: [HTTP/2 to chained proxies](../guides/chained-proxies.md#http2-to-chained-proxies)) |
| `cluster.<cluster>.upstream_cx_destroy`, `_destroy_local`, `_destroy_remote`, `upstream_cx_length_ms` | counter, histogram | connections closed, by whom, and how long they were open |
| `cluster.<cluster>.upstream_cx_pool_overflow` | counter | requests refused for want of a pooled connection (`UO`) |
| `cluster.<cluster>.upstream_rq_total`, `_active` | counter, gauge | requests sent to the cluster (each attempt) |
| `cluster.<cluster>.upstream_rq_1xx` ... `_5xx`, `upstream_rq_time` | counter, histogram | the server's responses by class, and request time |
| `cluster.<cluster>.upstream_rq_retry`, `_timeout`, `_rx_reset` | counter | requests sent again after a stale keep-alive connection (or a `421` on a coalesced HTTP/2 connection); that timed out (`UT`); that the server reset or cut off (`UR`, `UC`) |
| `cluster.<cluster>.ssl.handshake`, `ssl.connection_error` | counter | TLS handshakes with servers and TLS chained proxies |
| `cluster.<cluster>.ssl.retry_without_sni` | counter | TLS handshakes with servers tried again without SNI after the server's `unrecognized_name` alert ([`--tls-retry-without-sni`](../guides/mitm.md#server-tls-failures)) |
| `cluster.<cluster>.upstream_cx_rx_bytes_total`, `_tx_bytes_total` | counter | bytes read from / written to the cluster (decrypted over TLS, as the downstream ones; tunnels included; over QUIC, the datagrams' bytes, added when the connection closes) |
| `cluster.<cluster>.failover` | counter | connection attempts through the cluster that failed and moved on to the route's next choice |
| `cluster.<cluster>.backoff_engaged` | counter | waits ([retries and backoff](../guides/chained-proxies.md#retries-and-backoff)) before trying the cluster after earlier choices failed |
| `cluster.<cluster>.backoff_active` | gauge | requests waiting to try the cluster now: a lighter kind of outlier detection |
| `proxy_proto.v1.found`, `v2.found` / `v1.error`, `v2.error` | counter | [PROXY protocol](../guides/forward-proxy.md#proxy-protocol) headers read / malformed, or not complete in time |
| `proxy_proto.not_found_allowed`, `not_found_disallowed` | counter | connections without a PROXY header: served (optional mode) / closed (required mode, or a signature begun and not finished) |
| `proxy_proto.untrusted_source` | counter | MicroProxy's: connections closed because a PROXY header (or, when one is required, the connection) came from a peer outside `--proxy-protocol-trusted-sources` |
| `tls_inspector.tls_found`, `tls_not_found`, `sni_found`, `sni_not_found`, `alpn_found`, `alpn_not_found`, `client_hello_too_large` | counter | the ClientHellos the proxy reads to decide on a session (transparent TLS, interception) |
| `cache.hits`, `misses`, `stores`, `revalidations`, `stale_served` | counter | the [HTTP cache](../guides/caching.md)'s counts (`HttpCache.stats()`) |
| `concurrency_limit.in_use`, `waiting` / `acquired`, `rq_blocked`, `reclaimed` | gauge / counter | the [concurrency limiter](../guides/concurrency-limiting.md) among the filters |
| `connection_pool.total_connections`, `active_connections`, `idle_connections` / `borrow`, `return`, `eviction`, `validation_failure` | gauge / counter | the [shared pool](../guides/forward-proxy.md#shared-server-connection-pool) (`getServerConnectionPoolMetrics()`) |
| `server.uptime`, `live`, `concurrency`, `memory_allocated`, `memory_heap_size`, `total_connections` | gauge | seconds running, 1 while `LIVE` (0 once draining or stopping), processors, heap used and committed (`MemoryMXBean`), client connections open |
| `server.state` | gauge | Envoy's numbers: 0 live, 1 draining, 2 pre-initializing, 3 initializing (4 stopped) |
| `http.<name>.downstream_cx_drain_close` | counter | client connections told to go away while draining or with a failed health check (`Connection: close`, GOAWAY) |
| `listener_manager.total_listeners_active`, `total_listeners_draining` / `listener_stopped` | gauge / counter | listeners accepting, those accepting while the proxy drains / listeners closed |

## HTTP/2 and HTTP/3 codecs

`http2.<direction>.*` and `http3.<direction>.*`, where the
direction is `downstream` (connections from clients) or `upstream` (to servers), Prometheus's
`microproxy_direction`. The names are Envoy's codec stats where Envoy has them; the floods are the
hardening limits of [`Http2Options`](../guides/http2.md) and [`Http3Options`](../guides/http3.md) being hit,
each of which ends the connection.

| stat | type | meaning |
|---|---|---|
| `http2.<dir>.rx_reset`, `tx_reset` | counter | RST_STREAM received / sent |
| `http2.<dir>.goaway_sent`, `goaway_received` | counter | GOAWAY sent / received |
| `http2.<dir>.streams_active` | gauge | streams open |
| `http2.<dir>.header_overflow` | counter | header lists over SETTINGS_MAX_HEADER_LIST_SIZE (the stream is reset) |
| `http2.<dir>.headers_cb_no_stream` | counter | HEADERS for a stream already closed |
| `http2.<dir>.inbound_empty_frames_flood`, `inbound_priority_frames_flood`, `inbound_window_update_frames_flood` | counter | connections closed for too many empty DATA frames or trailers, PRIORITY and RST_STREAM frames, WINDOW_UPDATE frames |
| `http2.<dir>.outbound_control_flood` | counter | connections closed for too many PINGs or SETTINGS, each of which needs an answer |
| `http2.<dir>.inbound_rapid_reset_flood` | counter | MicroProxy's: connections closed for too many streams reset (or refused) before their response (Rapid Reset) |
| `http2.<dir>.settings_timeout` | counter | MicroProxy's: connections closed because the proxy's SETTINGS went unacknowledged |
| `http2.<dir>.rx_messaging_error` | counter | malformed frames, header blocks or messages received |
| `http2.<dir>.trailers` | counter | trailers received |
| `http2.<dir>.tx_flush_timeout` | counter | connections closed because writes made no progress for the idle timeout (a peer that stopped reading) |
| `http2.<dir>.stream_flow_control_blocked`, `connection_flow_control_blocked` | counter | MicroProxy's: times DATA waited for a stream's, or the connection's, send window |
| `http2.upstream.coalesced_streams` | counter | MicroProxy's: streams opened on a connection made for another server name ([connection coalescing](../guides/http2.md#connection-coalescing)) |
| `http2.upstream.misdirected_421_retry` | counter | MicroProxy's: requests a coalesced connection answered `421 Misdirected Request`, sent again on a connection of their own |
| `http3.<dir>.rx_reset`, `tx_reset` | counter | request streams the peer reset / the proxy reset |
| `http3.<dir>.goaway_sent`, `goaway_received`, `streams_active` | counter, gauge | GOAWAY, and request streams open |
| `http3.<dir>.qpack_blocked_streams`, `qpack_decoder_errors` | counter | field sections that waited for the QPACK encoder stream / that QPACK could not decode |
| `http3.<dir>.unknown_frames`, `unknown_stream_types` | counter | frames of unknown types (and empty DATA) / unidirectional streams of unknown types received |
| `http3.downstream.early_data_requests`, `too_early_425` | counter | requests that arrived in 0-RTT data / that were answered `425 Too Early` |
| `http3.upstream.tcp_fallback` | counter | requests to a server known to speak HTTP/3 that went over TCP (its QUIC handshake failed, now or recently, or it took no new streams) |
| `http3.alt_svc_origins` | gauge | origins remembered as offering HTTP/3 in `Alt-Svc` |

## QUIC

`quic.<scope>.*` counts the proxy's QUIC connections by scope (`microproxy_quic_scope`):
`downstream` (the HTTP/3 listener's), `transparent` (those the transparent QUIC listener
intercepts), `masque` (QUIC intercepted inside CONNECT-UDP flows) and `upstream` (the proxy's own,
to HTTP/3 servers and to the servers of QUIC intercepted stream by stream). A connection counts
its packets in plain fields of its own (`QuicConnection.stats()`, see the
[quic module](https://github.com/mahmoudimus/MicroProxy/blob/main/quic/README.md)); they are added to these counters once, when it closes.

| stat | type | meaning |
|---|---|---|
| `quic.<scope>.connections_active`, `connections_total` | gauge, counter | connections open / started |
| `quic.<scope>.handshake_failures.<error>` | counter | connections that ended before their handshake, by error (`microproxy_quic_error`): `timed_out`, `crypto_error` (TLS alerts), `connection_refused`, `protocol_violation`, `transport_error`, `peer_closed`, `application_closed`, `local_close`, `stateless_reset`, `version_mismatch` |
| `quic.<scope>.handshake_ms` | histogram | from a connection's start to its handshake's end |
| `quic.<scope>.rtt_ms` | histogram | smoothed RTT of connections when they closed |
| `quic.<scope>.packets_sent_total`, `packets_received_total`, `packets_lost_total` | counter | packets, counted at close |
| `quic.<scope>.bytes_sent_total`, `bytes_received_total`, `bytes_lost_total` | counter | UDP payload bytes, counted at close |
| `quic.<scope>.pto_total`, `congestion_events_total`, `key_updates_total` | counter | probe timeouts, congestion events, key updates, counted at close |
| `quic.<scope>.zero_rtt_accepted`, `zero_rtt_rejected` | counter | connections whose 0-RTT data was accepted / rejected |
| `quic.<scope>.migrations`, `nat_rebindings` | counter | moves to a new path, counted at close: the proxy following a client to its new address (a NAT rebinding, a migration, the preferred address; not a return to the old path after a failed validation), or the proxy's own connection switching to a path it probed / of those, the proxy following a client to a new port of the same address |
| `quic.<scope>.path_validations`, `path_validation_failures` | counter | PATH_CHALLENGEs answered / validations that got no PATH_RESPONSE in time: a client's new path the proxy then left for the old one, or a path the proxy probed |
| `quic.<scope>.stray_datagrams` | counter | datagrams from an address a connection takes no packets from, dropped: a client's new address during the handshake, or a server's that is not the one it connected to |
| `quic.<scope>.stateless_reset_received`, `dropped_datagrams` | counter | connections ended by a stateless reset; datagrams dropped because a connection fell behind |
| `quic.<scope>.congestion_controller.<name>` | counter | connections by congestion controller (`microproxy_congestion_controller`: `cubic`, `new_reno`, `bbr`) |
| `quic.<scope>.version_negotiation_sent`, `retry_sent`, `stateless_reset_sent`, `connections_refused` | counter | what the scope's server endpoints answered without a connection |

## Transparent QUIC and CONNECT-UDP

| stat | type | meaning |
|---|---|---|
| `quic_transparent.flows_active`, `pending_initials` | gauge | client flows known / whose ClientHello is being read or decided on |
| `quic_transparent.intercepted_total`, `relayed_total` | counter | flows intercepted (as HTTP/3, or stream by stream) / relayed untouched |
| `quic_transparent.dropped_initials.<reason>` | counter | datagrams of client flows dropped (`microproxy_drop_reason`): `cap` (a bound on pending or relayed flows, or held bytes), `malformed` (no readable ClientHello, too small), `timeout` (still pending), `refused` (no SNI, a `DROP` decision, a server that cannot be reached) |
| `quic_transparent.relay_rx_bytes_total`, `relay_tx_bytes_total` | counter | bytes relayed from clients / from servers, counted when relays end |
| `masque.udp_flows_active`, `udp_flows_total` | gauge, counter | CONNECT-UDP flows open / accepted |
| `masque.datagrams_rx`, `datagrams_tx`, `capsules_rx`, `capsules_tx` | counter | UDP payloads from / to clients, and those of them in DATAGRAM capsules (all of them over HTTP/2 and HTTP/1.1), counted when flows end |
| `masque.rx_bytes_total`, `tx_bytes_total`, `datagrams_dropped` | counter | payload bytes from / to clients, datagrams dropped by a full queue (either way, a client's flow-control window that stays closed among the causes), counted when flows end |
| `masque.flow_rejected.<reason>` | counter | CONNECT-UDP requests refused (`microproxy_reject_reason`): `limit` (too many flows) or `policy` (no direct route, a filter's answer) |
| `masque.quic.*` | | as `quic_transparent.*`, for the QUIC inside CONNECT-UDP flows (`masque.quic.intercepted_total`, ...) |
| `quic.messages_rx`, `messages_tx` | counter | whole messages cut from the streams of QUIC intercepted stream by stream for the message hook (`streamMessage`, `on_quic_message`), and the messages it returned that the proxy framed and sent |
| `quic.framing_errors` | counter | such streams reset because a peer sent a message over the framing's limit, or bytes its framer cannot read |

## SOCKS, tunnels and WebSockets

| stat | type | meaning |
|---|---|---|
| `socks.<version>.connections_total` | counter | SOCKS clients by version (`microproxy_socks_version`: `v4`, `v5`) |
| `socks.auth_failures`, `command_not_supported` | counter | clients refused by authentication / requests for a command other than CONNECT |
| `socks.replies.<reply>` | counter | replies by SOCKS5 code (`microproxy_socks_reply`: `succeeded`, `general_failure`, `not_allowed`, `network_unreachable`, `host_unreachable`, `connection_refused`, `ttl_expired`, `command_not_supported`, `address_type_not_supported`); a SOCKS4 client's by the code it stands for |
| `tunnel.active` | gauge | tunnels open |
| `tunnel.<kind>.total` | counter | tunnels opened by kind (`microproxy_tunnel_kind`): `h1_connect`, `h2_connect`, `h3_connect`, `socks`, `forwarded` (through a chained proxy, or a session's server), `raw` (TLS relayed undecrypted, `tcp://` reverse proxying, other upgrades) |
| `tunnel.rx_bytes_total`, `tx_bytes_total`, `tunnel.duration_ms` | counter, histogram | bytes from / to clients and how long tunnels were open, counted when they close |
| `websocket.sessions_active`, `sessions_total` | gauge, counter | WebSocket sessions open / opened |
| `websocket.frames_rx`, `frames_tx`, `messages_rx`, `messages_tx` | counter | frames read and written, and messages joined for and sent after the message hook, of the sessions whose frames are parsed (those with frame or message hooks) |
| `websocket.deflate_bytes_saved` | counter | bytes permessage-deflate saved on what the proxy compressed again |
| `websocket.close_codes.<code>` | counter | Close frames by status code, `1000` to `1015` (`1005` when there is none) or `other` (`microproxy_close_code`) |

## Hooks

`hooks.<family>.*` for each family of hooks (`microproxy_hook`): `http_filters` (the
head hooks `clientToProxyRequest`, `proxyToServerRequest`, `serverToProxyResponse` and
`proxyToClientResponse`), `frame_interceptor`, `tcp` (`tcpMessage`), `udp` (`udpMessage`),
`quic_stream` (`streamData`), `quic_message` (`streamMessage`), `quic_datagram` (`datagram`),
`websocket_frame`, `websocket_message`, and `starlark` (every call into a script). The `starlark`
family is kept per script and hook function, as `hooks.starlark.<script>.<hook>.*`, tagged
`microproxy_script` (the file name without `.star`, or `--script-name`) and
`microproxy_script_hook` (`on_request`, `on_response`, `on_frame`, `on_tcp_message`, ...); a
script's stats for a hook are made on its first call.

| stat | type | meaning |
|---|---|---|
| `hooks.<family>.invocations`, `errors` | counter | calls, and calls that threw |
| `hooks.<family>.drops`, `rewrites` | counter | calls that dropped what they were given (returned null or nothing) / replaced it, or answered for the server (not for `starlark`) |
| `hooks.<family>.latency_us` | histogram | microseconds calls took, in buckets of 1, 5, 10, 25, ... 1000000 µs |
| `hooks.starlark.<script>.<hook>.steps` | histogram | interpreter steps each call ran, in buckets of 10, 100, ... up to the step limit |
| `hooks.starlark.<script>.<hook>.alloc_bytes` | histogram | about how many bytes of values each call created (an [estimate](starlark-api.md#script-budgets)), in buckets of 1 KiB, 4 KiB, 16 KiB, ... up to the budget |
| `hooks.starlark.<script>.<hook>.budget_exceeded.<kind>` | counter | calls stopped by a budget: `steps`, `memory` or `time` (`microproxy_budget`) |

The clock is read only with metrics on (a script call also reads it for its deadline and its
exchange's totals). A hook that changes what it was given in place, rather than returning
something else, counts as neither a drop nor a rewrite.
