# Response flags

Why an exchange ended as it did: the Envoy response flag and the response code details the proxy
sets for each cause. Use this page to read access logs, metrics
(`downstream_rq_response_flag.<flag>`), traces and `ctx.response_flags` in scripts.

## Response flags and details

`FlowContext.failure()`, `responseFlags()` and `responseCodeDetails()` tell why an exchange ended
as it did; trackers, filters, scripts (`ctx.failure`, `ctx.response_flags`,
`ctx.response_code_details`) and `HttpLogger` lines see them. The proxy sets these flags (the
`ResponseFlag` enum names Envoy's flags, and a filter can add one with `ctx.addResponseFlag`):

| cause | flag | details |
|---|---|---|
| connection refused, unreachable or timed out (`ConnectFailed`) | `UF` | `proxy_failure:connect_failed` |
| the server's name did not resolve (`UnresolvedHost`) | `DF` | `proxy_failure:unresolved_host` |
| TLS with the server or a chained proxy failed (`TlsFailed`) | `UF`, and `%UPSTREAM_TRANSPORT_FAILURE_REASON%` (`TlsFailed.reason()`: `certificate_revoked: ...`) | `proxy_failure:tls_failed` |
| the server did not answer in time (`ServerTimeout`) | `UT` | `proxy_failure:server_timeout` (`upstream_response_timeout` mid-response) |
| a malformed response (`BadServerResponse`) | `UPE` | `proxy_failure:bad_server_response` |
| the server closed before its response head was complete | `UC` | `proxy_failure:bad_server_response` |
| the server reset or closed mid-response | `UR` | `upstream_reset_after_response_started` |
| nowhere to send it (`NoRoute`) | `NR` | `proxy_failure:no_route` |
| the shared pool was exhausted (`NoConnectionAvailable`) | `UO` | `proxy_failure:no_connection_available` |
| a refused or malformed request (`BadRequest`), or one too large (`RequestTooLarge`) | `DPE` | `proxy_failure:bad_request`, `proxy_failure:request_too_large`, `downstream_protocol_error` |
| the client left before the response was complete | `DC` | `downstream_remote_disconnect` |
| the client reset its HTTP/2 or HTTP/3 stream | `DR` | `downstream_remote_reset` |
| a `ConcurrencyLimiter` refused it | `RL` | `concurrency_limited` |
| every chained proxy (with backoff between them) failed | `URX`, with the last one's flag | as the last failure |
| an exchange, tunnel or CONNECT-UDP flow sat idle for the idle timeout | `SI` | `stream_idle_timeout` |
| the proxy authenticator refused the client (`407`) | `UAEX` | `auth_rejected` |
| a filter aborted the exchange (returned `null`) | `LR` | `filter_aborted` |
| `425 Too Early` for a request in 0-RTT data | none | `too_early` |
| served from the cache, or by a filter's short-circuit, or from a replay | none | `cache`, `filter`, `replay` |
| the server's response, relayed | none | `via_upstream` |
| a transparent QUIC flow | none (`UAEX` when the authenticator refused it) | `quic_relayed`, `quic_dropped`, `quic_streams` |

The `ConcurrencyLimiter` answers `429` by default, as a rate limit does, so it sets `RL` rather
than `UO` (Envoy's circuit-breaker overflow, which this proxy keeps for its exhausted pool). A
`425 Too Early` has no flag: Envoy has none for it, and a custom one would be meaningless to its
tools; `too_early` in the details tells it apart. A response from the cache gets no `RFCF` either,
since the cache is no filter of Envoy's: `cache` in the details and `%MP_RESPONSE_SOURCE%` say it.
