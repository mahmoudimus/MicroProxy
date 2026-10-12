# Access-log format

The access log's format strings: how operators render as text and JSON, every operator, the filter
syntax, and the presets. Use this page when writing `--access-log-format`, `--access-log-json` or
`--access-log-filter`; [Access logs](../observability/access-logs.md) explains how to turn the log
on, and [Response flags](response-flags.md) lists the flags and details.

## Text and JSON

An operator whose value is unavailable renders `-`, as does an operator this
proxy does not know; `%%` is a literal `%`; `%OPERATOR(...):N%` keeps the first `N` characters. In
text formats, control characters in values are escaped (`\n`, `\t`, `\u0001`), so a header cannot
break a line. A trailing newline (Envoy's formats end with one) is dropped. In the JSON form a value
that is a single operator keeps the operator's type, as in Envoy: numbers for codes, sizes and
durations, `true` or `false` for flags, `null` when unavailable; other values are JSON strings.
Nested objects, numbers and booleans in the dictionary are written as they are.

## Operators

| operator | value |
|---|---|
| `%START_TIME%`, `%START_TIME(fmt)%` | when the request started, UTC; default `2026-10-08T12:34:56.789Z`. `fmt` takes `%Y %y %C %m %d %e %j %H %I %M %S %p %b %B %a %A %u %w %z %Z %s %T %F %D %R`, and `%f` or `%1f`..`%9f` for fractions of a second |
| `%REQ(X?Y):N%`, `%REQUEST_HEADER(...)%` | the request header `X`, else `Y`; pseudo-headers `:method`, `:path` (no scheme or authority), `:authority`, `:scheme`, `:protocol`. The request as the client sent it |
| `%RESP(X?Y):N%`, `%RESPONSE_HEADER(...)%` | the response header (`:status` too) |
| `%TRAILER(X?Y):N%`, `%RESPONSE_TRAILER(...)%` | the response trailer |
| `%PROTOCOL%` | `HTTP/1.1`, `HTTP/1.0`, `HTTP/2` or `HTTP/3`: the client's |
| `%RESPONSE_CODE%` | the status the client got; `0` for none (a reset, a refused SOCKS client, a QUIC flow) |
| `%RESPONSE_CODE_DETAILS%` | why: see [Response flags and details](response-flags.md) |
| `%RESPONSE_FLAGS%`, `%RESPONSE_FLAGS_LONG%` | the flags, as `UF,URX` or `UpstreamConnectionFailure,UpstreamRetryLimitExceeded` |
| `%DURATION%` | milliseconds from the first byte of the request to the last of the response; for tunnels and flows, until they closed |
| `%REQUEST_DURATION%` | until the request was sent on to the server |
| `%RESPONSE_DURATION%` | until the first byte of the server's response |
| `%RESPONSE_TX_DURATION%` | from the first byte of the server's response to the last byte to the client |
| `%COMMON_DURATION(A:B:P)%` | between two points, in `ms`, `us` or `ns`: `START_TIME`, `DS_RX_BEG`, `DS_RX_END`, `US_CX_BEG`, `US_CX_END`, `US_HS_END`, `US_TX_END`, `US_RX_BEG`, `US_RX_END`, `DS_TX_END` |
| `%DOWNSTREAM_HANDSHAKE_DURATION%` | milliseconds of the TLS handshake with the client |
| `%BYTES_RECEIVED%`, `%BYTES_SENT%` | body bytes from and to the client; for tunnels and flows, the payload each way |
| `%UPSTREAM_WIRE_BYTES_SENT%`, `%UPSTREAM_WIRE_BYTES_RECEIVED%` | bytes to and from the server connection, heads and framing included |
| `%UPSTREAM_HOST%`, `%UPSTREAM_REMOTE_ADDRESS%` (`_WITHOUT_PORT`) | the server or chained proxy connected to |
| `%UPSTREAM_CLUSTER%` | the chained proxy's `host:port`, else the server's |
| `%UPSTREAM_LOCAL_ADDRESS%` (`_WITHOUT_PORT`) | the proxy's end of that connection |
| `%UPSTREAM_TRANSPORT_FAILURE_REASON%` | why the TLS handshake with the server failed |
| `%UPSTREAM_TLS_VERSION%`, `%UPSTREAM_TLS_CIPHER%`, `%UPSTREAM_PEER_SUBJECT%`, `%UPSTREAM_PEER_ISSUER%` | the TLS session with the server |
| `%DOWNSTREAM_REMOTE_ADDRESS%` (`_WITHOUT_PORT`), `%DOWNSTREAM_REMOTE_PORT%` | the client (the PROXY protocol's source, when one was accepted) |
| `%DOWNSTREAM_LOCAL_ADDRESS%` (`_WITHOUT_PORT`), `%DOWNSTREAM_LOCAL_PORT%` | the proxy's end of the client connection |
| `%DOWNSTREAM_TLS_VERSION%`, `%DOWNSTREAM_TLS_CIPHER%`, `%DOWNSTREAM_PEER_SUBJECT%`, `%DOWNSTREAM_PEER_ISSUER%`, `%DOWNSTREAM_PEER_FINGERPRINT_256%` | the TLS session with the client (listener or interception) and its certificate |
| `%REQUESTED_SERVER_NAME%` | the SNI the client sent |
| `%CONNECTION_ID%`, `%STREAM_ID%` | the client connection (as in `[conn <id>]` log lines) and the HTTP/2 or HTTP/3 stream |
| `%UNIQUE_ID%` | a random UUID per exchange, made only when a format asks for it; with [OpenTelemetry](../observability/opentelemetry.md), the exchange's `X-Request-Id` |
| `%TRACE_ID%`, `%SPAN_ID%` | the exchange's trace id and the id of the proxy's span for it, with a tracer ([OpenTelemetry](../observability/opentelemetry.md)) |
| `%HOSTNAME%` | this host's name |
| `%TLS_JA3_FINGERPRINT%`, `%TLS_JA4_FINGERPRINT%` | JA3 and JA4 of the client's ClientHello (JA4 starts with `q` for QUIC); `-` when the proxy read none |
| `%MP_RESPONSE_SOURCE%` | `SERVER`, `PROXY`, `FILTER`, `CACHE` or `REPLAY` |
| `%MP_FLOW%` | `h1`, `h2`, `h3`, `tunnel`, `socks`, `websocket`, `tcp`, `udp`, `quic` or `quic_relay` |
| `%MP_EARLY_DATA%`, `%MP_TRANSPARENT_QUIC%` | whether the request came as 0-RTT data; whether the client came to the transparent QUIC listener |
| `%MP_SOCKS_VERSION%`, `%MP_FORWARDED_VIA%` | the SOCKS version; the client's own proxy the request went through |
| `%MP_USER%`, `%MP_URL%`, `%MP_UPSTREAM_STATUS%` | the authenticated user; the absolute URL; the status the server sent (before a filter changed it) |
| `%MP_UPSTREAM_PROTOCOL%` | the protocol spoken to `%UPSTREAM_CLUSTER%`: to a chained proxy `HTTP/1.1` or `HTTP/2` (for a tunnel, that of its `CONNECT`), `SOCKS4` or `SOCKS5`; else to the server `HTTP/1.1`, `HTTP/2` or `HTTP/3`; `-` for a tunnel straight to the server |
| `%MP_TIMING(phase)%` | `dns`, `connect`, `tls`, `client_tls`, `ttfb` or `total`, in milliseconds with three decimals |
| `%MP_SCRIPT_CALLS%`, `%MP_SCRIPT_TIME%` | the exchange's calls into [scripts](starlark-api.md#script-budgets), and the milliseconds they took together, with three decimals |
| `%MP_SCRIPT_STEPS%`, `%MP_SCRIPT_ALLOC%` | the interpreter steps those calls ran, and about how many bytes of values they created (an estimate) |

## Filters

| filter | Java | compact syntax |
|---|---|---|
| status code | `statusCode(Comparison.GE, 500)` | `status>=500` (also `=`, `!=`, `<=`, `>`, `<`) |
| duration | `duration(Comparison.GE, 1000)` | `duration>=1000`, `duration>=1s` |
| not a health check | `notHealthCheck()` (`/healthz`, or Envoy's `User-Agent: Envoy/HC`), `notHealthCheckPath("/ready")`, `notHealthCheckHeader("X-Health-Check")` | `not_health_check`, `not_health_check(/ready)`, `not_health_check(header=x-health-check)` |
| response flags | `responseFlag()` (any), `responseFlag(UPSTREAM_OVERFLOW, ...)` | `response_flag`, `response_flag(UO,UF)` |
| request header | `header("x-debug")` (present), `header("user-agent", "curl/.*")` (whole value), `headerEquals(...)` | `header(x-debug)`, `header(user-agent~curl/.*)`, `header(x-env=prod)` |
| sampling | `runtime(10)` (by `X-Request-ID` when there is one, else at random) | `runtime(10)`, `sample(10%)` |
| combinators | `allOf(...)`, `anyOf(...)`, `a.and(b)`, `a.or(b)`, `a.negate()` | `&&` / `and`, `\|\|` / `or`, `!` / `not`, parentheses |

## Presets

`LogFormat` names nine formats from LittleProxy, now presets of the same formatter, and Envoy's
default: `CLF`, `ELF` (combined), `JSON`, `SQUID`, `W3C`, `LTSV`, `CSV`, `HAPROXY`,
`JSON_EXTENDED` and `ENVOY`. `new ActivityLogger(LogFormat.CLF)` (or `--activity-log-format clf`,
or `--access-log-format clf`) uses one; each constant's documentation shows its format string.
`JSON_EXTENDED` adds `source`, `upstream_status`, `ttfb_ms`, `total_ms`, `dns_ms`, `connect_ms`,
`tls_ms`, `response_flags`, `response_code_details` and `flow` to the `JSON` line.

## Limitations

Times are milliseconds: `%f` digits beyond them are zeros. `%REQUEST_DURATION%`
ends when the request was sent on to the server, and `DS_RX_END` is that point too.
`%BYTES_RECEIVED%` and `%BYTES_SENT%` count body bytes, not heads. Upstream wire bytes are what
passes the proxy's connection to the server: over TLS, the decrypted bytes.
`%DOWNSTREAM_LOCAL_ADDRESS%` is unknown for clients of the HTTP/3 listener. `%HOSTNAME%` is looked
up once. A transparent QUIC flow that is intercepted as HTTP/3 has a line per request, none of its
own.
