# Security

What MicroProxy does to stay safe with untrusted clients and servers, and what an operator has to
decide: who may reach the proxy, which servers clients may reach through it, what it trusts, and
what it logs. Read this before exposing a proxy beyond your own machine. Each section links to the
guide with the details.

## Exposure: who can use the proxy

- **Loopback by default.** The listener accepts connections on loopback only; `--server`
  (`allow_local_only=false`) listens on every interface. Put a proxy that listens on a network
  behind [proxy authentication](guides/authentication.md), a firewall, or both.
- **Proxy authentication** checks Basic credentials or any scheme of your own, per connection or
  per request, and removes `Proxy-Authorization` from every request before filters see it, so it
  is never forwarded ([Proxy authentication](guides/authentication.md)). SOCKS5 clients
  authenticate with a username and password through the same authenticator
  ([SOCKS](guides/socks.md#authentication)). Script authenticators fail closed
  ([Authenticating clients](guides/scripting.md#authenticating-clients)).
- **Concurrency limits** keep one client, user or target from taking every connection:
  `--max-concurrent-per-client` or a [`ConcurrencyLimiter`](guides/concurrency-limiting.md).
- **PROXY protocol** makes the address a header names the client's, for logs, authorization and
  limits alike. Required mode (`--accept-proxy-protocol`) is safe when only load balancers can
  reach the listener. Optional mode (`--proxy-protocol-mode optional`) lets any client that can
  connect claim any address by sending a header: use it only behind a load balancer on a trusted
  network, and name the load balancers with `--proxy-protocol-trusted-sources`, so that a header
  from any other peer closes its connection. `%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%` logs the TCP
  peer either way ([PROXY protocol](guides/forward-proxy.md#proxy-protocol)).
- **The admin API** can drain and stop the proxy. It listens on `127.0.0.1` unless told otherwise,
  takes a token (`--admin-token`, `--admin-token-file`), answers on loopback only to `Host`s that
  are loopback names (against DNS rebinding), refuses `POST`s that carry an `Origin`, and redacts
  secrets in `/config_dump` and `/server_info` ([Admin security](observability/admin.md#security)).

## Request parsing

The HTTP/1 parser rejects `Transfer-Encoding` together with `Content-Length`, conflicting
lengths, obs-fold in requests, and oversized lines and headers; header values are validated
against CR/LF injection; and `Host` is replaced by the absolute-form authority. The limits are
`max_initial_line_length` (8192), `max_header_size` (16384) and `max_chunk_size` (16384)
([Configuration properties](reference/properties.md)). When the proxy answers itself, its short
plain-text body never echoes the request ([Failure responses](guides/filters.md#failure-responses)).
`withLittleProxyCompatibility()` does not relax any of this.

A request with both `Transfer-Encoding` and `Content-Length` is the classic request smuggling
vector: two hops that frame it differently disagree on where the next request starts. RFC 9112
section 6.1 lets a server reject it, which MicroProxy does (`400`), as LittleProxy does through
Netty's decoder. Some LittleProxy forks accepted such requests; for clients that send them,
`--allow-chunked-length` (`allow_chunked_length`, `withAllowChunkedLength(true)`) accepts them as
the RFC describes, and only when the rest of the framing is sound: `chunked` exactly once, as the
final coding, a `Content-Length` valid on its own, HTTP/1.1, and neither a `CONNECT` nor an
`Upgrade`. The `Content-Length` is removed
before filters see the request, the body is read by its chunked coding, and the client connection
is closed after the response, so whatever followed the body is never read as a request. Accepted
requests are flagged (`FlowContext.isChunkedWithContentLength()`, `%MP_CHUNKED_LENGTH%`, the
`downstream_rq_chunked_length` counter) so they can be watched. A server's response with both
headers is always framed by its transfer coding, its `Content-Length` dropped, as RFC 9112
section 6.3 requires of an intermediary.

## Denial of service

Every input has a bound, and a peer that exceeds it loses its stream or connection, not the proxy:

| Area | Protections | Details |
|---|---|---|
| HTTP/2 (on by default over TLS, to clients and servers; `--no-http2`, `--no-http2-upstream`) | stream, header-list, CONTINUATION, HPACK and flow-control limits; Rapid Reset (CVE-2023-44487), PING, SETTINGS, RST_STREAM, WINDOW_UPDATE and empty-frame floods; idle and stalled-write timeouts | [HTTP/2 limits](guides/http2.md#limits) |
| HTTP/3 | QUIC's stream limits and flow control, field-section and QPACK limits, unknown frame and stream floods, Rapid Reset, optional address validation with Retry | [HTTP/3 limits](guides/http3.md#limits) |
| TLS | a handshake timeout (`--tls-handshake-timeout`, 10 s) on both sides; a ClientHello is read up to 64 KiB within that timeout | [Deciding what to intercept](guides/mitm.md#deciding-what-to-intercept-the-clienthello) |
| HTTP/1 request heads | a total 30 s deadline from the first byte; expired heads receive `408` and the connection closes. Set `--request-head-timeout 0` to disable | [Request parsing](security.md#request-parsing) |
| SOCKS | the whole handshake within the TLS handshake timeout; field lengths bounded | [SOCKS hardening](guides/socks.md#hardening) |
| WebSockets | frames over 1 MiB stream through unbuffered; messages, joined or inflated, over 16 MiB close the connection with 1009 (decompression bombs included) | [WebSockets](guides/websockets.md) |
| Bodies | decoding is capped at 64 MiB to defuse compression bombs; a Brotli body with bytes after its end, or a command past its meta-block, is rejected as the reference decoder does; buffered requests over the filters' limit get `413` | [Rewriting bodies](guides/rewriting-bodies.md) |
| Transparent QUIC and CONNECT-UDP | bounded pending clients, per-IP flows, held datagrams and queues; datagrams past a bound are dropped | [Transparent QUIC](guides/transparent-mode.md#transparent-quic), [CONNECT-UDP](guides/masque.md) |
| QUIC message framing | messages over `--quic-max-message-size` reset their stream | [QUIC message framing](guides/quic-hooks.md#quic-message-framing) |
| Scripts | each hook call is bounded in steps, time and allocation, and sandboxed (no files, network or processes) | [Budgets and measurements](reference/starlark-api.md#script-budgets) |
| Idle connections | `--idle-timeout` (70 s) closes idle client and server connections and tunnels | [Command-line flags](reference/cli.md) |

## Which servers clients can reach (SSRF)

- **Forward proxy:** the client chooses the server, by design, as with any forward proxy. If
  clients must not reach internal addresses through it, refuse them in a filter
  (`clientToProxyRequest`), a script or a [`BlockList`](guides/addons.md), or resolve names
  yourself in `proxyToServerResolutionStarted`, which may return the address to connect to; or
  route everything through an upstream with [chained proxies](guides/chained-proxies.md).
- **Reverse proxy:** the client never picks the server. Absolute-form URIs are made origin-form
  for the upstream, `:authority` chooses nothing, and `CONNECT` is refused
  ([Reverse proxy](guides/reverse-proxy.md)).
- **Transparent proxy:** the SNI or `Host` names the server; put the proxy where only the clients
  it serves can reach it ([Transparent mode](guides/transparent-mode.md)).
- **TLS origination:** `https://` URIs sent without `CONNECT` are fetched over TLS the proxy opens
  (on by default). Turn it off with `--no-originate-tls` when plain-HTTP clients should reach TLS
  servers only through tunnels: host rules and `proxyToServerAllowMitm` do not apply to these
  requests, and on the plain listener the request crosses the network in clear text
  ([TLS origination](guides/forward-proxy.md#tls-origination-https-uris-without-connect)).

## Trust settings

- **Upstream certificates** are validated against the JDK's trust store by default, by the MITM
  manager's server context when one is configured. `--mitm-trust-all` (`SslContexts.trustAll()`)
  turns validation off: use it only for testing. For private CAs, add anchors with
  `SslContexts.systemDefaultPlus(caCert)` instead ([MITM](guides/mitm.md#turning-interception-on)).
- **The interception CA** signs certificates every client that trusts it will accept. `--mitm`
  keeps its key in `microproxy-ca.p12`, protected by `--mitm-ca-password` (default `microproxy`):
  set your own password, keep the file private, and trust its certificate only on clients you
  control.
- **TLS versions:** only TLS 1.3 and 1.2 are allowed by default on every TLS connection
  ([TLS protocol versions](guides/mitm.md#tls-protocol-versions)).
- **Browser fingerprints:** captured ClientHello suites stay on the wire, but the fingerprint
  client's acceptance policy checks the selected cipher, group, signature and certificate keys.
  CBC record protection is disabled. Cipher restrictions and `SSLParameters` algorithm constraints
  apply to full and resumed handshakes; JDK TLS disabled-algorithm restrictions are checked too.
  Named-group and signature-scheme lists on `SSLParameters`, endpoint-identification modes other
  than HTTPS, and unsupported disabled-algorithm syntax are rejected explicitly. With a custom
  algorithm constraint on JDK 21, the hybrid ML-KEM group is refused when its complete key cannot
  be inspected. Delegated-credential and client-certificate sessions require full authentication
  on subsequent TCP connections. See the
  [timing review and local assessment](security-timing-audit.md) for the comparison inventory,
  advisory references and limits of timing measurements.
- **Traffic keys:** the fingerprint TLS client's AES-GCM keys are capped at 2^23 records per
  direction. TLS 1.3 writes rotate traffic keys before reaching the cap, including within large
  application writes. Reads require the peer to update its keys before the cap; TLS 1.2
  connections must reconnect before it. Exhausted counters fail closed.
- **Server names:** a server that rejects the name the proxy sends (SNI) is retried without it
  only with `--tls-retry-without-sni` (on by default in LittleProxy compatibility mode); a filter
  may send another name or check the certificate against another host
  (`proxyToServerTlsIdentity`). Neither skips a check: the certificate is still validated and
  matched against the intended (or the filter's) host, since SNI authenticates nothing
  ([Server TLS failures](guides/mitm.md#server-tls-failures)).
- **DNS:** `--dnssec` validates answers from the root down and never falls back to unvalidated DNS
  ([DNSSEC](guides/dnssec.md)). Validation has a work budget shared by the whole resolution,
  including address-family fallback, aliases and the trust chain. Exhausting the budget or
  exceeding the NSEC3 iteration ceiling fails validation. Answer, zone-key and delegation caches
  each have a size limit and discard expired entries.
- **0-RTT:** early data from HTTP/3 clients can be replayed, so it is off by default
  (`--http3-0rtt`); when on, methods that are not safe to repeat get `425 Too Early`
  ([Session resumption and 0-RTT](guides/http3.md#session-resumption-and-0-rtt)).

## Sensitive data

- **Request logging** redacts `Authorization`, `Cookie`, `Set-Cookie` and `Proxy-Authorization`
  by default, but `BODY` logs payloads unredacted ([Request/response
  logging](observability/request-logging.md)). WARC files and HAR files record traffic complete and
  unredacted ([WARC recording](guides/warc.md), [HAR files](guides/addons.md#har-files)).
- **Tracing headers** can be removed from requests sent upstream (`--strip-tracing-headers`)
  ([Removing tracing headers](guides/forward-proxy.md#removing-tracing-headers)), and
  `--otel-ignore-incoming` makes the proxy a trust boundary for trace context
  ([OpenTelemetry](observability/opentelemetry.md#propagation)).
- **Secrets on the command line** are visible to other local users (`ps`): use
  `--admin-token-file` and `--script-var-file` rather than their inline forms.
