# Chained proxies

How MicroProxy forwards traffic through other proxies: upstream HTTP, HTTPS and SOCKS proxies
chosen from URLs, `NO_PROXY` rules or the environment, failover and backoff between them, and what
happens when a client's own proxy sits behind an intercepting MicroProxy. Use this page to put
MicroProxy in front of (or behind) a corporate proxy.

Chained proxies are HTTP (with Basic credentials, optionally over TLS, spoken to in HTTP/1.1 or
[HTTP/2](#http2-to-chained-proxies)), SOCKS4a and SOCKS5 (with username/password). A `ChainedProxyManager` chooses them per request, as a list of candidates: the
proxy falls back to the next proxy or a direct connection when one fails, optionally with
exponential backoff between attempts. `UpstreamProxyManager` configures them from proxy URLs,
`NO_PROXY` rules or the environment; a [Starlark script's `upstream` hook](../reference/starlark-api.md)
can choose them too.

## Upstream proxies and NO_PROXY

`UpstreamProxyManager` is a `ChainedProxyManager` configured the way command-line clients are:

- **Upstreams:** one proxy URL for plain HTTP and optionally another for HTTPS/CONNECT:
  `http://user:pw@proxy:3128`, `https://...` (TLS to the proxy), `h2://...` and `h2c://...`
  ([HTTP/2 to the proxy](#http2-to-chained-proxies)), `socks4://`, `socks5://`.
- **Bypass:** `NoProxyRules` takes curl's `NO_PROXY` syntax: `*`, domain suffixes
  (`example.com`, `.example.com`, `*.example.com`), IP literals, CIDR ranges and `:port`
  qualifiers. Addresses are only compared when the request names an IP literal, so no DNS
  lookups happen.
- **Environment:** `UpstreamProxyManager.fromEnvironment(System.getenv())`, `--env-proxy` or
  `use_env_proxy=true` read `http_proxy`, `https_proxy`, `all_proxy` and `no_proxy` like curl
  does. Upper-case `HTTP_PROXY` is ignored, as curl ignores it, because CGI servers set it from a
  request header.

```bash
java -jar microproxy.jar --upstream-proxy http://proxy.corp:3128 --no-proxy "localhost,.corp,10.0.0.0/8"
```

For servers or proxies signed by a private CA, `SslContexts.systemDefaultPlus(caCert)` trusts the
JDK's roots plus extra anchors and keeps host-name checks. Use it as the MITM manager's upstream
context, or as a chained proxy's.

### Retries and backoff

When a connection through one chained proxy fails (refused, timed out, its name does not resolve,
its TLS handshake or `CONNECT` fails), the proxy tries the next candidate the
`ChainedProxyManager` offered, which may be a direct connection. By default it moves on at once.
`withChainedProxyRetryBackoff(initial, max)` (or `chained_proxy_backoff_initial_ms` and
`chained_proxy_backoff_max_ms`, or `--chained-proxy-backoff <initial-ms>[:<max-ms>]`) waits in
between, so a flapping upstream is not hammered:

```java
MicroProxy.bootstrap()
        .withChainProxyManager(upstreams)
        .withChainedProxyRetryBackoff(Duration.ofMillis(100), Duration.ofSeconds(2))
        .start();
```

```bash
java -jar microproxy.jar --upstream-proxy http://proxy.corp:3128 --chained-proxy-backoff 100:2000
java -jar microproxy.jar --config proxy.properties --chained-proxy-backoff 0   # turn off the file's backoff
```

Without a maximum, the property and the flag cap the wait at 8 × the initial one; `0` on the
command line turns waiting off, overriding a properties file.

- Before attempt `n + 1` it waits a random time between zero and `initial * 2^(n-1)`, capped at
  `max` ("full jitter", so clients that failed together do not retry together).
- It never waits before the first attempt or after the last one.
- It stops waiting, and gives up on the request, if the client disconnects meanwhile. Once the
  client has sent more bytes (a request body, a pipelined request) a disconnect can no longer be
  seen, and the rest of the wait is a plain sleep.
- The waits of one request add up to at most 30 seconds or the connect timeout, whichever is
  less, so a long candidate list cannot hold a request for minutes. Once that budget is spent,
  the remaining candidates are tried without waiting.
- The waiting counts towards the connect phase of `FlowContext.timings()`; it fires no callbacks,
  only a `DEBUG` log line.

## HTTP/2 to chained proxies

A chained HTTP proxy is spoken to in HTTP/1.1 by default: a connection of its own for each
tunnel, and plain-HTTP requests on (pooled) connections one at a time. A chained proxy that speaks
HTTP/2 can carry all of them as streams of a few shared connections instead (RFC 9113 section
8.5), as forward proxies such as MicroProxy itself (on its TLS listener, where HTTP/2 is on by default,
or with `--http2-cleartext`) do. It is chosen per proxy: the `h2://` and `h2c://` schemes in a proxy URL,
or `ChainedProxy.http2()`, which is `false` by default.

| Proxy URL | Means | Bootstrap |
|---|---|---|
| `h2://[user:pw@]host[:port]` | TLS to the proxy (port 443 by default), offering `h2` and `http/1.1` with ALPN | `http2()` and `requiresEncryption()` return `true` |
| `h2c://[user:pw@]host[:port]` | HTTP/2 with prior knowledge over plain TCP (port 80 by default) | `http2()` returns `true` |

Proxy URLs are taken by `--upstream-proxy` and `--upstream-https-proxy`, the `upstream_proxy` and
`upstream_https_proxy` properties, `http_proxy`, `https_proxy` and `all_proxy` (`--env-proxy`),
`UpstreamProxyManager.proxy(url)` and a script's `upstream()`.

```bash
java -jar microproxy.jar --upstream-proxy h2://alice:s3cret@proxy.corp:443 --mitm
java -jar microproxy.jar --upstream-proxy h2c://127.0.0.1:3128
```

- **What takes a stream.** Every `CONNECT` the proxy sends the chained proxy is a stream: a
  client's `CONNECT` it relays, the tunnel of an intercepted one (its TLS with the server, and
  HTTP/2 with the server if both choose it, then run inside the stream), the tunnel it opens to
  [originate TLS](forward-proxy.md#tls-origination-https-uris-without-connect) for an `https://`
  request, and the tunnels to [a client's own proxy](#in-front-of-an-http-or-https-proxy) reached
  through it. A
  plain-HTTP request is a stream too, as a proxy request: `:scheme http`, `:authority` the
  server's, and `:path`. A WebSocket upgrade over plain HTTP still goes over HTTP/1.1.
- **Shared connections.** A connection to the chained proxy is keyed by the proxy alone (its
  address, TLS, `SSLContext` instance, credentials and local address), never by the server, and
  carries the streams of every client connection; it is never coalesced. The proxy reads the
  chained proxy's SETTINGS first and opens no more streams than its
  `SETTINGS_MAX_CONCURRENT_STREAMS`; when every connection is full it opens another. A burst of
  exchanges waits for the connection one of them is making. Connections close after the idle
  timeout without streams.
- **Negotiation.** Over TLS, `h2` and `http/1.1` are offered with ALPN (before the proxy's
  `configure`, which may change that); a chained proxy that chooses `http/1.1`, or no protocol,
  is spoken to in HTTP/1.1, as without HTTP/2. An `h2c://` proxy must speak HTTP/2 with prior
  knowledge: one that does not fails as an unreachable proxy does.
- **Credentials.** The proxy's credentials go on every stream, as `proxy-authorization` (Basic).
  As over HTTP/1.1, a `407` to a plain-HTTP request is relayed to the client (without its
  challenge, which is not the client's to answer), and a `CONNECT` the chained proxy refuses is a
  `502`.
- **Tunnels.** A tunnel's bytes are DATA frames, flow controlled both ways: a client that stops
  reading stops the chained proxy's stream, never the connection. One side's end is END_STREAM
  (and the chained proxy's END_STREAM ends the client's side), and a reset of the stream fails
  the tunnel as a reset socket does. The PROXY protocol header (`--send-proxy-protocol`) goes into
  the tunnel, as through an HTTP/1.1 chained proxy.
- **Failover.** Failing to reach the chained proxy (refused, timed out, TLS failed, its preface
  not HTTP/2) or a refused `CONNECT` moves on to the route's next proxy (or a direct connection),
  with the [backoff](#retries-and-backoff) and the `failover` and `backoff_*` stats, as over
  HTTP/1.1. A GOAWAY or a connection failure affects only the streams of that connection; others
  go on. A stream the chained proxy never processed (above GOAWAY's last stream id, or answered
  `REFUSED_STREAM`) is sent again on another connection, and after two such streams an exchange
  moves on to the next proxy. A stream that started (a tunnel that opened, a request whose
  response was under way) is not sent again: it fails as with any server connection, with the
  response flags that say so (`UC` when the connection went away).
- **Stats and logs.** The chained proxy's cluster (`cluster.<host_port>.*`) counts its HTTP/2
  connections in `upstream_cx_total` and `upstream_cx_http2_total` (not each tunnel), the
  requests on them in `upstream_rq_*`, and their bytes, frames included, in
  `upstream_cx_rx_bytes_total` and `_tx_bytes_total`; `http2.upstream.*` counts their streams
  with those to servers. In the access log, `%UPSTREAM_CLUSTER%` names the chained proxy and
  `%MP_UPSTREAM_PROTOCOL%` says `HTTP/2` (`FlowRecord.upstreamProtocol()`, and
  `microproxy.upstream_protocol` in [OpenTelemetry](../observability/opentelemetry.md)).
- **Needs** the `http2-codec` jar (bundled in the `-all` jar): an `h2://` or `h2c://` URL without
  it fails at startup; a `ChainedProxy` whose `http2()` says `true` is spoken to in HTTP/1.1.

## In front of an HTTP or HTTPS proxy

A client may be set up to use an HTTPS proxy, such as a corporate egress proxy `corp.example:443`
that speaks TLS (and often HTTP/2) on its listener, with MicroProxy in front of it intercepting
the client's `CONNECT corp.example:443`. Inside that session the client asks what it takes for its
proxy for a tunnel per site: a `CONNECT` stream over HTTP/2 (`:authority github.com:443`, no
`:protocol`), or `CONNECT github.com:443 HTTP/1.1` over HTTP/1.1, and plain-HTTP URIs as proxy
requests: `GET http://example.com/ HTTP/1.1` (absolute-form), or a stream with `:scheme http` and
`:authority example.com`.

A client may use a plain-HTTP forward proxy the same way, such as a Squid at `corp.example:3128`:
it sends `CONNECT corp.example:3128`, then speaks plain HTTP in the tunnel, which MicroProxy (with
a MITM manager) serves as a plain session ([Deciding what to
intercept](mitm.md#deciding-what-to-intercept-the-clienthello)). Inside it the client sends what it would
send that proxy: absolute-form requests, and `CONNECT github.com:443 HTTP/1.1`.

In both cases MicroProxy forwards these proxy requests to the session's server, as the client
intended, rather than to `github.com` or `example.com` itself, which would bypass the proxy the
client chose. (Without a MITM manager, the `CONNECT` to the proxy is a tunnel, and everything in it
reaches the proxy untouched.)

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        // HTTP/2 to servers (on by default) puts CONNECT streams on the HTTP/2 connection to the proxy
        .withFiltersSource((request, ctx) -> new HttpFiltersAdapter(request, ctx) {
            @Override
            public boolean proxyToServerAllowMitm() {
                // Intercept the session with the proxy, but not the tunnels through it.
                return ctx.forwardedVia().isEmpty();
            }
        })
        .start();
```

- **Upstream.** The session's server is a chained proxy for the tunnel. When MicroProxy's
  connection to an HTTPS proxy negotiated HTTP/2 (`withHttp2Upstream`, on by default), the `CONNECT` is a stream
  on that connection, multiplexed with the session's requests. Otherwise it goes on an HTTP/1.1
  connection to it, over TLS to an HTTPS proxy and plain TCP to an HTTP one: an idle one of the
  session's, or one made as the session's are (the same routes, the MITM manager's trust and
  `configureServerSocket`, the same isolation; through an HTTP chained proxy, a tunnel to it).
  Connections that carry a client's credentials for the proxy are never pooled or shared with
  other clients.
- **Proxy requests.** An absolute-form request goes to the proxy as it was sent: absolute-form,
  with `Host` from its URI; over HTTP/2 to an HTTPS proxy, as `:scheme http` and the target's
  `:authority`. It goes on the session's own connections to the proxy, never pooled ones (nor ones
  that hand an HTTP chained proxy its requests), by the routes to the proxy.
- **Fields, both ways.** The client's fields go with the `CONNECT` or the proxy request,
  `Proxy-Authorization` included (those credentials are for the proxy; MicroProxy's own
  authentication covered the outer `CONNECT`), without hop-by-hop fields and with `Via`. The
  proxy's answer reaches the client as it was sent: a `407` with its `Proxy-Authenticate`
  challenge, a `403`, the response it fetched, or the `2xx` that opens the tunnel. An HTTP/1.1
  client can retry on the same session after a refusal.
- **Filters.** A proxy request is a request of the session: `clientToProxyRequest`,
  `proxyToServerRequest` (which may rewrite a `CONNECT`'s target), then `serverToProxyResponse`
  and `proxyToClientResponse` for the proxy's answer; a short-circuit response (a `403`, say)
  rejects it. `FlowContext.forwardedVia()` names the proxy (`host:port`) for it and for the
  requests inside the tunnel a `CONNECT` opens; scripts see `ctx.forwarded_via`.
- **The client's URIs, and the filters'.** Only an absolute URI the client sent itself makes a
  proxy request. A filter or script that gives a request an absolute URI of its own (`MapRemote`,
  `req.uri = "https://..."`) sends it straight to that URI's server, as in any intercepted
  session, and `forwardedVia()` is then empty; one that leaves the client's URI as it was keeps it
  a proxy request. A client's absolute-form request to a server that is not a proxy is legal, if
  rare, and goes there as sent too: the client chose that server.
- **The tunnel.** Once the proxy has opened it, the tunnel goes on as a `CONNECT` to MicroProxy
  would ([Deciding what to intercept](mitm.md#deciding-what-to-intercept-the-clienthello)), with the
  proxy's tunnel as the way to the target. Without interception for the target
  (`proxyToServerAllowMitm`, `allow_mitm` in scripts, an ignore rule for the target, or a MITM
  manager that declines), its bytes are relayed as they are. Otherwise the client's first bytes
  decide: a ClientHello goes through the host rules (with its SNI), `shouldIntercept` and
  `proxyToServerAllowMitm(clientHello)`, and when intercepted, MicroProxy's own TLS to the target
  runs inside the tunnel, offering the client's ALPN protocols, and the client gets the target's
  choice; plain HTTP is served as HTTP, its requests going through the filters; anything else, a
  declined ClientHello, a [TCP host](tcp-hooks.md#raw-tcp-streams) or a server that speaks first (noticed
  through the tunnel) is relayed as it is, through the TCP hooks, as is intercepted TLS that does
  not carry HTTP. Relayed bytes go under flow control both ways; END_STREAM and half-closes go
  through (over an HTTP/1.1 TLS connection to the proxy, where TLS 1.3 allows one). Every other
  connection to the target, for the requests of an intercepted or plain session in the tunnel, is
  a tunnel through the same proxy, opened with the same `CONNECT` fields, never pooled;
  `FullFlowContext.getChainedProxy()` names the proxy. A target that does not speak TLS to a
  client that does gets a plain tunnel, a new one.
- **Resets.** A client's reset of the stream resets the stream to the proxy (or closes the
  connection to it), and once the tunnel is open it is not a rapid reset. A reset from the proxy,
  or its connection closing, resets the client's stream.

Over HTTP/2, `:scheme https` requests for another authority still get `421` ([connection
coalescing](http2.md#connection-coalescing)), and so does a WebSocket's extended `CONNECT`, which is not forwarded.
