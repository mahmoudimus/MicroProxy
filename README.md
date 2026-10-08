# MicroProxy

MicroProxy is an HTTP/HTTPS proxy for Java that can intercept and rewrite traffic. It is a
port of [LittleProxy](https://github.com/LittleProxy/LittleProxy) that drops Netty. Each
connection runs on its own **virtual thread** (Project Loom) and uses plain blocking socket I/O.

- **Runtime:** JDK 21 or newer (also tested on JDK 25).
- **Dependencies:** none at runtime. Logging goes through `System.Logger`, which can be routed to
  SLF4J/Log4j with the usual bridges.
- **Size:** about 6k lines of main code (including Javadoc), compared with LittleProxy's 11k lines plus Netty.

```java
HttpProxyServer proxy = MicroProxy.bootstrap()
        .withPort(8080)
        .withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFiltersAdapter(originalRequest, ctx) {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                        if (httpObject instanceof HttpRequest r && r.uri().contains("/blocked")) {
                            return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                    HttpResponseStatus.FORBIDDEN, "blocked by proxy");
                        }
                        return null; // continue proxying
                    }
                };
            }
        })
        .start();
```

## Why virtual threads instead of Netty

LittleProxy relies on Netty's event loops, so all of its logic runs as callbacks: pipelines,
handler swapping, a `ConnectionFlow` state machine, and manual backpressure through
`channelWritabilityChanged`. MicroProxy writes the same logic as a straight-line loop:

```
read request → filters → connect (or reuse) → write request → stream body → read response → stream back
```

Each connection gets one cheap virtual thread, so blocking calls only park that thread. A slow
peer applies backpressure simply by blocking a write. The CONNECT tunnel is two loops copying
bytes, one per direction. Tens of thousands of concurrent connections are fine.

A few rules keep this safe on JDK 21, where a virtual thread that blocks inside `synchronized`
pins its carrier thread:

- Blocking code paths use `ReentrantLock` instead of `synchronized`.
- The tests run with `-Djdk.tracePinnedThreads=short` to catch pinning.
- On JDK 24+ (JEP 491), `synchronized` no longer pins, so user filters written with
  `synchronized` are fine there too.

## Running

```bash
mvn package
java -jar target/microproxy-0.1.0-SNAPSHOT.jar --port 8080
java -jar target/microproxy-0.1.0-SNAPSHOT.jar --port 8080 --mitm   # intercept HTTPS
java -jar target/microproxy-0.1.0-SNAPSHOT.jar --help
```

`--mitm` creates (or reuses) a CA in `microproxy-ca.p12` and writes its certificate to
`microproxy-ca.pem`. To intercept HTTPS without errors, add that certificate to your client's
trust store.

### Properties file

Pass a properties file with `--config file.properties` or `MicroProxy.bootstrapFromFile(path)`.
Command-line flags override values from the file.

| key | meaning | default |
|---|---|---|
| `name` | thread / log name | `MicroProxy` |
| `port` / `address` | listen port / `host:port` | `8080` |
| `allow_local_only` | listen on loopback only | `true` |
| `transparent` | don't add `Via` or strip hop-by-hop headers | `false` |
| `idle_connection_timeout` | seconds, 0 = none | `70` |
| `connect_timeout` | milliseconds | `40000` |
| `max_initial_line_length` / `max_header_size` / `max_chunk_size` | parser limits in bytes | `8192` / `16384` / `16384` |
| `nic` | local address for outbound connections | any |
| `proxy_alias` | name in `Via` | host name |
| `allow_requests_to_origin_server` | accept origin-form requests | `false` |
| `allow_proxy_protocol` / `send_proxy_protocol` | PROXY protocol in / out | `false` |
| `throttle_read_bytes_per_second` / `throttle_write_bytes_per_second` | global server bandwidth | `0` (unlimited) |

## Features

| | |
|---|---|
| HTTP/1.0 and 1.1 proxying | keep-alive on both sides, pipelining, chunked bodies and trailers, `Expect: 100-continue` (a `100` is sent for servers that ignore it), 1xx pass-through, re-chunking of close-delimited responses, de-chunking for HTTP/1.0 clients, stale keep-alive retry |
| Filters | `HttpFilters` / `HttpFiltersSource` with the same hooks as LittleProxy, streaming or buffered (`getMaximumRequestBufferSizeInBytes` / `getMaximumResponseBufferSizeInBytes`) |
| CONNECT | byte tunnel with idle timeout and half-close |
| MITM | `MitmManager`; `CertificateAuthorityMitmManager` issues per-host certificates on demand (EC P-256). Its SANs copy the real server's DNS names. Only the JDK is used, through a small built-in X.509/DER encoder (`org.microproxy.tls.CertificateBuilder`) |
| Chained proxies | HTTP (with Basic credentials, optionally over TLS), SOCKS4a, SOCKS5 (with username/password); falls back to the next proxy or a direct connection |
| Proxy authentication | `ProxyAuthenticator` (Basic) |
| TLS listener | `withSslContextSource(...)`, optional client-certificate auth |
| PROXY protocol | accept v1 and v2, send v1 |
| WebSockets | `Upgrade` is preserved and the connection becomes a tunnel after `101` |
| Throttling | global token bucket for server reads and writes, adjustable at runtime |
| Activity tracking | `ActivityTracker` for connections, requests, responses and bytes |
| Hardening | rejects `Transfer-Encoding` + `Content-Length`, conflicting lengths, obs-fold in requests, and oversized lines and headers; header values are validated against CR/LF injection; Host is replaced by the absolute-form authority |

## Migrating from LittleProxy

The public API keeps LittleProxy's shape (`HttpProxyServerBootstrap`, `HttpFilters`,
`HttpFiltersSource`, `ActivityTracker`, `ChainedProxy`, `ChainedProxyManager`, `MitmManager`,
`ProxyAuthenticator`, `HostResolver`, `FlowContext`). The packages changed from
`org.littleshoot.proxy` to `org.microproxy`. The Netty types are replaced like this:

| LittleProxy / Netty | MicroProxy |
|---|---|
| `io.netty.handler.codec.http.*` (`HttpRequest`, `HttpResponse`, `HttpContent`, `LastHttpContent`, `FullHttpRequest`, `FullHttpResponse`, `HttpHeaders`, `HttpMethod`, `HttpVersion`, `HttpResponseStatus`, `HttpUtil`) | `org.microproxy.http.*` with the same names and similar methods |
| `ByteBuf content()` | `byte[] content()` / `setContent(byte[])` / `contentAsString()` |
| `DefaultHttpProxyServer.bootstrap()` | `MicroProxy.bootstrap()` |
| `HttpFiltersSource.filterRequest(req, ChannelHandlerContext)` | `filterRequest(req, FlowContext)` |
| `HttpFiltersAdapter(req, ctx)` | `HttpFiltersAdapter(req, flowContext)` |
| `proxyToServerConnectionSucceeded(ChannelHandlerContext)` | `proxyToServerConnectionSucceeded(FullFlowContext)` |
| `SslEngineSource` (`SSLEngine`) | `SslContextSource` (`SSLContext`, plus a `configure(SSLSocket, clientMode)` hook) |
| `MitmManager.serverSslEngine / clientSslEngineFor` | `serverSslContext / clientSslContextFor` (return `SSLContext`) |
| `withSslEngineSource` | `withSslContextSource` |
| `SelfSignedSslEngineSource` (keytool, JKS file) | `org.microproxy.tls.SelfSignedSslContextSource` (generated in memory) |
| `SelfSignedMitmManager` | `org.microproxy.tls.CertificateAuthorityMitmManager` |
| `HttpProxyServer.getIdleConnectionTimeout()` (seconds) | returns a `Duration` |

Other behaviour differences:

- Full messages are written with a `Content-Length` that matches their actual body. Filters that
  replace a body don't need to fix the header themselves.
- All interface methods have defaults, so the `*Adapter` classes are only conveniences.

Not ported, because they are Netty-specific or have no equivalent here:

- `ThreadPoolConfiguration` and `ServerGroup`: virtual threads replace event-loop sizing.
- `connectionSaturated` / `connectionWritable` tracker events: blocking writes are the backpressure.
- `proxyToServerConnectionQueued`.
- The shared cross-client server connection pool: server connections are reused per client
  connection, as in LittleProxy's default mode.
- DNSSEC resolution: plug in your own `HostResolver`.
- `ActivityLogger` access-log formats.
- `webSocketFrameReceived` frame inspection: WebSocket traffic is tunnelled unparsed.

## Building and testing

```bash
mvn test
```

The tests use JUnit 5, the JDK's `HttpClient` as the client, `com.sun.net.httpserver` as origin
servers, and raw sockets for wire-level checks. They cover proxying, filters, authentication,
CONNECT, MITM, chaining (HTTP, TLS, SOCKS4/5, fallback), timeouts, PROXY protocol, throttling,
lifecycle, the codec and certificate generation.

## License

Apache License 2.0, like LittleProxy, from which this project is derived.
