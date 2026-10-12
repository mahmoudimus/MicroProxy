# Architecture

How MicroProxy is built: why it uses virtual threads and blocking I/O instead of Netty, what that
costs and saves, how the modules fit together, and where to read the internals. Read this before
changing the proxy's code, or to judge whether its concurrency model suits your load.

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

Bodies that no filter inspects skip the message objects entirely. They are copied between the
sockets through one reusable 64 KiB buffer per connection, re-framed only when one side uses
chunked coding, and flushed only when no more input is buffered. A filter that overrides a
content hook (`clientToProxyRequest` / `proxyToServerRequest` for requests,
`serverToProxyResponse` / `proxyToClientResponse` for responses), checked through chains as
well, gets every piece as before. On loopback with a 256 MiB body this relays about 1.2 GB/s
with `Content-Length` and 0.6 GB/s chunked, against 0.47 and 0.25 GB/s through per-chunk
objects, and allocates under 3 MB instead of about 270 MB.

Idle connections hold almost no memory. Socket buffers are lent from a bounded per-server
pool only while bytes are moving. Between requests, a connection waits for the next byte without
a buffer, and tunnels give theirs back whenever the peer goes quiet. With 2,000 idle keep-alive
connections, each client and server connection pair costs about 11 KiB of heap, down from 141
KiB. An idle `CONNECT` tunnel costs about 15 KiB, down from 113 KiB.

Per request, header handling avoids throwaway objects:

- Heads are written straight into the pooled buffer.
- Header lines are parsed into one string each, and then a single name and value.
- List-valued fields are checked in place, and URIs are checked without regular expressions.
- The `Date` value is formatted once per second.
- The request copy that the filters API hands to filters is made only when filters are configured.

A small keep-alive GET through the proxy now allocates about 4.7 KB, down from 12.1 KB, at
10-20% higher throughput. Both figures include the benchmark client's own allocations.

A few rules keep this safe on JDK 21, where a virtual thread that blocks inside `synchronized`
pins its carrier thread:

- Blocking code paths use `ReentrantLock` instead of `synchronized`.
- The tests run with `-Djdk.tracePinnedThreads=short` to catch pinning.
- On JDK 24+ (JEP 491), `synchronized` no longer pins, so user filters written with
  `synchronized` are fine there too.

## Modules

The proxy is the `microproxy` module; everything else is optional, and the standalone modules
depend on nothing (see [Install](getting-started/install.md#modules-and-artifacts) for the
artifacts). Each standalone module documents its own design:

| Module | Design notes |
|---|---|
| `zstd-decoder` | [zstd-decoder/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/zstd-decoder/README.md): a Zstandard decoder written from RFC 8878 |
| `http2-codec` | [http2-codec/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/http2-codec/README.md): HTTP/2 frames and HPACK |
| `http3-codec` | [http3-codec/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/http3-codec/README.md): HTTP/3 frames and QPACK |
| `quic` | [quic/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/quic/README.md): the QUIC transport, its TLS 1.3 handshake, recovery, congestion control (CUBIC, NewReno, BBR), connection migration and qlog |
| `microproxy` | [org/microproxy/impl/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md): exchanges and transports, below |
| `microproxy-otel` | [OpenTelemetry](observability/opentelemetry.md): the `FlowTracer` hook and OTLP export |
| `microproxy-starlark` | [Scripting with Starlark](guides/scripting.md); the vendored interpreter's notes are in [thirdparty/starlark/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy-starlark/src/main/java/org/microproxy/thirdparty/starlark/README.md) and [thirdparty/larky/README.md](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy-starlark/src/main/java/org/microproxy/thirdparty/larky/README.md) |

## Inside the core: exchanges and transports

A client connection runs on one virtual thread in `ClientConnection`. Its code has two layers,
split so that HTTP/2 and HTTP/3 streams reuse everything but the wire format, on either side: a
transport (`ClientChannel`: HTTP/1, one HTTP/2 stream, or one HTTP/3 request stream) and the
exchange logic (`ClientConnection.handleRequest`), which runs the filters, connects (or reuses a
connection), relays the request and response, and opens tunnels. On the server side,
`ServerConnection` is an HTTP/1.1 connection, or one stream of a shared HTTP/2 or HTTP/3
connection to the server.

The package's design notes, kept next to the code in
[`microproxy/src/main/java/org/microproxy/impl/README.md`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md), describe how a request flows
through the proxy, which parts are HTTP/1-specific, and how HTTP/2 and HTTP/3 streams run the
same exchange logic concurrently:

| Section | What it covers |
|---|---|
| [The transport: `ClientChannel`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#the-transport-clientchannel) | the per-transport interface the exchange logic writes to |
| [The exchange logic](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#the-exchange-logic) | one request from head to response, on any transport |
| [The server side: `ServerConnection`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#the-server-side-serverconnection) | connections to servers and chained proxies, pooling |
| [CONNECT: the client's first bytes decide](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#connect-the-clients-first-bytes-decide) | ClientHello peeking, interception, tunnels |
| [HTTP/2: `Http2Connection` and `Http2StreamChannel`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#http2-http2connection-and-http2streamchannel) | HTTP/2 clients, proxy requests inside a session, who picks the server, the concurrency audit |
| [HTTP/2 to servers: `Http2UpstreamConnection` and `Http2Origins`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#http2-to-servers-http2upstreamconnection-and-http2origins) | shared HTTP/2 connections, WebSockets to origins |
| [Frame interception: `Http2Frames`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#frame-interception-http2frames) | how frame interceptors stay protocol-correct |
| [HTTP/3: `Http3Connection` and `Http3StreamChannel`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#http3-http3connection-and-http3streamchannel) | HTTP/3 clients and CONNECT-UDP (`UdpFlow`) |
| [Transparent QUIC: `TransparentQuicListener` and `QuicFlows`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#transparent-quic-transparentquiclistener-and-quicflows) | redirected QUIC, stream-by-stream relaying (`QuicSession`), QUIC inside CONNECT-UDP (`MasqueQuic`) |
| [HTTP/3 to servers: `Http3UpstreamConnection` and `Http3Origins`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#http3-to-servers-http3upstreamconnection-and-http3origins) | shared QUIC connections to servers, HTTP/3 frames |
| [What stays HTTP/1-specific, and why](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#what-stays-http1-specific-and-why) | the parts that are not shared |
| [Stats: `ProxyStats`, `ProtocolStats` and `QuicStats`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#stats-proxystats-protocolstats-and-quicstats) | how metrics are kept off the hot path |
| [Tracing: `FlowTracer`](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#tracing-flowtracer) | the tracing hook |
| [Notes for later](https://github.com/mahmoudimus/MicroProxy/blob/main/microproxy/src/main/java/org/microproxy/impl/README.md#notes-for-later) | known gaps and ideas |

## Rules for contributors

- Never use `synchronized` in blocking code: use `java.util.concurrent.locks.ReentrantLock`, so
  virtual threads do not pin their carriers on JDK 21 (see above).
- No runtime dependencies in any module: the core, the codecs and QUIC use only the JDK.
- `AllocationTest` fails if a small keep-alive request starts allocating much more than it does
  now; `StatsFastPathTest` guards the metrics' fast path.
