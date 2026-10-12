# Raw TCP and TLS hooks

See, rewrite, drop and add the bytes of raw TCP tunnels, including TLS sessions the proxy decrypts
that do not carry HTTP (SMTPS, IMAPS, MQTT over TLS), with mitmproxy's TCP hooks. Use this page for
non-HTTP protocols; UDP flows and QUIC streams have hooks of their own ([CONNECT-UDP](masque.md),
[QUIC stream hooks](quic-hooks.md)).

## Raw TCP streams

`withTcpInterceptor(TcpInterceptor)` shows the bytes of every raw TCP tunnel to one interceptor,
with mitmproxy's TCP hooks: `tcpStart(ctx)`; `tcpMessage(msg, ctx)` for the bytes of each read,
which returns the bytes to pass on (`msg.data()` as it is or changed in place, others, or `null`
or an empty array to drop them); `tcpHalfClose(ctx, fromClient)` when one side finishes sending,
before the end is passed on; then `tcpEnd(ctx)`, or `tcpError(ctx, error)` when a read or write
failed, never both. `ctx.send(fromClient, bytes)` adds bytes as if that side had sent them, at any
time while that direction is open; sent from a `tcpMessage` call in the same direction, they
follow the message. `TcpContext` also gives the client connection's id and address, the target's
host and port, whether the proxy decrypted the client's TLS (`tlsIntercepted()`), the SNI and the
negotiated ALPN protocol.

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withTcpHosts("^mail\\.example\\.com$")                      // --tcp-hosts, tcp_hosts
        .withTcpInterceptor((msg, ctx) -> {
            if (!msg.fromClient() && msg.text().startsWith("220 ")) {
                return msg.text().replace("ESMTP", "ESMTP (via MicroProxy)").getBytes(UTF_8);
            }
            return msg.data();
        })
        .start();
```

- **Which tunnels.** A `CONNECT` that is not intercepted (no MITM manager, an ignored host, a
  declined ClientHello, a protocol that is neither TLS nor HTTP, a server that speaks first), on
  an HTTP/1 connection or as a stream of an HTTP/2 one; whether the server is reached directly,
  through a chained proxy, on a stream of an HTTP/2 connection, or through the HTTP or HTTPS proxy
  of a session ([In front of an HTTP or HTTPS proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy));
  `reverse:tcp://` connections; and a [SOCKS client](socks.md#socks5-mode)'s connection that is not
  intercepted or served as HTTP, which goes the way of a `CONNECT`. Upgraded WebSockets are not
  tunnels: their frames and messages go to the
  [WebSocket hooks](websockets.md#websocket-frames-and-messages).
- **Messages.** TCP has no message boundaries. A `TcpMessage` is whatever one read returned (up
  to a buffer, 16 KiB by default), with `fromClient()` and a timestamp; a peer's write may show
  up in pieces, or joined with the next one. Hooks that look for lines or commands keep the start
  of one until its end arrives.
- **Threads.** Each direction is read by a thread of its own, so a tunnel's hooks are called
  from two threads at once: the interceptor must be thread-safe. Within a direction calls come in
  order, and the direction waits for each.
- **Half-close.** The end of one direction is reported, then passed on; the other direction goes
  on, as without hooks. (Intercepted TLS closes the whole connection there instead, as before:
  TLS peers differ in their support for half-close.)
- **The fast path.** Without an interceptor, tunnels copy bytes through pooled buffers without
  copying them again, as before; with one, each message gets an array of its own.

## TLS that does not carry HTTP

Once the client's TLS is intercepted, the proxy decides what
the session is, as mitmproxy's next layer does inside TLS: an `h2` client is served as HTTP/2;
the [TCP hosts](#raw-tcp-streams) are raw TCP; an ALPN protocol of HTTP/1 is HTTP and any other
(`imap`, `mqtt`, ...) raw TCP; without ALPN, a server that speaks first (an SMTP banner) makes the
session raw at once, while the proxy waits for the client's first bytes, and otherwise those bytes
decide: a request line is HTTP, anything else raw TCP. A raw session is relayed between the
decrypted streams through the TCP hooks, whose context says `tlsIntercepted()`, with the SNI and
ALPN. With an interceptor, a client whose ALPN offers no HTTP protocol (an MQTT client offering
`mqtt`, say) is intercepted rather than tunnelled: the server is offered the client's protocols
and the client gets the server's choice. `acme-tls/1` (the ACME TLS-ALPN challenge) is never
intercepted, since no certificate the proxy makes could answer it. Without an interceptor such
clients are tunnelled untouched, as before.

## TCP hosts

`withTcpHosts(...)` (`--tcp-hosts`, `tcp_hosts`) is mitmproxy's `tcp_hosts`: each
pattern is a regular expression searched for, ignoring case, in the target's host name and the
client's SNI (without ports). Their connections are raw TCP even when they speak HTTP: plain
bytes after a `CONNECT` are tunnelled rather than served as HTTP, and an intercepted TLS session
is relayed decrypted. TLS is still intercepted, unlike with `--ignore-hosts`.

## Limitations

A session can be relayed as raw TCP only over a server connection of its own:
one shared as an HTTP/2 connection, a pooled one or none at all (offline interception) leaves it
served as HTTP. Bytes added with `send` do not pass through `tcpMessage`, unlike mitmproxy's
injected messages. UDP flows ([CONNECT-UDP](masque.md)) have hooks of their own,
`withUdpInterceptor`, and so do the streams of intercepted QUIC, `withQuicInterceptor`
([QUIC stream hooks](quic-hooks.md)).
