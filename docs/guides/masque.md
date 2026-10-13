# CONNECT-UDP (MASQUE)

Proxy UDP for MASQUE clients with CONNECT-UDP (RFC 9298) over HTTP/3, HTTP/2 and HTTP/1.1, see and
rewrite each datagram with UDP hooks, and optionally intercept the QUIC carried inside the flows.
Use this page to tunnel DNS, QUIC or any UDP through the proxy; the HTTP/3 listener itself is
described in [An HTTP/3 forward-proxy listener](http3.md#an-http3-forward-proxy-listener).

## CONNECT-UDP over HTTP/3, HTTP/2 and HTTP/1.1

A forward proxy proxies UDP with CONNECT-UDP (RFC 9298) on its HTTP/3 listener (`--http3`) and,
with `--http3` or `--masque` (`withConnectUdp(true)`, `masque=true`), on its TCP listener too:

| Transport | Request | UDP payloads |
|---|---|---|
| HTTP/3 (`--http3`) | extended `CONNECT`, `:protocol connect-udp` (section 3.5) | QUIC DATAGRAM frames, or DATAGRAM capsules on the stream |
| HTTP/2: `h2` on the TLS listener (on by default), or `h2c` (`--http2-cleartext`) | extended `CONNECT`, `:protocol connect-udp` (section 3.4); the proxy sends `SETTINGS_ENABLE_CONNECT_PROTOCOL` | DATAGRAM capsules in the stream's DATA |
| HTTP/1.1, plain or on the TLS listener | `GET` with `Connection: Upgrade` and `Upgrade: connect-udp` (section 3.2), in origin-form or absolute-form; the answer is a `101` | DATAGRAM capsules on the connection, which closes with the flow |

`--masque` serves the TCP listener without an HTTP/3 listener (so no certificate or UDP port is
needed, and h2c works), and needs the `quic` and `http3-codec` jars as `--http3` does; a reverse
proxy fails to start with it. The request's path names the target by the URI template, by
default the well-known `/.well-known/masque/udp/{target_host}/{target_port}/`
(`--masque-udp-template`, `Http3Options.connectUdpTemplate`, `masque_udp_template`: a path with
an optional query, or an absolute URI, whose authority is the proxy's own, with each variable
once; values are percent-decoded, so an IPv6 address's colons may be encoded). Everything below
is the same whichever transport carries the flow.

- **Policy.** The request is an exchange like any other: authentication applies (`407`), filters
  see it as the HTTP/1.1 upgrade an HTTP/1.1 client would send (`GET` of the path with `Upgrade:
  connect-udp`, version `HTTP/3.0`, `HTTP/2.0` or `HTTP/1.1`) and may answer it, the target is
  routed as `CONNECT host:port` would be (chained proxies carry no UDP, so a route through them
  only gets `502`), `proxyToServerRequest` may answer, and the target's name is resolved by the
  proxy's resolver and the filters' resolution hooks (`502` when it does not resolve). A path
  that does not match the template gets `400`. The acceptance is a `101` with `Upgrade:
  connect-udp` for filters and trackers, and a `200` (HTTP/2, HTTP/3) or that `101` (HTTP/1.1)
  with `capsule-protocol: ?1` for the client. CONNECT-UDP elsewhere (a reverse proxy, an
  intercepted session, a proxy without `--masque` or `--http3`) gets `501` over HTTP/2 and
  HTTP/3; over HTTP/1.1 such a request is passed on as any upgrade.
- **HTTP Datagrams** (RFC 9297). UDP payloads travel as HTTP Datagrams with context ID 0: over
  HTTP/3 in QUIC DATAGRAM frames, whose payload starts with the stream's quarter stream ID, or in
  DATAGRAM capsules on the request stream (the capsule protocol, RFC 9297 section 3), which the
  proxy reads whatever the client negotiated; HTTP/2 and HTTP/1.1 have no datagrams, so there
  every payload is a capsule (section 3.5), both ways. Capsules of unknown types are skipped,
  however large, and payloads with other context IDs dropped; a stream that ends inside a capsule,
  or a DATAGRAM capsule larger than any UDP payload, resets the flow (HTTP/2 `CANCEL`). Towards
  an HTTP/3 client the proxy uses DATAGRAM frames when the client's SETTINGS_H3_DATAGRAM and QUIC
  transport parameters allow them and the payload fits, else capsules.
- **Relaying.** Each flow has a UDP socket of its own, connected to the target; datagrams go both
  ways, one for one, until the client ends or resets its stream (half-closes its connection, for
  HTTP/1.1), or the flow is idle for `--masque-udp-idle-timeout` (60 s), after which the proxy
  ends the stream.
- **Bounds** (`Http3Options`). Flows at once, in total (4096) and per client connection (64;
  `--masque-max-udp-flows`, `--masque-max-udp-flows-per-connection`; an HTTP/1.1 connection
  carries one): a request past either gets `503`. Each direction of a flow queues at most 128
  datagrams and 512 KiB (`connectUdpQueue`); past that datagrams are dropped, as a network drops
  what it cannot carry, so a client that does not read its stream, or a slow target, holds up
  nothing else.
- **Room after an end.** A flow holds its places in the bounds until the proxy has seen it end,
  and no longer: the proxy gives them back before it tells the client of an end of its own (a
  refusal, the idle timeout), and as soon as it reads the client's (a reset, the end of its
  stream, the close of its connection), before it reads anything after it. A request the client
  sends right after ending a flow on the same connection finds room for it: over HTTP/2 in the
  order of the frames, over HTTP/3 in the order QUIC received them. Across connections there is
  no such order, and a client that ends a flow on one and opens one on another may have the new
  request read first: a request that finds the proxy's bound full waits, for at most
  `--masque-release-wait` (250 ms), while flows whose end the proxy has seen are still closing,
  and is refused at once when none are. A client that has read the proxy's end of a flow (its
  reset or its own end of the stream) always finds that flow's places free.
- **Flow control.** A capsule to the client is stream data: over HTTP/2 it waits for the
  stream's and the connection's send window (over HTTP/3 for QUIC's, over HTTP/1.1 for TCP's),
  as any DATA does. While it waits, the target's later datagrams queue up to the bounds above
  and those past them are dropped, counted in `masque.datagrams_dropped`: UDP is lossy, and stale
  datagrams are worth less than the window they would take. A client that opens no window for the
  idle timeout (`--idle-timeout`) has its flow reset, as a stalled tunnel would. The client's own
  capsules are read as they come, crediting the windows back at once, whatever the target does.
- **Hooks.** `withUdpInterceptor(UdpInterceptor)` sees every datagram, both ways: `udpStart`,
  `udpMessage` (return the payload to send, changed or not, or `null` to drop it), `udpEnd`, and
  `UdpContext.send` to add datagrams; scripts get [`on_udp_message`](scripting.md#udp-hooks). A flow whose
  QUIC the proxy intercepts ([below](#quic-inside-connect-udp-flows)) shows the hooks no
  datagrams: its QUIC ends at the proxy.
- **QUIC.** With `--masque-intercept-quic`, the QUIC inside a flow is decided on as transparent
  QUIC is ([QUIC inside CONNECT-UDP flows](#quic-inside-connect-udp-flows)); without it, it is
  relayed like any UDP.

```java
bootstrap.withUdpInterceptor((msg, ctx) ->
        msg.fromClient() && ctx.port() == 53 && msg.text().contains("blocked") ? null : msg.data());
```

A MASQUE client, such as aioquic's `H3Connection` (with HTTP/3 datagrams on), opens a flow and
sends a DNS query through it:

```python
http = H3Connection(quic, enable_webtransport=True)   # sends SETTINGS_H3_DATAGRAM
http.send_headers(stream_id, [(b":method", b"CONNECT"), (b":protocol", b"connect-udp"),
                              (b":scheme", b"https"), (b":authority", b"proxy.example:8443"),
                              (b":path", b"/.well-known/masque/udp/192.0.2.53/53/"),
                              (b"capsule-protocol", b"?1")])
# once the 200 arrives: context ID 0, then the UDP payload
http.send_datagram(stream_id, b"\x00" + dns_query)
```

Over TCP the same query goes in a DATAGRAM capsule: its type (0), its length, then the context ID
(0) and the payload, as stream DATA on HTTP/2, or on the connection once an HTTP/1.1 client has
the `101`:

```python
# HTTP/1.1, to a proxy started with --masque (any HTTP/2 client sends the same capsule in DATA)
sock.sendall(b"GET /.well-known/masque/udp/192.0.2.53/53/ HTTP/1.1\r\nHost: proxy.example:8080\r\n"
             b"Connection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
# once "HTTP/1.1 101 Switching Protocols" has arrived (a payload under 63 bytes keeps the length to one byte)
sock.sendall(bytes([0x00, 1 + len(dns_query), 0x00]) + dns_query)
```

## QUIC inside CONNECT-UDP flows

With `--masque-intercept-quic` (`Http3Options.Builder.connectUdpInterceptQuic(true)`,
`masque_intercept_quic=true`), the QUIC that a [MASQUE client](#connect-udp-masque) sends through
a CONNECT-UDP flow is decided on as [transparent QUIC](transparent-mode.md#transparent-quic) is, with the flow's
target as the server, instead of being relayed as any UDP:

- **Which flows.** Those to a UDP port of `--masque-quic-ports` (`connectUdpQuicPorts`,
  `masque_quic_ports`; 443 by default, `any` for every port) whose first datagram from the client
  is a QUIC Initial. Other flows, and flows whose first datagram is something else, are relayed as
  before, through the [UDP hooks](scripting.md#udp-hooks).
- **Deciding.** The proxy holds the flow's datagrams, reads the ClientHello from its Initials,
  and runs the [same decision](transparent-mode.md#transparent-quic): a `CONNECT target` is made up for it, the
  [ignore and allow rules](mitm.md#ignoring-and-allowing-hosts) apply to the target and the SNI, then
  the ALPN, `shouldIntercept` and `on_client_hello`. The MASQUE client's CONNECT-UDP request was
  authenticated already, so the inner flow is not asked again, and its client connection has the
  MASQUE client's address and user.
- **Intercepted.** HTTP/3 is served as HTTP/3, its requests going to the target (by the SNI's
  name when the target is an IP address, so that the server's certificate is checked against it,
  at the target's address): filters, scripts (`on_request`, `on_frame`, ...) and trackers see
  them, with `FlowContext.isTransparentQuic()` true. Other QUIC goes through the
  [QUIC stream hooks](quic-hooks.md), with `QuicContext.masque()` true. The proxy's
  replies travel back in the flow, as HTTP Datagrams or capsules; over HTTP/2 and HTTP/1.1 (with
  `--masque`, which needs no `--http3`), every packet of the inner QUIC is a capsule.
- **Relayed.** An ignored or declined host, or QUIC that is not intercepted, goes to the target
  from the flow's own socket, the held datagrams first, as without the option.
- **How.** A virtual listener: the transparent listener's per-flow logic (`QuicFlows`) over a
  QUIC server without a socket (`QuicServer.unbound`), fed the flows' datagrams under addresses
  it makes up for each flow, and handing its replies back to the flows.

```java
MicroProxy.bootstrap()
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("proxy.p12"), password))
        .withHttp3(true)
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp3Options(Http3Options.builder()
                .connectUdpInterceptQuic(true)                           // --masque-intercept-quic
                .connectUdpQuicPorts(443, 8443)                          // --masque-quic-ports 443,8443
                .build())
        .withIgnoreHosts("\\.bank\\.example:443$")                         // relayed untouched
        .start();
```
