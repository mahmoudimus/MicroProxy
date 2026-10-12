# HTTP/3 and QUIC

Serve HTTP/3 over the proxy's own QUIC transport to the clients of a reverse proxy and of a forward
proxy's TLS listener, and speak HTTP/3 to servers that offer it, with session resumption, 0-RTT,
`Alt-Svc` handling and hardened limits. Use this page to turn HTTP/3 on; QUIC that clients redirect
to the proxy is in [Transparent QUIC](transparent-mode.md#transparent-quic), UDP proxying in
[CONNECT-UDP (MASQUE)](masque.md), and QUIC that is not HTTP/3 in [QUIC stream
hooks](quic-hooks.md).

MicroProxy speaks HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)) over its own
QUIC transport, the [`quic`](https://github.com/mahmoudimus/MicroProxy/blob/main/quic/README.md) module (ported from quinn and rustls), with
[`http3-codec`](https://github.com/mahmoudimus/MicroProxy/blob/main/http3-codec/README.md) for frames and QPACK. It does so in four places: to the
clients of a reverse proxy, to the clients of a [forward proxy](#an-http3-forward-proxy-listener)
that serves it next to its TLS listener (for `CONNECT`, WebSockets and MASQUE), to clients whose
QUIC is redirected to a [transparent proxy](transparent-mode.md#transparent-quic) or carried in a
[CONNECT-UDP flow](masque.md#quic-inside-connect-udp-flows), and to origin servers known to support it. QUIC
that carries another protocol can be intercepted too, its streams relayed through
[hooks](quic-hooks.md). All need the optional
`quic` and `http3-codec` jars on the class path (the `microproxy-starlark` `-all` jar bundles
them); a proxy started with HTTP/3 enabled without them fails at startup with an
`IllegalStateException` that says so, and without HTTP/3 nothing loads them.

```java
MicroProxy.bootstrap()
        .withReverseProxy("https://backend.internal")                     // --mode reverse:https://backend.internal
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("site.p12"), password))  // --listener-keystore site.p12
        .withHttp3(true)                                                   // to clients: --http3, http3=true
        .withHttp3Upstream(true)                                           // to servers: --http3-upstream, http3_upstream=true
        .withHttp3UpstreamHosts("\\.internal:")                            // --http3-upstream-hosts, http3_upstream_hosts
        .withHttp3Options(Http3Options.builder().maxConcurrentStreams(200).build())   // optional
        .start();
```

```bash
java -jar microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8443 --mode reverse:https://backend.internal \
    --listener-keystore site.p12 --listener-keystore-password secret --http3 --http3-upstream
```

## Serving HTTP/3 in reverse mode

With `--http3` (`withHttp3(true)`, `http3=true`) and `--mode reverse:...`, the proxy opens a UDP
listener on the TCP listener's port number and serves HTTP/3 there (ALPN `h3`).

- **Certificate.** The HTTP/3 listener presents the TLS listener's certificate: its
  `SslContextSource` gives it as `KeyMaterial` (`getKeyMaterial`), which
  `KeyStoreSslContextSource` (`--listener-keystore`, `listener_keystore`) and
  `SelfSignedSslContextSource` do; QUIC runs its own TLS 1.3 handshake and needs the key itself,
  not an `SSLContext`. Without a TLS listener, a `CertificateAuthorityMitmManager` (`--mitm`)
  issues one for the name the client asks for. With neither, the proxy fails at startup.
- **Exchanges.** Each request stream is an exchange like any HTTP/1 or HTTP/2 request, on a
  virtual thread of its own: filters, the cache, authentication (per stream, as on `h2c`),
  logging, WARC and HAR recording, timings and trackers all apply. The request is an
  `HttpRequest` with version `HTTP/3.0` (`HttpVersion.HTTP_3_0`), `FlowContext.getHttpVersion()`
  says `HTTP/3.0` and `getStreamId()` gives the QUIC stream id, and scripts see
  `req.http_version == "HTTP/3"`. The upstream gets it as HTTP/1.1, HTTP/2 (unless `--no-http2-upstream`)
  or HTTP/3 (`--http3-upstream`), whichever it speaks: a body without `content-length` goes chunked
  to an HTTP/1.1 server, trailers go through end to end where both sides carry them, and
  `100-continue` and `103 Early Hints` reach the client as interim responses.
- **Advertising.** Responses sent over TCP get `Alt-Svc: h3=":<port>"; ma=86400`, so that clients
  find the HTTP/3 listener, unless the server's own `Alt-Svc` field is left after the `h3`
  stripping (below), which then goes to the client as it is; a `proxyToClientResponse` filter may
  remove the field. `Http3Options.altSvc(false)` (`--no-http3-alt-svc`, `http3_alt_svc=false`)
  turns it off, and `altSvcMaxAge` sets `ma`. Browsers act on `Alt-Svc` only over HTTPS, so pair
  HTTP/3 with a TLS listener.
- **WebSockets** over extended `CONNECT` (RFC 9220) reach the upstream as described
  [below](#websockets-over-http3); `CONNECT` is refused with `400`, as over HTTP/1 and HTTP/2, and
  CONNECT-UDP with `501`. There is no server push, and no HTTP datagrams (SETTINGS_H3_DATAGRAM is
  not sent, nor QUIC DATAGRAM frames accepted).

### Limits

**Limits** (of every HTTP/3 connection to clients). Much of HTTP/2's defence is QUIC's in HTTP/3: the stream limit and flow control are
the transport's, which a peer cannot exceed without a QUIC error. The proxy's own limits are set
with `Http3Options` (or `http3_*` properties and `--http3-max-streams`); rate limits count per
window of 10 seconds (`rateWindow`).

| Limit | Default | When exceeded | Setting |
|---|---|---|---|
| Request streams open per connection | 100 | QUIC holds new streams back until one ends | `maxConcurrentStreams` |
| Bytes a peer sends ahead of the proxy, per stream / per connection | 256 KiB / 1 MiB (QUIC flow control) plus 64 KiB read ahead per stream | QUIC `FLOW_CONTROL_ERROR` | `streamReceiveWindow` / `connectionReceiveWindow` |
| Field section (names and values plus 32 per field), SETTINGS_MAX_FIELD_SECTION_SIZE | `max_header_size` + `max_initial_line_length` (24 KiB) | `431` for a request (the connection goes on), `502` for a response | `maxFieldSectionSize` |
| QPACK dynamic table, each way | 4096 bytes | `QPACK_ENCODER_STREAM_ERROR` | `qpackMaxTableCapacity` |
| Streams blocked on the peer's QPACK encoder stream | 16, each for at most `idle_connection_timeout` | `QPACK_DECOMPRESSION_FAILED` / the stream is rejected | `qpackBlockedStreams` |
| Frames of unknown and reserved types, and empty DATA frames | 1000 per window | `H3_EXCESSIVE_LOAD` | `maxUnknownFrames` |
| Unidirectional streams of unknown and reserved types | 100 per window (each abandoned with `STOP_SENDING`) | `H3_EXCESSIVE_LOAD` | `maxUnknownStreams` |
| Requests reset by the client before their response completed (Rapid Reset) | 100 per window | `H3_EXCESSIVE_LOAD` | `maxRapidResets` |
| A connection with nothing to do | `idle_connection_timeout` (70 s) | QUIC's idle timeout closes it | `withIdleConnectionTimeout` |
| Client address validation (QUIC Retry) | off | | `retry` |

<a id="http3-congestion-control"></a>

### Congestion control

The proxy's QUIC connections, those
its HTTP/3 and transparent QUIC listeners accept and those it opens to servers, use CUBIC by
default. `--quic-congestion newreno` or `bbr` (`quic_congestion`,
`Http3Options.quicCongestionControl`) chooses NewReno or BBR. BBR, ported from quinn and
experimental there too, paces at its estimate of the path's bandwidth rather than backing off on
every loss, so it keeps its throughput on paths with random loss (wireless links, long distances)
where CUBIC collapses; it is not tuned for sharing a bottleneck fairly. See the [quic
module](https://github.com/mahmoudimus/MicroProxy/blob/main/quic/README.md#connection-internals) for its behaviour and limits.

Protocol violations close the connection with the code RFC 9114 or RFC 9204 names: a second
control or QPACK stream or a push stream from a client (`H3_STREAM_CREATION_ERROR`), frames out of
place (`H3_FRAME_UNEXPECTED`, `H3_MISSING_SETTINGS`), a critical stream that ends
(`H3_CLOSED_CRITICAL_STREAM`), bad settings (`H3_SETTINGS_ERROR`), bad QPACK. Malformed requests
(missing or repeated pseudo-headers, upper-case or connection-specific fields, a
`content-length` the DATA does not match) only reset their stream, with `H3_MESSAGE_ERROR`.

### Shutting down

A graceful stop (`stop()`) sends `GOAWAY` naming the first stream the proxy
will not process; streams opened after it are refused with `H3_REQUEST_REJECTED`, which clients
retry elsewhere, the streams in progress finish (for up to the graceful stop timeout), and the
connection closes once the client has closed it, or after two seconds.

## An HTTP/3 forward-proxy listener

With `--http3` (`withHttp3(true)`, `http3=true`) on a forward proxy whose own TLS listener is on
(`--listener-keystore`, `withSslContextSource`), the proxy also serves HTTP/3 on UDP at the TCP
listener's port, with the same certificate. Browsers send HTTP/3 only to origins, never to a
proxy; this listener is for clients configured to use an HTTP/3 proxy, MASQUE clients first:
they tunnel TCP with `CONNECT`, WebSockets with extended `CONNECT`, and UDP (QUIC included) with
CONNECT-UDP, all over one QUIC connection to the proxy.

- **Proxy requests.** A request names its target with `:scheme` and `:authority`, and goes on as
  an HTTP/1 client's absolute-form proxy request does: filters see `http://host:port/path` with
  version `HTTP/3.0`. Every authority is served (no `421`: a forward proxy's requests name their
  targets), and no `Alt-Svc` is added (a forward proxy's responses are its servers').
- **Proxy authentication** applies per stream, as on `h2c`: a stream without valid credentials
  gets `407` with `proxy-authenticate`, and the connection goes on.
- **SETTINGS.** The listener sends SETTINGS_ENABLE_CONNECT_PROTOCOL and SETTINGS_H3_DATAGRAM,
  and accepts QUIC DATAGRAM frames (the `max_datagram_frame_size` transport parameter). The
  reverse proxy's listener and intercepted transparent QUIC send neither datagram setting and
  refuse DATAGRAM frames.
- **Not served.** A forward proxy without a TLS listener, and a transparent proxy (whose clients'
  QUIC goes to `--transparent-quic-port`), fail at startup with `--http3`.

```java
MicroProxy.bootstrap()
        .withPort(8443)
        .withSslContextSource(new KeyStoreSslContextSource(Path.of("proxy.p12"), password))  // --listener-keystore
        .withHttp3(true)                                                   // --http3: UDP 8443 too
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))       // intercept CONNECT streams (optional)
        .withHttp3Options(Http3Options.builder()
                .connectUdpIdleTimeout(Duration.ofSeconds(30))             // --masque-udp-idle-timeout 30
                .connectUdpMaxFlows(4096, 64)                              // --masque-max-udp-flows(-per-connection)
                .build())
        .start();
```

## CONNECT over HTTP/3

A `CONNECT` stream (RFC 9114 section 4.4: `:method CONNECT` and `:authority host:port` only)
opens a byte tunnel, as an HTTP/2 `CONNECT` stream does ([CONNECT and
WebSockets](http2.md#connect-and-websockets)): its `200` leaves the stream open, DATA frames carry the
tunnel's bytes, and the stream's FIN half-closes one direction. A reset ends the tunnel and
closes its server connection, and is not counted as a rapid reset; a server connection that fails
resets the stream with H3_CONNECT_ERROR. HEADERS after the `CONNECT`'s are a connection error
(H3_FRAME_UNEXPECTED).

The stream goes the way an HTTP/1 or HTTP/2 `CONNECT` does, because it is shown to the same code
as a socket: with a MITM manager, the stream's first bytes decide ([Deciding what to
intercept](mitm.md#deciding-what-to-intercept-the-clienthello)): a ClientHello goes through the host
rules and the ClientHello hooks, and an intercepted session is a client connection of its own
inside the stream (HTTP/1.1, or HTTP/2 when the client negotiates `h2`), whose requests filters
see; plain HTTP is served as HTTP; anything else is tunnelled, through the [TCP
hooks](tcp-hooks.md#raw-tcp-streams) and `--tcp-hosts`. Chained proxies and NO_PROXY apply as to any
`CONNECT`. Inside an intercepted HTTP/3 session (transparent QUIC), a `CONNECT` goes to the
intercepted server, which the client takes for its HTTPS proxy ([In front of an HTTP or HTTPS proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)),
and a request for another host gets `421`.

### WebSockets over HTTP/3

**WebSockets over HTTP/3** (RFC 9220) work on every HTTP/3
connection to clients, as over HTTP/2: an extended `CONNECT` with `:protocol websocket`, `:scheme`
`http` or `https`, `:authority` and `:path` becomes the HTTP/1.1 upgrade an HTTP/1.1 client would
send. Filters see a `GET` with `Upgrade: websocket` (absolute-form on a forward proxy) and the
answer as a `101`, which the client gets as a `200`; the frame and message hooks, the WebSocket
limits and permessage-deflate apply as for HTTP/1 and HTTP/2 ([WebSocket frames and
messages](websockets.md#websocket-frames-and-messages)). Towards the server the WebSocket goes as an HTTP/1.1
upgrade, as an extended `CONNECT` to an HTTP/2 server that enables RFC 8441, or, with
`--http3-upstream`, as an extended `CONNECT` on the shared QUIC connection to an HTTP/3 server
whose SETTINGS enable it. A server that resets the connection cancels the stream
(H3_REQUEST_CANCELLED). Other `:protocol`s get `501`.

```python
# aioquic's H3Connection, a WebSocket through the proxy's HTTP/3 listener:
http.send_headers(stream_id, [(b":method", b"CONNECT"), (b":protocol", b"websocket"),
                              (b":scheme", b"https"), (b":authority", b"chat.example:443"),
                              (b":path", b"/socket"), (b"sec-websocket-version", b"13")])
```

## Session resumption and 0-RTT

The proxy's QUIC servers that serve HTTP/3 (`--http3`, the clients the [transparent
QUIC](transparent-mode.md#transparent-quic) listener intercepts as HTTP/3, and HTTP/3 intercepted inside CONNECT-UDP
flows with `--masque-intercept-quic`) send each client two TLS session tickets after its
handshake, sealed with a key of the proxy's that rotates every six hours, and two NEW_TOKEN tokens.
A returning client resumes its session (no certificate exchange: a fresh key exchange and a PSK)
and skips the Retry round trip of `--http3-retry`. Tickets work across all the QUIC servers of one
proxy, but not across proxy processes: each has its own key. QUIC intercepted stream by stream
(the [QUIC stream hooks](quic-hooks.md)) gets no tickets, so no resumption and no 0-RTT: its
streams are opaque, and the proxy could not tell what in them is safe to replay.

### 0-RTT to the proxy

**0-RTT to the proxy** is off by default. `--http3-0rtt` (`Http3Options.zeroRtt(true)`,
`http3_0rtt=true`) lets a resuming client send its first requests as early data, before its
handshake completes, saving a round trip. Early data is not protected against replay: whoever
captures a client's first flight can send it again, and the proxy would act on it twice ([RFC
8446 section 8](https://datatracker.ietf.org/doc/html/rfc8446#section-8)). So:

- **The QUIC layer** accepts a ticket's early data at most once, and only while the ticket age the
  client reports agrees with the proxy's within 10 seconds, which a stale capture fails. Its record
  of used tickets is in memory, one per process that all its QUIC servers share, and bounded
  (refusing early data when full); rejected early data costs the client nothing but the round
  trip, as it sends it again.
- **The proxy** treats a request any part of which arrived as early data as
  [RFC 8470](https://datatracker.ietf.org/doc/html/rfc8470) says. A method that is not safe to
  repeat (anything but `GET`, `HEAD` and `OPTIONS` without a body, and so any `CONNECT`, extended
  or not) gets `425 Too Early`, and the client sends it again once its handshake completes. Others go on with `Early-Data: 1`, so the
  server (or another proxy behind) can answer `425` itself, which the proxy relays.
- **Filters** see `FlowContext.isEarlyData()` (`ctx.early_data` in scripts) and may answer `425`
  to requests they deem unsafe, `GET`s with side effects for instance:

  ```python
  def on_request(req, ctx):
      if ctx.early_data and "/checkout" in req.uri:
          return response(425, "too early\n")
  ```

The proxy does not hold early requests back until the handshake completes; one that arrived early
is marked even when the handshake has completed by the time it goes on.

### 0-RTT to servers

**0-RTT to servers** is on with `--http3-upstream` (`Http3Options.upstreamZeroRtt`,
`http3_upstream_0rtt`; `--no-http3-upstream-0rtt` turns it off). The proxy keeps the tickets
servers send, per server name, for as long as it runs, and resumes when it opens a new QUIC
connection to one. If the request that opens the connection is safe to replay (`GET`, `HEAD`,
`OPTIONS` without a body) and the ticket allows it, the request goes as 0-RTT data; requests that
are not wait for the handshake. A server that rejects the early data gets it again in 1-RTT
packets; one that answers `425 Too Early` gets the request again after the handshake, unless the
request itself arrived as early data (`Early-Data: 1`), whose `425` goes back to its client.

## HTTP/3 to servers

With `--http3-upstream` (`withHttp3Upstream(true)`, `http3_upstream=true`), the proxy speaks
HTTP/3 to servers known to support it, whatever protocol the client spoke (HTTP/1, HTTP/2 or
HTTP/3), in any mode.

- **Knowing.** A server is known to speak HTTP/3 once one of its responses over TLS advertised
  `h3` on its own host (`Alt-Svc: h3=":443"`), remembered for the advertisement's `ma` (24 hours
  without one) and forgotten on `Alt-Svc: clear` or `ma=0`. The proxy learns before it strips
  `h3` for the client, so stripping stays on. Alternatives on other hosts, and draft versions
  (`h3-29`), are never used. `--http3-upstream-hosts <regex>` (`withHttp3UpstreamHosts`,
  `http3_upstream_hosts`) names servers to reach over HTTP/3 at once, on their URI's port.
- **Sharing.** One QUIC connection per server, shared by every exchange for it, of every client,
  as streams, within the server's stream limit. Nothing about a QUIC connection is particular to
  one client.
- **Trust.** Servers are validated as TLS connections to them are: with the MITM manager's
  server trust (`MitmManager.serverTrustManager`, which `CertificateAuthorityMitmManager` and
  every context from `SslContexts` provide, so `--mitm-trust-all` works too), or the JDK's default
  trust store without a manager, checking the host name as HTTPS does. A manager whose trust the
  proxy cannot reproduce keeps its servers on TCP.
- **Falling back** (happy eyeballs, lite). A QUIC handshake that fails, or does not complete
  within `upstreamHandshakeTimeout` (1 second), sends the exchange over TCP, and the server stays
  on TCP for `upstreamFailureTimeout` (5 minutes). Exchanges for the same server wait for a
  handshake in progress rather than start their own.
- **Failures.** A `GOAWAY` from the server, or a stream it refuses with `H3_REQUEST_REJECTED`,
  makes the request safe to send again, on a new connection. QUIC's idle timeout answers `504`
  (`ProxyFailure.ServerTimeout`); other resets and connection errors `502`
  (`ProxyFailure.BadServerResponse`), or reset the client's stream once the response has started.
- **Only direct connections.** Requests through chained proxies (UDP does not go through them),
  through a tunnel a session's server opened, with a PROXY protocol header, and proxy requests
  keep using TCP.
- **WebSockets** go over HTTP/3 to a server whose SETTINGS enable extended `CONNECT` (RFC 9220),
  waited for up to `upstreamHandshakeTimeout`; to other servers on an HTTP/1.1 connection of their
  own.

## Alt-Svc: which clients may move to HTTP/3

HTTP/3 runs over QUIC, on UDP. Browsers never send QUIC through an HTTP proxy, and a transparent
setup may redirect only TCP. So a client that learns that an origin speaks HTTP/3 can switch to it
and bypass the proxy, and with it interception, filters and logging, unless its UDP is redirected
to a [transparent QUIC](transparent-mode.md#transparent-quic) port. Clients learn about HTTP/3 in two ways:

- **From `Alt-Svc` response headers** such as `Alt-Svc: h3=":443"; ma=86400, h2=":443"`. The
  proxy removes the `h3` alternatives, including the draft versions (`h3-29`, `h3-Q050`, ...)
  and Google QUIC's `quic`. Other alternatives such as `h2=":443"` are kept with their
  parameters (`ma`, `persist`), a header left empty is removed, and `Alt-Svc: clear` is passed
  on. This is **on by default with interception (`--mitm`, `withManInTheMiddle`) or
  `--transparent`**, and off for a plain forward proxy; **with `--transparent-quic-port`, it is
  off by default for clients whose traffic was redirected to the proxy**, whose QUIC reaches the
  proxy too (table below). `--no-alt-svc-h3`, `withoutHttp3Advertisement()` or
  `strip_alt_svc_h3=true` turn it on for every client, and `--keep-alt-svc-h3`,
  `withAltSvcH3Stripping(false)` or `strip_alt_svc_h3=false` off for every client. Filters see server
  responses unchanged in `serverToProxyResponse` and already stripped in
  `proxyToClientResponse`. Short-circuit responses (including cache answers) are stripped as
  they are sent. With `--http3-upstream`, the proxy itself learns from the advertisement first.
- **From DNS `HTTPS` records**, which the proxy never sees. In transparent deployments without
  a transparent QUIC port, **block UDP port 443** (for example `iptables -A FORWARD -p udp
  --dport 443 -j REJECT`). Clients then fall back to TCP, which the proxy does see.

Who keeps `h3` alternatives, by default (an explicit `strip_alt_svc_h3` applies to every row):

| Client | Configuration | `h3` in `Alt-Svc` | Its HTTP/3 then |
|---|---|---|---|
| Explicit proxy client (`CONNECT`, absolute-form) | plain forward proxy | kept | goes around the proxy |
| Explicit proxy client | `--mitm` or `--transparent` (with or without `--transparent-quic-port`) | stripped | stays on TCP through the proxy; a client whose UDP is redirected to the QUIC port anyway may turn stripping off (`--keep-alt-svc-h3`) |
| Redirected client (SNI-routed TLS, HTTP routed by `Host`) | `--transparent`, no QUIC port | stripped | stays on TCP; block UDP 443 for DNS `HTTPS` records |
| Redirected client | `--transparent --transparent-quic-port` | kept | redirected to the QUIC port: intercepted (`h3` with `--mitm`) or relayed |
| HTTP/3 client of the transparent QUIC port | `--transparent-quic-port` | kept | already on HTTP/3 through the proxy |
| Reverse proxy client | `--http3` | the proxy's own `h3` | the proxy's HTTP/3 listener |

HTTP/2 can also announce alternatives in `ALTSVC` frames. The proxy never sends them, and drops
any that HTTP/2 servers send (as frames of a type it does not handle), so alternatives reach
HTTP/2 clients only as `Alt-Svc` headers, which are stripped the same way.

## Limitations and what is next

- **Transparent QUIC**'s original destination is the SNI's host (no TPROXY, no
  `SO_ORIGINAL_DST`). Clients of an explicit proxy are still steered to TCP, unless they use the
  forward proxy's HTTP/3 listener.
- **QUIC stream hooks.** Streams are paired as they open, so the hooks cannot open streams of
  their own, nor see QUIC frames (only stream bytes and datagrams). The server's handshake comes
  before the client's, so a server that is slow to answer delays the client's, which may
  retransmit its Initials meanwhile; one that cannot be reached drops the flow rather than relay
  it. 0-RTT is not offered, as the QUIC module has none.
- **QUIC message framing.** A connection's streams all get the framer its ALPN or host chooses,
  each carrying that protocol's messages from its start (a stream type or a header before them,
  as HTTP/3's unidirectional streams have, needs a framer of one's own). Framers keep no state
  between calls, and a script's framer is called with all the bytes kept so far each time. Bytes
  a framer cannot read reset the stream rather than fall back to the reads, and the hooks are not
  told of the resets framing makes.
- **MASQUE.** QUIC inside a CONNECT-UDP flow is intercepted only with `--masque-intercept-quic`,
  and a flow is inspected from its first datagram: one that starts with anything but a QUIC
  Initial is relayed as UDP throughout, and once one of its QUIC connections is relayed, so is the
  rest of the flow. An intercepted connection that its client carries over to another CONNECT-UDP
  flow to the same target follows it there (a flow whose first datagram belongs to the connection
  goes to the proxy's QUIC server, which validates the path through the new flow), and closes when
  the flow it is on ends, not one it left; relayed QUIC that moves between flows is not followed.
  CONNECT-UDP to an upstream MASQUE proxy (HTTP/3
  chained proxies) and CONNECT-IP are not done.
- Server push (never requested: the proxy sends no MAX_PUSH_ID).
- The proxy's own QUIC connections to servers (stream by stream, HTTP/3 to origins) never move to
  a new local address, having no reason to; they move to a server's preferred address as any
  client does, and do not follow a server that moves to another address of its own accord (see
  the QUIC module's [README](https://github.com/mahmoudimus/MicroProxy/blob/main/quic/README.md)).
- HTTP/3 to servers only over direct connections, and without client certificates.
