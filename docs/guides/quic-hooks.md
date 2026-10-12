# QUIC stream hooks

Intercept QUIC that does not carry HTTP/3 (DNS over QUIC, `hq-interop`, protocols of your own) and
see, rewrite, drop and add its stream bytes, whole framed messages and datagrams. Use this page for
non-HTTP QUIC arriving through [transparent QUIC](transparent-mode.md#transparent-quic) or
[CONNECT-UDP flows](masque.md#quic-inside-connect-udp-flows); scripts use the [`on_quic_*`
hooks](scripting.md#quic-hooks).

## Intercepting QUIC stream by stream

QUIC that does not carry HTTP/3 can be intercepted too, stream by stream:
`withQuicInterceptor(QuicInterceptor)` (or a script's [`on_quic_*`](scripting.md#quic-hooks) hooks) makes the
proxy intercept the [transparent QUIC](transparent-mode.md#transparent-quic) flows, and the QUIC inside
[CONNECT-UDP flows](masque.md#quic-inside-connect-udp-flows) with `--masque-intercept-quic`, whose ALPN
offers no `h3` (`doq`, `hq-interop`, a protocol of its own), once the other rules allow it, as the
[TCP hooks](tcp-hooks.md#raw-tcp-streams) do for TLS that carries no HTTP. `withQuicHosts(...)` (`--quic-hosts`,
`quic_hosts`) names hosts, by regular expressions searched for in the server's host name and the
SNI, whose QUIC is relayed this way whatever its ALPN: their HTTP/3 too, which filters and frame
hooks then do not see, and their other QUIC even without an interceptor.

```java
MicroProxy.bootstrap()
        .withTransparent(true)
        .withTransparentQuicPort(8443)
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withQuicHosts("^quic\\.example\\.com$")                         // --quic-hosts, quic_hosts
        .withQuicInterceptor(new QuicInterceptor() {
            @Override
            public void quicStart(QuicContext ctx) {
                log("QUIC " + ctx.alpn() + " to " + ctx.host() + ":" + ctx.port() + " (" + ctx.sni() + ")");
            }

            @Override
            public byte[] streamData(QuicStreamMessage msg, QuicStreamContext stream) {
                return stream.clientInitiated() && !msg.fromClient()
                        ? msg.text().replace("secret", "******").getBytes(UTF_8) : msg.data();
            }

            @Override
            public byte[] datagram(QuicDatagram datagram, QuicContext ctx) {
                return datagram.length() > 1000 ? null : datagram.data();   // drop large ones
            }
        })
        .start();
```

- **Pairing the connections.** The proxy first connects to the server, from a UDP socket of the
  flow's own, with the client's SNI and ALPN protocols, validating the server as it validates
  [HTTP/3 servers](http3.md#http3-to-servers) (the MITM manager's server trust). Then it completes the
  client's handshake with a certificate its CA issues for the SNI, choosing the protocol the
  server chose, and taking DATAGRAM frames only when the server does. A server that cannot be
  reached drops the flow, as a relay that cannot be made does.
- **Streams.** Each stream one side opens, bidirectional or unidirectional, is opened on the
  other connection when the peers' stream limits allow it, in order, so the stream IDs on both
  connections are usually the same (`QuicStreamContext.streamId()` is the client's,
  `serverStreamId()` the server's). The hooks: `quicStart`; `streamOpened`; `streamData` for the
  bytes of each read, which returns the bytes to pass on (`msg.data()` as it is or changed in
  place, others, or `null` or an empty array to drop them); `streamFinished` before a FIN is passed
  on; `streamReset` (RESET_STREAM, passed on with its code) and `streamStopped` (STOP_SENDING:
  the other side is asked the same, and the stream reset towards the side that asked); `datagram`
  for each datagram, which returns the payload or `null`; then `quicEnd`, or `quicError` when a
  connection timed out, was reset or failed with a transport error, never both. When one side
  closes its connection, the other is closed with the same application error code and reason.
- **Adding data.** `QuicStreamContext.send(fromClient, bytes)` writes bytes to a stream as if that
  side had sent them, after the message being handled when called from a `streamData` of the same
  direction; `QuicContext.sendDatagram(fromClient, bytes)` sends a datagram. Neither passes
  through the hooks.
- **Messages.** A stream is a byte stream, as TCP is: a `QuicStreamMessage` is whatever one read
  returned (at most 16 KiB), so a peer's write may show up in pieces, or joined with the next one.
  Hooks that look for a protocol's messages keep the start of one until its end arrives, or let
  the proxy cut the stream into messages for `streamMessage`
  ([QUIC message framing](#quic-message-framing)).
- **Flow control.** End to end: each direction of each stream is read only as fast as the other
  side takes the bytes, so QUIC's flow control holds a fast sender back while a slow receiver
  reads, and the proxy keeps at most one read per direction. The proxy's receive windows are
  HTTP/3's (`Http3Options.streamReceiveWindow`, `connectionReceiveWindow`).
- **Threads.** Each direction of each stream, and of datagrams, has a virtual thread of its own:
  the interceptor must be thread-safe; within one direction of one stream, calls come in order.
  The context names the client connection (`connectionId`, `clientAddress`, `flowContext`), the
  server (`host`, `port`, `serverAddress`), `sni`, `alpn` and `masque()`.

## QUIC message framing

A stream's bytes come to `streamData` in reads, without the protocol's message boundaries. Many
protocols over QUIC frame their messages simply, and the proxy can cut their streams into whole
messages for a hook: `QuicInterceptor.streamMessage(QuicMessage msg, QuicStreamContext stream)`
(or a script's [`on_quic_message`](scripting.md#quic-hooks)) sees each message's payload, without its length
prefix or delimiter, and returns the messages to send in its place. What it returns is framed
again, so an edited payload gets a length prefix of its new length.

`--quic-framing` (`quic_framing`, `withQuicFraming(QuicFraming)`) chooses a framer by ALPN or by
host: comma-separated `key=framer` rules, where a key is an ALPN protocol (`doq`), a host name
matched against the server's host and the SNI (`dns.example.com`, or `*.example.com` for it and
the names below it), or `*` for any connection. A host rule wins over an ALPN rule, which wins
over `*`. DNS over QUIC (`doq`) is framed with `u16` by default; `doq=none` turns that off.

| Framer | Messages |
|---|---|
| `u16` | a two-byte big-endian length, then the payload: DNS over QUIC (RFC 9250), DNS over TCP |
| `u32` | a four-byte big-endian length, then the payload |
| `varint` | a QUIC variable-length integer (RFC 9000 section 16) as the length; written in its shortest form |
| `lf` | a line ending with a line feed, which the payload leaves out (a carriage return before it stays) |
| `crlf` | a line ending with a carriage return and a line feed |
| `none` | not framed: `streamData` sees the reads |
| `script` | a script's `quic_message_length(data)` (see [QUIC](scripting.md#quic-hooks)) |
| a `MessageFramer` | from Java: `framing.withRule("myproto", framer)` or `withFramer(name, framer)` |

```bash
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 \
    --transparent --transparent-quic-port 8443 --mitm --script doq.star \
    --quic-framing doq=u16,myproto=varint,*=none --quic-max-message-size 65537
```

- **Which streams.** Every stream of a connection whose framing rule names a framer, when the
  interceptor overrides `streamMessage` (a script, when it defines `on_quic_message`). Framing
  replaces the chunk hook there: `streamData` (`on_quic_stream_data`) is not called on those
  streams, and is called as before on the streams of other connections. An interceptor that does
  not override `streamMessage` is never framed, whatever the rules say: **without framing, or
  without a message hook, nothing is kept**, and each read goes on as it came.
- **What a hook returns.** `List.of(msg)` passes the message on (changed in place or not); other
  messages replace it, in order; `null` or an empty list drops it. A message whose `fromClient()`
  is the other direction's (`msg.withFromClient(false)`) goes to the side that sent `msg`, on the
  same stream, as if the other side had answered. `QuicStreamContext.send` still writes bytes as
  they are, not framed. A hook that throws, or returns a payload its framer cannot frame (more
  than 65535 bytes for `u16`), has the message passed on unchanged.
- **Limits.** A message larger than `--quic-max-message-size` (`quic_max_message_size`,
  `QuicFraming.withMaxMessageSize`; 1 MiB, the prefix or delimiter included), known from a length
  prefix as soon as it arrives or from a delimiter that does not come in time, and bytes a framer
  cannot read (a custom framer that throws), **reset the stream** in both directions on both
  connections, and ask both sides to stop sending, with `--quic-message-error-code`
  (`quic_message_error_code`, `withErrorCode`; 2, DNS over QUIC's `DOQ_PROTOCOL_ERROR`), as a
  WebSocket message too big closes its connection with 1009. The connection and its other
  streams go on. Bytes left over when a side finishes its stream, not a whole message, are passed
  on as they are, before the FIN.
- **Flow control** stays end to end: a direction keeps at most one message's bytes and a read.
- **Datagrams** are whole messages already: `datagram` (`on_quic_datagram`) sees them as before.
- **Decoding.** `QuicMessage` has `data()`, `text()`, `fromClient()`, `streamId()`, `alpn()`,
  `timestamp()`, the copies `withData`, `withText`, `withFromClient` and `withDns`, and decoders:
  `dns()` reads the payload as a DNS message (`org.microproxy.dns.DnsMessage`: the header, the
  questions, and records with typed data for A, AAAA, NS, CNAME, PTR, DNAME, MX, SRV, TXT and
  SOA; it encodes back, names compressed); `protobuf()` and `protobuf(schema, type)` decode
  protobuf as the [content views](content-views.md#content-views) do; `render()` renders the payload with the
  best content view, as `dig` shows it for DNS over QUIC (the `dns` view), for logging.

DNS over QUIC, logging each query and answering a blocked name with `0.0.0.0` by rewriting the
server's answer:

```java
Set<String> blocked = Set.of("ads.example", "tracker.example");
bootstrap.withQuicInterceptor(new QuicInterceptor() {
    @Override
    public byte[] streamData(QuicStreamMessage msg, QuicStreamContext stream) {
        return msg.data();                                  // streams that are not framed
    }

    @Override
    public List<QuicMessage> streamMessage(QuicMessage msg, QuicStreamContext stream) {
        DnsMessage dns = msg.dns();
        DnsMessage.Question q = dns.questions().getFirst();
        if (msg.fromClient()) {
            log(stream.clientAddress() + " asks for " + q.name() + " " + q.typeName());
            return List.of(msg);
        }
        if (!blocked.contains(q.name().toLowerCase(Locale.ROOT))) return List.of(msg);
        List<DnsMessage.ResourceRecord> answers = dns.answers().stream()
                .map(r -> r.type() == DnsMessage.A ? r.withData(DnsMessage.Address.of("0.0.0.0")) : r)
                .toList();
        return List.of(msg.withDns(dns.withAnswers(answers)));   // framed again, its length recomputed
    }
});
```
