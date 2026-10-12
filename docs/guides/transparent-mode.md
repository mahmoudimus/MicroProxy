# Transparent mode

Proxy traffic that a firewall or gateway redirects to MicroProxy instead of sending it there: TLS
routed by its SNI, plain HTTP by its `Host`, and QUIC on a UDP port of its own, intercepted or
relayed. Use this page to set up a transparent proxy with iptables; the clients then need no proxy
settings, only the proxy's CA for intercepted hosts.

## Transparent TLS and HTTP

`--transparent` (`withTransparent(true)`, `transparent=true` or `mode=transparent`) is for
traffic redirected to the proxy rather than sent to it, by a firewall rule or a gateway. Besides
leaving out `Via` and keeping hop-by-hop headers, the listener then accepts:

- **TLS without `CONNECT`.** A connection that starts with a TLS record is routed by its
  ClientHello's SNI, to that host's port 443 (`--transparent-tls-port`, `transparent_tls_port`),
  and treated like a `CONNECT` to it: filters see a `CONNECT` the proxy made up (it gets no answer
  on the wire), and the host rules, hooks and interception apply. Without a MITM manager, such
  connections are tunnelled: an SNI proxy.
- **Plain HTTP**, routed by its `Host` field, when origin-form requests are allowed
  (`--allow-requests-to-origin-server`, `allow_requests_to_origin_server=true`), as before.
- **QUIC** on a UDP port of its own, with `--transparent-quic-port <port>`
  (`withTransparentQuicPort`, `transparent_quic_port`): routed by the SNI of the ClientHello in
  its first packets, then intercepted (HTTP/3, or other protocols stream by stream) or relayed by
  the same rules (see [Transparent QUIC](#transparent-quic)).

Java cannot read a redirected connection's original destination (Linux's `SO_ORIGINAL_DST`), so
the server is the one the SNI or the `Host` field names, not the address the client connected to.
The client choosing the server is by design here, as it is for any forward proxy: a transparent
proxy takes the client where it was going. Put it where only the clients it serves can reach it.
Inside an SNI-routed session, an absolute URI is a request for that session's server (as for a
proxy, [In front of an HTTP or HTTPS proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)), never for the URI's authority.
A ClientHello without SNI (clients connecting to an IP address send none) cannot be routed: the
proxy answers with a TLS `unrecognized_name` alert, closes the connection and reports it to
`ActivityTracker.connectionExceptionCaught`. Such clients cannot send proxy credentials: with
proxy authentication, their connections are closed unless the authenticator accepts them without.

Redirecting a machine's outgoing web traffic to a proxy on port 8080, running as the user `proxy`
so that its own connections are not redirected again:

```bash
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxy --dport 80 -j REDIRECT --to-ports 8080
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxy --dport 443 -j REDIRECT --to-ports 8080
# On a gateway, for the clients behind it (eth1), use PREROUTING instead:
#   iptables -t nat -A PREROUTING -i eth1 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 8080
sudo -u proxy java -jar microproxy.jar --server --port 8080 --transparent --mitm \
    --allow-requests-to-origin-server --ignore-hosts '\.bank\.example:443$'
```

Clients must trust the proxy's CA (`microproxy-ca.pem`) for the hosts that are intercepted. QUIC
(UDP 443) is not redirected by these rules: redirect it to a [transparent QUIC](#transparent-quic)
port too, or block it so that browsers fall back to TCP.

## Transparent QUIC

`--transparent-quic-port <port>` (`withTransparentQuicPort(port)`, `transparent_quic_port`, with
`--transparent`) opens a UDP listener for QUIC that a firewall redirects to the proxy: the UDP
counterpart of [transparent TLS](#transparent-mode). Java cannot read a redirected datagram's
original destination either, so each new client flow (a client address and the Destination
Connection ID of its first Initial packets) is routed by its SNI, to that host's
`--transparent-tls-port` (443).

- **Reading the ClientHello.** The proxy holds a new client's datagrams and decrypts its Initial
  packets with the keys their Destination Connection ID gives (RFC 9001 section 5.2, QUIC v1 and
  v2), without a handshake, as mitmproxy does. It puts the CRYPTO frames back together across
  packets and datagrams, in any order (browsers' post-quantum ClientHellos take two packets, their
  frames shuffled), and parses the same `ClientHello` that TLS over TCP gives.
- **Deciding**, as for transparent TLS: a `CONNECT sni:443` is made up for the flow (filters see
  it; `clientToProxyRequest` answering it drops the flow; `proxyToServerAllowMitm()` and
  `allow_mitm` may decline), then the [ignore and allow rules](mitm.md#ignoring-and-allowing-hosts),
  the client's ALPN (`h3` is served as HTTP/3; other protocols are intercepted
  [stream by stream](quic-hooks.md) with a `QuicInterceptor` or for the `--quic-hosts`, and
  relayed otherwise), `MitmManager.shouldIntercept(hello, flow)`, and
  `proxyToServerAllowMitm(hello)` / `on_client_hello` (the table below). A redirected client
  sends no proxy credentials: with an authenticator, it must accept clients without.
- **Intercepted** (HTTP/3 with a MITM manager, which must be a `CertificateAuthorityMitmManager`
  to issue QUIC's certificates): the held datagrams go to the proxy's QUIC server, whose handshake
  presents a certificate the CA issues for the SNI, and the connection is served HTTP/3 like a
  [reverse proxy's](http3.md#serving-http3-in-reverse-mode) clients, with its requests going to the SNI's
  host: over HTTP/3 with `--http3-upstream` (the proxy takes the client's HTTP/3 as the origin's
  advertisement, and falls back to TCP if its QUIC handshake fails), else over HTTP/2 or
  HTTP/1.1. Filters, scripts (`on_request`, `on_frame`, ...), logging and trackers see the
  requests, with `FlowContext.isTransparentQuic()` (and `ctx.transparent_quic`) true.
- **Intercepted stream by stream** (another ALPN such as DNS over QUIC's `doq` with a
  `QuicInterceptor`, or a `--quic-hosts` host): the proxy connects to the server first, then
  completes the client's handshake with the server's choice of ALPN, and relays the two
  connections' streams and datagrams through the [QUIC stream hooks](quic-hooks.md).
- **Relayed** (no MITM manager, an ignored or declined host, another ALPN without a
  `QuicInterceptor`): the datagrams go to the server untouched from a UDP socket of the flow's
  own, and the server's back to the client from the listener's socket, until the flow is idle for
  `--transparent-quic-relay-idle-timeout` (60 s). The client completes its handshake with the
  real server.
- **Demultiplexing.** One socket serves every client. Intercepted connections are routed by the
  connection IDs the proxy issued (so they survive the client moving to new ones); relayed flows
  by the client address and the connection IDs seen in their long headers, and otherwise to the
  client address's most recently active flow (servers issue more IDs in encrypted frames).
- **Clients that move** (QUIC connection migration, RFC 9000 section 9: a NAT that rebinds the
  client to a new port, a phone that goes from Wi-Fi to cellular, a client that migrates on
  purpose). An intercepted connection, HTTP/3 or [stream by stream](quic-hooks.md), follows
  its client as any QUIC server does: its datagrams are routed by connection ID from any address,
  the proxy validates the new path with PATH_CHALLENGE, sends there no more than three times what
  it received until the client answers, keeps the congestion state for a new port and starts it
  over for a new address, goes back to the old path if the new one does not answer, and answers
  from the new path. The proxy's own connection to the server (stream by stream, and HTTP/3 to
  origins) stays where it is. A relayed flow is harder: the proxy cannot read the client's packets,
  nor the encrypted frames in which the server gives the client the connection IDs it moves to.
  A short header packet from an address with no flow goes to the relayed flow that knows its
  connection ID (from any address), else to the flow of the same client IP address whose known
  server IDs share the longest prefix of at least 4 bytes with it (servers that encode routing in
  their IDs), else to that IP address's most recently active relayed flow, which is what a NAT
  rebinding needs. The flow then sends the server's datagrams to the new address, as a NAT sends
  replies to its latest mapping, and learns the client's new ID when the server's IDs all have
  one length. Limits: a relayed client that changes both IP address and connection ID is found
  only by an ID prefix; with several relayed flows from one IP address the fallback may pick the
  wrong one; and since the proxy can neither validate the new address nor tell a newer packet from
  a replayed one, a sender that can spoof the client's IP address with one of the flow's
  connection IDs can turn its replies elsewhere until the client sends again (the end-to-end
  connection stays the client's: the server, whose path to the proxy does not change, validates
  nothing). A server that sends `disable_active_migration` is not migrated away from by clients
  that honour it.
- **Versions.** A new client offering a version the proxy cannot read gets Version Negotiation
  (v1, v2), since its destination is in a ClientHello the proxy cannot decrypt; on an existing
  relayed flow, other versions are relayed like anything else.
- **Retry.** `--http3-retry` (`Http3Options.retry`) makes intercepted clients prove their address
  first. Relayed clients never get one: their server would refuse the proxy's token.

The decision, in order; the first row that applies decides:

| The flow | Becomes |
|---|---|
| A `clientToProxyRequest` answers the made-up `CONNECT`, or the authenticator refuses a client without credentials | dropped |
| No MITM manager, or `proxyToServerAllowMitm()` / `allow_mitm` declines | relayed |
| An [ignore or allow rule](mitm.md#ignoring-and-allowing-hosts) leaves out the server or the SNI | relayed |
| ALPN without `h3`, not a `--quic-hosts` host, and no `QuicInterceptor` (`on_quic_*`) | relayed |
| No SNI (only inside a CONNECT-UDP flow to an IP address), or no `CertificateAuthorityMitmManager` to issue the certificate | relayed |
| `MitmManager.shouldIntercept(hello, flow)` or `proxyToServerAllowMitm(hello)` / `on_client_hello` declines | relayed |
| A `--quic-hosts` host (whatever its ALPN, `h3` included) | intercepted [stream by stream](quic-hooks.md) |
| ALPN offering `h3` | intercepted as HTTP/3 |
| Any other ALPN (`doq`, `hq-interop`, a protocol of its own), with a `QuicInterceptor` | intercepted [stream by stream](quic-hooks.md) |

`ActivityTracker.transparentQuicFlowDecided` reports each decision (`intercepted` is true for
both kinds of interception, the reason saying why for stream by stream).
- **Bounds** (`Http3Options`): new clients held at once (1024, and 32 per client IP address, each
  holding 16 datagrams and 64 KiB at most, all together 8 MiB), how long one may take to send its
  ClientHello and be decided on (5 s), relayed flows (4096, and 256 per client IP address).
  Datagrams past a bound are dropped, as a full socket buffer would drop them.

```java
MicroProxy.bootstrap()
        .withTransparent(true)
        .withTransparentQuicPort(8443)                                   // --transparent-quic-port 8443
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withHttp3Upstream(true)                                         // HTTP/3 to origins too
        .withIgnoreHosts("\\.bank\\.example:443$")                         // relayed untouched
        .start();
```

Redirecting a gateway's clients' QUIC (`eth1`) to UDP port 8443, next to their TCP:

```bash
# REDIRECT (NAT): the proxy answers from its listener socket, and the kernel's connection
# tracking turns the replies' source back into the address the client sent to.
iptables -t nat -A PREROUTING -i eth1 -p udp --dport 443 -j REDIRECT --to-ports 8443
# On the proxy's own machine, its own QUIC (relays, HTTP/3 to origins) must not be redirected:
iptables -t nat -A OUTPUT -p udp -m owner ! --uid-owner proxy --dport 443 -j REDIRECT --to-ports 8443

# TPROXY keeps the original destination on the packet instead of rewriting it:
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -i eth1 -p udp --dport 443 -j TPROXY --on-port 8443 --tproxy-mark 1
```

### NAT

Use REDIRECT. With it, replies must leave from the socket the client's datagrams arrived
at, as the proxy's do, so that connection tracking maps them back; and the conntrack entry of a
UDP flow (`nf_conntrack_udp_timeout_stream`, 120 s by default) should outlive the relay's idle
timeout. TPROXY needs a listening socket with `IP_TRANSPARENT`, which the JDK cannot set, and
replies sent from the original destination address, which the JDK cannot do either: it does not
work with MicroProxy as it is. Relayed flows reach servers from a new UDP socket each, so a
firewall in front of the proxy sees each as a flow of its own. A client the NAT maps to a new port
is followed (see **Clients that move** above).
