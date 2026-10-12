# MITM, certificates and TLS

Intercept HTTPS: the proxy terminates the client's TLS with a certificate its own CA issues, and
opens its own TLS connection to the server, so filters, scripts and logs see the decrypted
requests. This page covers the CA, choosing a CA and upstream trust per client, how the ClientHello
decides what is intercepted, host rules, ALPN mirroring and the TLS versions the proxy allows. Use
it whenever you pass `--mitm` or `withManInTheMiddle(...)`.

## Turning interception on

From the command line, `--mitm` creates (or reuses) a CA in `microproxy-ca.p12` and writes its
certificate to `microproxy-ca.pem`. To intercept HTTPS without errors, add that certificate to
your client's trust store.

```bash
java -jar microproxy.jar --port 8080 --mitm
curl -x http://127.0.0.1:8080 --cacert microproxy-ca.pem https://example.com/
```

| Flag | Meaning |
|---|---|
| `--mitm` | intercept HTTPS with a generated CA |
| `--mitm-ca <file.p12>` | the CA key store (created if missing; default `./microproxy-ca.p12`); its certificate is written next to it as `<name>.pem` |
| `--mitm-ca-password <pw>` | the key store's password (default `microproxy`) |
| `--mitm-trust-all` | do not validate upstream server certificates |

From Java, give the bootstrap a `MitmManager`. `CertificateAuthorityMitmManager` issues per-host
certificates on demand (EC P-256), whose SANs copy the real server's DNS names, through a small
built-in X.509/DER encoder (`org.microproxy.tls.CertificateBuilder`): only the JDK is used. It
validates real servers against the JDK trust store unless given another upstream context:

```java
CertificateAuthority ca = CertificateAuthority.loadOrCreate(
        Path.of("microproxy-ca.p12"), "microproxy".toCharArray(), "MicroProxy CA");
ca.writeCertificatePem(Path.of("microproxy-ca.pem"));       // for clients to trust
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))            // JDK trust store
        // .withManInTheMiddle(new CertificateAuthorityMitmManager(ca, SslContexts.trustAll()))  // --mitm-trust-all
        .start();
```

`CertificateAuthority.generate(commonName)` makes a CA in memory. For servers signed by a
private CA, `SslContexts.systemDefaultPlus(caCert)` trusts the JDK's roots plus extra anchors
([Upstream proxies and NO_PROXY](chained-proxies.md#upstream-proxies-and-no_proxy)), and
`SslContexts.trusting(anchors...)` only the given ones. Hosts that must never be intercepted
(banks, pinned apps) are left alone with [host rules](#ignoring-and-allowing-hosts) or a filter.

## Interception per client connection

The proxy hands every `MitmManager` call the client connection's `FlowContext`, with its
authenticated user (`getClientDetails().getUserName()`) and address (`getClientAddress()`). Two
ways to use it:

- **One manager per tenant:** `MitmManager.perConnection(flow -> ...)` picks a manager when a
  connection is first intercepted and keeps it for that connection. Return the same instance for
  clients that may share server connections; `null` tunnels without interception.

  ```java
  Map<String, MitmManager> byTenant = Map.of(
          "alice", new CertificateAuthorityMitmManager(aliceCa, aliceUpstreamContext),
          "bob", new CertificateAuthorityMitmManager(bobCa, bobUpstreamContext));
  MicroProxy.bootstrap()
          .withProxyAuthenticator(authenticator)
          .withManInTheMiddle(MitmManager.perConnection(
                  flow -> byTenant.get(flow.getClientDetails().getUserName())))
          .start();
  ```

- **One manager deciding per call:** override the `FlowContext` overloads,
  `serverSslContext(host, port, flow)` (upstream trust store and client certificate; `flow` is a
  `FullFlowContext` naming the server and route), `clientSslContextFor(connect, session, flow)`
  (the certificate shown to the client) or `configureServerSocket(socket, flow)`. They default to
  the methods without `FlowContext`, so existing managers work unchanged. `shouldIntercept(hello,
  flow)` decides by the client's ClientHello whether to intercept at all (see
  [below](#deciding-what-to-intercept-the-clienthello)).

An upstream context with a key (`SslContexts.withKey(key, chain, trustManagers)`) presents that
client certificate to servers that ask for one.

With `withPoolSharedMitmConnections(true)`, a pooled TLS connection carries the trust and client
certificate it was made with, so the pool keeps them apart. Connections made by a manager chosen
with `forConnection` (which `perConnection` uses) are pooled under that manager and only reused by
clients given the same one. A manager overriding `serverSslContext(host, port, flow)` or
`configureServerSocket(socket, flow)` may decide differently for every client, so its server
connections are not pooled: each client connection keeps its own. Overriding only
`clientSslContextFor(..., flow)` does not affect pooling.

## Deciding what to intercept: the ClientHello

With a MITM manager, a `CONNECT` is not intercepted blindly. The proxy connects to the server (TCP,
and through any chained proxy), answers `200`, and reads what the client sends first without
consuming it, as mitmproxy does:

- **A TLS ClientHello** is read across as many TLS records as it spans (post-quantum key shares
  make it several), up to 64 KiB and within the TLS handshake timeout, and parsed into a
  `ClientHello`: the server name (SNI), the ALPN protocols, the TLS versions and the cipher
  suites, GREASE values included. The rules below decide whether to intercept. If they do, the
  proxy shakes hands with the server first and then with the client, replaying the bytes it read
  into the JDK's handshake with `SSLSocketFactory.createSocket(socket, consumed, autoClose)`. If
  not, the bytes are relayed to the server first and the connection is a plain tunnel, so the
  client sees the real server's certificate.
- **Plain HTTP** (a request line, as a `ws://` WebSocket through a proxy sends) is served as
  HTTP: its requests go to the `CONNECT` target through the filters, as in an intercepted session
  but without TLS. Absolute-form requests and `CONNECT`s in it are proxy requests for that target,
  which the client takes for its HTTP proxy ([In front of an HTTP or HTTPS
  proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)). With `--littleproxy-compat` it is tunnelled, as
  LittleProxy does.
- **Anything else** is tunnelled, the bytes read so far first: other protocols, HTTP/2 with prior
  knowledge, and a malformed or oversized ClientHello. A server that speaks first (SMTP, SSH) is
  noticed while the proxy waits for the client, and its connection is tunnelled as well.

So it goes, too, for a tunnel that a client asks its own proxy for inside a session MicroProxy
serves, once that proxy has opened it: everything then reaches the target through that proxy's
tunnels ([In front of an HTTP or HTTPS proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)).

Interception is decided in this order; the first "no" tunnels the connection untouched:

1. `HttpFilters.proxyToServerAllowMitm()` and the [ignore rules](#ignoring-and-allowing-hosts)
   against the `CONNECT` target, when the `CONNECT` arrives. Nothing is read from the client
   then, as before.
2. With the ClientHello: the host rules against the `CONNECT` target and the SNI; a client whose
   ALPN offers no protocol the proxy speaks (only `acme-tls/1`, say; with a
   [TCP interceptor](tcp-hooks.md#raw-tcp-streams), such clients are intercepted, except `acme-tls/1`, and
   their sessions relayed as raw TCP); then `MitmManager.shouldIntercept(clientHello, flow)` and
   `HttpFilters.proxyToServerAllowMitm(clientHello)`.

```java
MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca))
        .withIgnoreHosts("\\.bank\\.example:443$")                  // --ignore-hosts, ignore_hosts
        .withFiltersSource((request, flow) -> HttpFilters.builder()
                .allowMitmFor(hello -> !"pinned.example.com".equals(hello.sni()))
                .build())
        .start();
```

`FlowContext.getClientHello()` then returns the ClientHello to the session's requests, and to
`MitmManager.clientSslContextFor(connect, session, flow)`. Scripts get `on_client_hello` and
`ctx.client_hello` (see [Scripting](scripting.md)).

The same applies to a `CONNECT` stream of an HTTP/2 client ([CONNECT and
WebSockets](http2.md#connect-and-websockets)). A `CONNECT` inside an intercepted session, or inside a plain
HTTP one, goes to the session's server instead ([In front of an HTTP or HTTPS
proxy](chained-proxies.md#in-front-of-an-http-or-https-proxy)): the tunnel it opens is intercepted without reading
its ClientHello, unless the host rules ignore its target.

### Server TLS failures

As the server handshake waits for the ClientHello, it now happens after
the `CONNECT` is answered. A server whose certificate fails validation, or that refuses the
proxy's TLS versions, no longer fails the `CONNECT` with `502`. The client's handshake completes
with a certificate made from the host name, and each request inside the session is answered
`502` (`ProxyFailure.TlsFailed`, through `proxyToServerFailure` and the `FailureResponder`), as
mitmproxy answers. A server that turns out not to speak TLS gets the client's bytes tunnelled.
Unreachable servers still fail the `CONNECT`, since it is connected before it is answered. For
filters, `proxyToServerConnectionSSLHandshakeStarted` comes after the `CONNECT`'s `200`, and the
`CONNECT` exchange completes (`proxyToClientResponseSent`, `responseCompleted`) once the server
handshake is over, so its timings include that handshake.

### Ignoring and allowing hosts

`withIgnoreHosts(...)` (`--ignore-hosts`, `ignore_hosts`) and `withAllowHosts(...)`
(`--allow-hosts`, `allow_hosts`) work as mitmproxy's options of the same names. Each pattern is a
regular expression searched for (not matched whole), ignoring case, in the connection's `host:port`
names: the `CONNECT` target, and the client's SNI with the same port. An ignored connection is
tunnelled untouched. With allow patterns, only connections that one of them finds are
intercepted, and the ignore patterns still apply to those.

| Pattern | Ignores |
|---|---|
| `example\.com` | `example.com:443`, `www.example.com:443`, `example.com.evil.test:443` |
| `^(.+\.)?example\.com:443$` | `example.com` and its subdomains, on port 443 only |
| `^10\.` | `CONNECT`s to `10.x.x.x` addresses, whatever their SNI |

On the command line each flag takes one pattern and may be repeated; in a properties file the
patterns are separated by commas (commas inside `{...}` belong to the pattern). A `CONNECT` whose
target an ignore pattern finds is tunnelled without reading its ClientHello at all. The rules
apply to TLS and QUIC only: plain HTTP requests are proxied as usual. For QUIC the names are the
server and the SNI on the server's port: [transparent QUIC](transparent-mode.md#transparent-quic)'s flows, and, with
[`--masque-intercept-quic`](masque.md#quic-inside-connect-udp-flows), the QUIC inside CONNECT-UDP flows, an
ignored one being relayed as any UDP flow is.

### ALPN mirroring

When intercepting, the server is offered only the ALPN protocols the client offered, of those the
proxy speaks and has enabled: `http/1.1`, `http/1.0`, and `h2` only with
[HTTP/2 to servers](http2.md#http2-to-servers) on. The client's own handshake then mirrors the server's
choice when that choice tells what the server speaks, that is, when the server was offered `h2`.

| Client offers | Server offered | Server picks | Client gets |
|---|---|---|---|
| `http/1.1` | `http/1.1` | `http/1.1` | `http/1.1`: never HTTP/2 upstream |
| `h2`, `http/1.1` | `h2`, `http/1.1` | `h2` | `h2` (with `--http2`): HTTP/2 end to end |
| `h2`, `http/1.1` | `h2`, `http/1.1` | `http/1.1` | `http/1.1`, the same as the server |
| `h2`, `http/1.1` (no `--http2-upstream`) | `http/1.1` | `http/1.1` | `h2` with `--http2`: the proxy translates |
| no ALPN | `h2`, `http/1.1` with `--http2-upstream`, else none | either | no protocol (HTTP/1.1) |

This follows mitmproxy's order (`tlsconfig.py`: the server's handshake first, with the client's
offers, then the client's with the server's choice). Two differences: a client that sends no ALPN
keeps the proxy's old offer, so HTTP/1.1 clients without ALPN (such as the JDK's `HttpClient`)
still reach HTTP/2 servers; and where the server was not offered `h2`,
clients still get HTTP/2 when `--http2` allows it. Without a server connection of its own, the
session mirrors nothing: an existing HTTP/2 connection the session shares (a client that did not
offer `h2` gets none of it, and its requests connect with its own offers), a reused pooled
connection, or offline interception. The session's requests that connect later offer the same
protocols.

## TLS protocol versions

Every TLS socket the proxy creates allows only `TLSv1.3` and `TLSv1.2` by default: the TLS
listener (`withSslContextSource`), both sides of an intercepted session (towards the client and
towards the server) and connections to TLS chained proxies. `withTlsProtocols(...)` (or
`tls_protocols=...`, `--tls-protocols ...`) changes the list:

```java
MicroProxy.bootstrap().withTlsProtocols("TLSv1.3").start();   // TLS 1.3 only
MicroProxy.bootstrap().withTlsProtocols().start();            // each SSLContext's own defaults
```

- **Per socket:** each socket enables the listed versions its `SSLContext` supports, in the order
  given. If it supports none of them, the handshake fails with an error naming both lists (a
  `TlsFailed` towards servers, a failed handshake towards clients).
- **Order:** the versions are set right after the socket is created, before
  `SslContextSource.configure`, `MitmManager.configureServerSocket` and `ChainedProxy.configure`
  run. A hook that sets its own protocols therefore wins.
- **The JDK still applies** `jdk.tls.disabledAlgorithms`, which turns off TLS 1.1 and older,
  whatever is listed here.
- **Resumption over TCP is the JDK's.** TLS over TCP (HTTPS, HTTP/2, intercepted sessions, TLS
  chained proxies) runs on the JDK's `SSLEngine`, which resumes sessions on its own: each
  `SSLContext` caches sessions (`SSLSessionContext`, `javax.net.ssl.sessionCacheSize`,
  `jdk.tls.server.enableSessionTicketExtension` for stateless TLS 1.3 tickets) and offers them
  when it connects to the same server again. The proxy adds nothing to it, and the JDK sends and
  accepts no 0-RTT data. QUIC's TLS is the `quic` module's own, with its own tickets and 0-RTT
  ([Session resumption and 0-RTT](http3.md#session-resumption-and-0-rtt)).
- A server that refuses the proxy's versions with a `protocol_version` alert gets the requests
  inside the session a `502` (`TlsFailed`; see [server TLS
  failures](#deciding-what-to-intercept-the-clienthello)). One that just closes the connection on
  the proxy's `ClientHello` looks like a server that does not speak TLS, and the client's bytes
  are tunnelled without interception, as for any non-TLS server.
