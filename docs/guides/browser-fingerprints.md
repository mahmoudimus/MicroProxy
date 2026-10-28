# Browser fingerprints

Make the proxy's connections to servers look like a browser's: its TLS ClientHello (JA3, JA4),
its HTTP/2 connection preface (the Akamai fingerprint), its QUIC and HTTP/3 connections, and its
request headers. Use this page when servers or CDNs treat the proxy differently from a browser
because of how its connections look. Use [MITM, certificates and TLS](mitm.md) for the
interception itself.

A server sees the proxy's own TLS stack by default, the JDK's for TCP and the `quic` module's
for QUIC. With a `BrowserProfile`, each layer presents that browser's fingerprint instead:

| Layer | What changes | Configured by |
|---|---|---|
| TLS over TCP | cipher suites, extensions and their per-connection shuffle, GREASE, X25519MLKEM768 and X25519 key shares, ALPS, certificate compression, Trust Anchor IDs, GREASE ECH | `BrowserProfile.sslContext` |
| HTTP/2 | SETTINGS in order, the connection WINDOW_UPDATE, HEADERS priority (per request, for Firefox), pseudo-header order, the first stream id, `te: trailers` | carried by the same context |
| QUIC | its ClientHello, transport parameters (in shuffled order, with GREASE), connection ID lengths, 1250-byte Initial packets numbered from 1, chaos protection of the ClientHello | `Http3Options.upstreamProfile` |
| HTTP/3 | SETTINGS with a GREASE setting, a GREASE frame, PRIORITY_UPDATE, lazily opened QPACK streams, pseudo-header order | `Http3Options.upstreamProfile` |
| Requests | the browser's headers in its order, its User-Agent, no `Via` | `BrowserProfile.filtersSource` |
| ECH | the ClientHello encrypted to servers whose ECHConfigList you supply (RFC 9849) | `BrowserProfile.sslContext(trust, ech)` |

```java
BrowserProfile chrome = BrowserProfile.chrome156();
HttpProxyServer proxy = MicroProxy.bootstrap()
        .withManInTheMiddle(new CertificateAuthorityMitmManager(ca, chrome.sslContext(null)))
        .withHttp3Upstream(true)                                                   // optional
        .withHttp3Options(Http3Options.builder().upstreamProfile(chrome).build())  // QUIC and HTTP/3 too
        .withFiltersSource(chrome.filtersSource(true))                             // its headers and User-Agent
        .start();
```

Each profile is built from captures of the browser itself, and checked against them:

| Profile | Browser | JA4 | Akamai HTTP/2 | QUIC and HTTP/3 |
|---|---|---|---|---|
| `chrome156()` | Chrome 156.0.8078.48, macOS | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | yes, JA4 `q13d0312h3_55b375c5d22e_178839b6cec1` |
| `firefox159()` | Firefox 159.0, macOS | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | yes, JA4 `q13d0315h3_55b375c5d22e_dc5437974b47` |

Through the proxy, tls.peet.ws reports each browser's own JA4 and Akamai fingerprint. JA3 matches
too, with one difference between the browsers. Chrome shuffles its extensions on every
connection, so its JA3 hash changes each time, the profile's as well as the browser's; it is the
same once the extension list is put in order, which is why JA4 sorts it. Firefox keeps a fixed
order, so its JA3 hash is the same on every connection: `9d42e90b0225e779f03141ddcd699df2` for a new
one, `a55f6cb044839f48d371a56323ed22ef` for one that resumes a session.

Browsers move to HTTP/3 on servers that advertise it, so a proxy that should look like one
throughout turns HTTP/3 to servers on (`withHttp3Upstream(true)`) with the same profile in
`Http3Options.upstreamProfile`; with it off, those servers see the browser over HTTP/2 only.

The two browsers' QUIC differs as much as their TLS. Chrome cuts its ClientHello into shuffled
CRYPTO frames among PING and PADDING frames, numbers its packets from 1 and pads its 1250-byte
Initials inside the packet. Firefox (neqo) cuts its ClientHello at the middle of the server name
and sends the halves in reverse order, starts at a random packet number, sends 1252-byte Initials
over IPv4 (1232 over IPv6) padded with zero bytes after the packet, and lists QUIC version 2 among
its versions; a server may move the connection to it (RFC 9368), as LiteSpeed's do, and the
profile's connections follow.

## How it works

`BrowserProfile.sslContext` returns an `SSLContext` whose sockets run the proxy's own TLS client
with the browser's ClientHello. Anything that takes a client `SSLContext` can use it, not only
MicroProxy.
- **TLS 1.3:** the client also answers what the browser's hello invites from a server: ALPS, compressed
  certificates (Brotli, zlib and, with `zstd-decoder` on the class path, zstd), KeyUpdate, and
  resumption with the session tickets the context keeps.
- **TLS 1.2:** used when a server selects it. The supported suites are ECDHE with RSA or ECDSA, and RSA
  key exchange; with AES-GCM, ChaCha20-Poly1305 or AES-CBC. It includes the extended master secret
  and session tickets.
- **What only Firefox's hello invites:** a server's delegated credential (RFC 9345), checked as
  Firefox checks one; P-521 key exchange and signatures; a TLS 1.2 ServerKeyExchange signed with
  SHA-1, which Firefox still accepts; and a smaller `record_size_limit`.

The Firefox profile's transport parameters include `reset_stream_at`, as Firefox's do, but the
proxy's QUIC client does not take a RESET_STREAM_AT frame (draft-ietf-quic-reliable-stream-reset):
a server that sends one, which only WebTransport servers do, closes the connection with an error.

A resuming hello differs from a new one as the browser's does: both put `pre_shared_key` last,
and Firefox's leaves out `session_ticket` and sizes its GREASE ECH with the PSK.

The HTTP/2 profile travels with the context's sockets, so an HTTP/2 connection made over one opens
as the browser's does, and a `MitmManager` that returns different contexts for different servers
gives them different browsers. `Http2Options.upstreamProfile` sets one HTTP/2 profile for every
connection instead.

A connection holds itself to what the profile advertises: its HTTP/2 and QUIC flow-control windows,
HPACK and QPACK table sizes and stream limits become the browser's. A QUIC connection with a profile
has a UDP socket of its own, as a browser's does, since an empty source connection ID tells its
datagrams apart by address alone.

## What it does not change

- The client's request headers, unless `filtersSource` applies the browser's. It never adds
  `accept-encoding`, since a client that did not ask for an encoding could not read a body in it.
- Request header order beyond the browser's own headers, which come first; the client's others
  follow in its order.
- The cipher suites, which `setEnabledCipherSuites` on a socket does not change: they are part of
  the fingerprint.

## Certificates with Trust Anchor IDs

Chrome's hello advertises Trust Anchor IDs, so some servers send a shorter chain to it. Over QUIC,
Google's servers send the leaf alone, expecting the client to hold the intermediate. The JDK's trust
store does not have those intermediates. Either run with
`-Dcom.sun.security.enableAIAcaIssuers=true`, so that path building fetches a missing intermediate
from the certificate's AIA URL, or give `sslContext` a trust manager that has them.

## ECH

`sslContext(trust, ech)` encrypts the ClientHello to the servers whose `ECHConfigList` the
`EchConfigProvider` returns, and sends the browser's GREASE ECH to the rest. The proxy looks up no
DNS records itself: the provider decides where configs come from, such as the server's DNS `HTTPS`
record from the resolver you trust. A server that rejects ECH fails the handshake with
`EchRejectedException`, which carries its retry configs; nothing is retried automatically.

## Keeping profiles current

Browsers change their fingerprints every few releases; in 2026 Chrome added ML-DSA signature
schemes and Trust Anchor IDs. A profile is data, built from captures of the browser:
- `scripts/fingerprints/CaptureBrowser.java` records a browser's ClientHello and HTTP/2 preface;
  with `page`, it serves a page of subresources and records every request's HEADERS priority.
- `scripts/fingerprints/CaptureQuic.java` records its QUIC Initial datagrams and ClientHello, and
  `CaptureH3.java` its HTTP/3 control stream and first request.
- The fixtures under `quic/src/test/resources/fingerprints/` are what the tests compare the
  profiles with.
