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
| HTTP/2 | SETTINGS in order, the connection WINDOW_UPDATE, HEADERS priority, pseudo-header order | carried by the same context |
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

`chrome156()` is Chrome 156.0.8078.48 on macOS, captured from the browser itself. Through the
proxy, tls.peet.ws reports Chrome's own JA4, `t13d1517h2_8daaf6152771_cb7bf5808d99`, and its Akamai
fingerprint, `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. Over QUIC its JA4 is
`q13d0312h3_55b375c5d22e_178839b6cec1`.

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
- `scripts/fingerprints/CaptureBrowser.java` records a browser's ClientHello and HTTP/2 preface.
- The fixtures under `quic/src/test/resources/fingerprints/` are what the tests compare the
  profiles with.
