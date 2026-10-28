# Firefox 159.0 (macOS) QUIC and HTTP/3 captures

Taken 2026-10-28 from Firefox 159.0, headless, on a fresh profile that trusts the capture CA, with
`network.dns.localDomains` mapping `quic.test` to loopback,
`network.http.http3.alt-svc-mapping-for-testing` sending `https://quic.test:PORT/` over HTTP/3,
and `network.http.http3.disable_when_third_party_roots_found` off (Firefox otherwise refuses
HTTP/3 to a server whose certificate chains to a root it does not ship).

- `quic-clienthello-N.bin`, `initial-datagram-N-0.bin`, `initial-datagram-N-1.bin`,
  `initial-layout-N.txt`: the first two Initial datagrams of four connections, their frames, and
  the ClientHello they carry (`scripts/fingerprints/CaptureQuic.java`).
- `h3-control-and-request-N.txt`: two HTTP/3 connections' unidirectional streams, control stream
  frames and first request (`scripts/fingerprints/CaptureH3.java`).
