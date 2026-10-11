# quic

A dependency-free QUIC transport for JDK 21 and newer: RFC 9000 (transport), RFC 9001 (TLS for QUIC)
and RFC 9002 (loss detection and congestion control), with its own TLS 1.3 handshake, since the JDK's
`SSLEngine` cannot carry TLS in QUIC CRYPTO frames or hand out the traffic secrets QUIC needs.

The design follows [quinn](https://github.com/quinn-rs/quinn)'s `quinn-proto` (a sans-I/O state
machine) and the TLS 1.3 client and server of [rustls](https://github.com/rustls/rustls), both used
under the Apache License 2.0. Cryptography comes from the JDK: AES-GCM, ChaCha20-Poly1305, HMAC for
HKDF, X25519 and P-256, ECDSA, RSA-PSS and Ed25519.

The module is in progress; this README grows with it.

## TLS 1.3 handshake

`io.github.mahmoudimus.quic.tls` is a TLS 1.3 client and server for QUIC (RFC 8446, RFC 9001),
ported from rustls (`client/`, `server/`, `tls13/key_schedule.rs`, `msgs/`, `quic.rs`) with the
sans-I/O session interface of quinn's `crypto::Session`. There is no record layer: handshake bytes
travel in CRYPTO frames per encryption level, and the traffic secrets go to packet protection.

```java
TlsConfig clientConfig = TlsConfig.builder()
        .serverName("example.com")          // SNI and the name the certificate must match
        .alpnProtocols("h3")                // required: QUIC always negotiates ALPN
        .build();                           // JDK default trust manager, host name verification
TlsSession client = TlsSession.client(clientConfig, encodedTransportParameters);

TlsConfig serverConfig = TlsConfig.builder()
        .certificateSelector(hello -> mintCertificateFor(hello.serverName()))  // or certificate(chain, key)
        .alpnProtocols("h3")                // preference order, or alpnSelector(hello -> ...)
        .build();
TlsSession server = TlsSession.server(serverConfig, encodedTransportParameters);

// The connection layer's loop, on each side:
session.readHandshake(level, cryptoFrameData);       // in-order CRYPTO bytes, any fragmentation
for (Secrets s; (s = session.nextSecrets()) != null; ) installKeys(s);
byte[] toSend = session.writeHandshake(level);       // for each level
```

- **Secrets.** `nextSecrets()` hands out `Secrets(level, suite, client, server)` in order. A client
  gets the Handshake secrets after the ServerHello and the 1-RTT secrets after the server's
  Finished, when it has queued its own and the handshake is complete. A server gets both after the
  ClientHello, its flight ending with its Finished queued: it may send 0.5-RTT data, but must not
  process the client's 1-RTT packets before `isHandshakeComplete()` (RFC 9001 section 5.7).
  Confirming the handshake (HANDSHAKE_DONE) and dropping keys are the connection's job.
- **Key update.** `nextOneRttSecrets()` moves both 1-RTT secrets on a generation with
  `HKDF-Expand-Label(secret, "quic ku", "", Hash.length)`.
- **Results.** `peerTransportParameters()` (opaque bytes: the connection layer encodes and
  decodes them), `negotiatedAlpn()`, `serverName()` (the client's SNI, on the server),
  `peerCertificates()`, `peerSignatureScheme()`, `cipherSuite()`, `negotiatedGroup()`,
  `usedHelloRetryRequest()` and `exportKeyingMaterial(label, context, length)` (RFC 8446 section 7.5).
- **Errors.** Everything fails with `QuicException`. TLS alerts become `CRYPTO_ERROR` codes, `0x0100 +
  alert` (`TlsAlert` names them): `decode_error` for malformed messages, `unexpected_message` for
  messages out of order or at the wrong level, `illegal_parameter`, `missing_extension` (no
  `quic_transport_parameters`, among others), `unsupported_extension` for unsolicited ones,
  `no_application_protocol`, `protocol_version` without TLS 1.3, `bad_certificate`, `unknown_ca`,
  `certificate_expired`, `certificate_unknown`, `decrypt_error` for a bad CertificateVerify or
  Finished (compared in constant time), `handshake_failure` with nothing in common. A message body
  over `maxHandshakeMessageSize` (64 KiB by default) is `CRYPTO_BUFFER_EXCEEDED`; a ClientHello with
  a `legacy_session_id` is `PROTOCOL_VIOLATION` (RFC 9001 section 8.4).
- **Threads.** A session is a single-threaded state machine and takes no locks; configurations are
  immutable and shared.

| | Supported |
|---|---|
| Cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| Key exchange | X25519, secp256r1, secp384r1; HelloRetryRequest (with `message_hash` and cookie echo) when the client's key share is not one the server takes |
| CertificateVerify | `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `rsa_pss_rsae_sha256/384/512`, `ed25519`; `rsa_pkcs1_*` is advertised for certificate chains only |
| Extensions | `server_name`, `supported_groups`, `signature_algorithms` (`_cert` parsed), ALPN, `supported_versions`, `key_share`, `cookie`, `quic_transport_parameters` (0x39), `psk_key_exchange_modes` (parsed only) |
| Certificates | client: an `X509TrustManager` (the JDK default by default) plus host name verification as HTTPS does it, or `trustAllCertificates(true)` for tests; server: one `CertifiedKey` or a per-ClientHello selector (`ClientHelloInfo`: SNI, ALPN, signature schemes, suites, groups) |
| Client authentication | `clientAuth(REQUEST or REQUIRE)` with a `clientTrustManager`; the client presents `clientCertificate(...)` |

Validation follows rustls: message order, TLS 1.3 only, the null compression method, an empty
`legacy_session_id` echo, repeated extensions, extensions not offered or not allowed in a message,
key shares in `supported_groups`, the cipher suite and group kept across a retry, no renegotiation and
no KeyUpdate message (QUIC has its own key update). No middlebox compatibility mode and no
EndOfEarlyData, as RFC 9001 requires.

Tests check the key schedule, Finished values and transcript (including the HelloRetryRequest
`message_hash`) against RFC 8448 sections 3 and 5, run in-memory handshakes for every suite, group and
signature scheme with randomly fragmented CRYPTO data, and fuzz the decoders from a fixed seed.

Out of scope for now, as follow-ups: session resumption, PSKs, 0-RTT and session tickets (a server sends
no NewSessionTicket; a client checks and ignores the ones it gets), `rsa_pss_pss` schemes, secp521r1
and ML-KEM hybrids, certificate compression, OCSP stapling and raw public keys.
