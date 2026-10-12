# quic

A dependency-free QUIC transport for JDK 21 and newer: RFC 9000 (transport), RFC 9001 (TLS for QUIC)
and RFC 9002 (loss detection and congestion control), with its own TLS 1.3 handshake, since the JDK's
`SSLEngine` cannot carry TLS in QUIC CRYPTO frames or hand out the traffic secrets QUIC needs.

The design follows [quinn](https://github.com/quinn-rs/quinn)'s `quinn-proto` (a sans-I/O state
machine) and the TLS 1.3 client and server of [rustls](https://github.com/rustls/rustls), both used
under the Apache License 2.0. Cryptography comes from the JDK: AES-GCM, ChaCha20-Poly1305, HMAC for
HKDF, X25519 and P-256, ECDSA, RSA-PSS and Ed25519.

The module is in progress; this README grows with it.

## Packets and protection

The packet layer is sans-I/O: it encodes and decodes bytes in caller-owned `ByteBuffer`s and
removes or applies protection in place, so payloads are never copied. It is ported from
quinn-proto (`varint.rs`, `coding.rs`, `packet.rs`, `frame.rs`, `transport_parameters.rs`,
`shared.rs`, `token.rs`, `crypto/rustls.rs`) and the QUIC key schedule of rustls (`quic.rs`);
each ported file names its source in its header comment.

```java
// Client: build a padded Initial with the ClientHello in a CRYPTO frame.
Keys initial = Keys.initial(QuicVersion.V1, dcid, false);
PacketBuilder builder = new PacketBuilder(ByteBuffer.allocate(1500), 1500);
ByteBuffer frames = builder.begin(new PacketHeader.Initial(QuicVersion.V1, dcid, scid, new byte[0], 0, 1), initial.local());
Frame.Crypto.encode(frames, 0, clientHello, frames.remaining());   // as much as fits
builder.finish(PacketBuilder.MIN_INITIAL_DATAGRAM);                // PADDING to 1200 bytes, then protect
send(builder.datagram());

// Server: split the datagram, pick keys from the unprotected header, then unprotect in place.
for (ProtectedPacket p : ProtectedPacket.splitDatagram(datagram, localIdLength, false)) {
    Keys keys = Keys.initial(p.version(), p.destinationId(), true);   // or the level's keys
    Packet packet = p.unprotect(keys.remote(), largestReceived);      // null: drop it
    for (Frame f : FrameDecoder.decodeAll(packet.payload(), p.type())) { ... }
}
```

### API

| Package | Types |
| --- | --- |
| `io.github.mahmoudimus.quic` | `VarInt` (RFC 9000 section 16), `ConnectionId` (0 to 20 bytes, value semantics), `QuicVersion` (`V1`, `V2`: salts, labels, Retry keys), `StatelessResetToken` (constant-time comparison, datagram check, HMAC derivation) |
| `...quic.packet` | `PacketHeader` (sealed: `Initial`, `ZeroRtt`, `Handshake`, `Short`, `Retry`, `VersionNegotiation`), `PacketType`, `PacketNumber` (RFC 9000 appendix A.2 and A.3), `ProtectedPacket` (partial decode, sample offset, coalesced datagrams, header and payload unprotection, Retry verification), `PacketProtection`, `PacketBuilder`, `Packet`, `PacketDecodeException`, `UnsupportedVersionException` (with the Version Negotiation reply) |
| `...quic.frame` | `Frame` (sealed records for every RFC 9000 frame, DATAGRAM, ACK_FREQUENCY and IMMEDIATE_ACK), `FrameType` (codes and the RFC 9000 Table 3 packet rules), `FrameDecoder`, `FrameException` |
| `...quic.params` | `TransportParameters` (with a builder), `PreferredAddress`, `VersionInformation` (RFC 9368), `UnknownParameter` (preserved and GREASE parameters) |
| `...quic.crypto` | `Keys` (from TLS `Secrets`, Initial keys from a connection ID, key updates), `DirectionalKeys`, `PacketKey` (AEAD seal and open in place, AEAD limits), `HeaderKey` (AES-ECB or ChaCha20 masks), `RetryIntegrity` |

Errors follow RFC 9000: a malformed frame is a `FrameException` (a `QuicException`) with
`FRAME_ENCODING_ERROR` and the frame type; a frame in a packet type that may not carry it, an
empty payload, a frame type in a longer encoding than needed, and reserved header bits set after
decryption are `PROTOCOL_VIOLATION`; bad transport parameters are `TRANSPORT_PARAMETER_ERROR`. A
header that cannot be parsed is a `PacketDecodeException`, since such packets are dropped rather
than closing the connection, and a packet that fails authentication decrypts to `null`. The
decoders throw nothing else for any input; a seeded fuzz test checks this.

### Versions

QUIC version 1 (`0x00000001`) and version 2 (`0x6b3343cf`, RFC 9369), which differ in the long
header type bits, the Initial salt, the HKDF labels (`quic ` and `quicv2 `) and the Retry integrity
key. Long headers of any other version raise `UnsupportedVersionException`, whose connection IDs
may be up to 255 bytes (RFC 8999) so that a server can answer with Version Negotiation.

### Limits and choices

- The tests reproduce RFC 9001 appendix A (keys, client and server Initial, Retry, ChaCha20-Poly1305
  short header) and RFC 9369 appendix A byte for byte, along with the RFC 9000 appendix A varint
  and packet number examples and the rustls key update vector.
- Long headers are written with a two-byte Length field, as quinn does, so a long header packet
  carries at most 16383 bytes after its header; `PacketBuilder` enforces this.
- Packets must leave room for the 16-byte header protection sample; `PacketBuilder` pads with
  PADDING frames, and `PacketProtection.protect` rejects a payload that is too short.
- AEAD limits (RFC 9001 section 6.6) are constants on `PacketKey`: AES-GCM may seal 2^23 packets
  and fail 2^52 openings per key; ChaCha20-Poly1305 has no practical sealing limit and 2^36
  failed openings. Counting packets is up to the connection.
- Key objects keep one JDK `Cipher` each and are confined to one thread at a time; nothing locks.
  The JDK refuses to seal twice in a row under one key with the same packet number, which QUIC
  never does.
- Decoded frames hold views of the decrypted payload, so copy CRYPTO, STREAM and DATAGRAM data that
  must outlive the datagram buffer.
- Coalesced packets after the first are ignored from the first that fails to parse or carries a
  different Destination Connection ID (RFC 9000 section 12.2).
- Transport parameters: unknown and GREASE parameters are kept, not dropped; integer values need
  not be minimally encoded. `authenticateConnectionIds` checks the handshake connection IDs of
  RFC 9000 section 7.3 once the connection layer knows them.
- ACK_FREQUENCY and IMMEDIATE_ACK follow quinn's implementation of the ACK frequency draft, and
  `min_ack_delay` uses its draft code point `0xff04de1b`.

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
