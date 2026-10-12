# quic

A dependency-free QUIC transport for JDK 21 and newer: RFC 9000 (transport), RFC 9001 (TLS for QUIC)
and RFC 9002 (loss detection and congestion control), with its own TLS 1.3 handshake, since the JDK's
`SSLEngine` cannot carry TLS in QUIC CRYPTO frames or hand out the traffic secrets QUIC needs.

The design follows [quinn](https://github.com/quinn-rs/quinn)'s `quinn-proto` (a sans-I/O state
machine) and the TLS 1.3 client and server of [rustls](https://github.com/rustls/rustls), both used
under the Apache License 2.0. Cryptography comes from the JDK: AES-GCM, ChaCha20-Poly1305, HMAC for
HKDF, X25519 and P-256, ECDSA, RSA-PSS and Ed25519.

The stack runs end to end: a blocking API for virtual threads over the sans-I/O connection and
endpoint, tested against itself on loopback and against aioquic as client and server. Not yet:
0-RTT and resumption, connection migration, BBR (see [Connections and
endpoints](#connections-and-endpoints)).

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

## Connection internals

The building blocks a connection is assembled from, ported from quinn-proto's `connection` module,
`congestion.rs`, `range_set`, `cid_generator.rs`, `cid_queue.rs`, `token.rs` and
`bloom_token_log.rs`. Like the rest of the module they are sans-I/O: they take frames and times in
and hand frames, packet numbers and deadlines out. [Connections and
endpoints](#connections-and-endpoints) drive them.

```java
TimerTable timers = new TimerTable();
NanoClock clock = NanoClock.system();                 // a fake clock in tests
Recovery recovery = new Recovery(Side.CLIENT, RecoveryConfig.DEFAULT, timers, new SecureRandom(), clock.nanoTime());
StreamsState streams = new StreamsState(Side.CLIENT, 100, 100, 8 << 20, 1 << 30, 1_250_000);
streams.setParams(peerTransportParameters);
Recovery.Listener listener = Recovery.Listener.forStreams(streams);
Retransmits pending = recovery.space(SpaceId.DATA).pending();

StreamId id = streams.open(Dir.BI);
int taken = streams.write(id, data, pending);         // StreamException BLOCKED: wait for Writable

// Building a packet: control frames, then STREAM frames, then remember what it carried
long pn = recovery.nextPacketNumber(SpaceId.DATA);
Retransmits sent = new Retransmits();
streams.writeControlFrames(payload, pending, sent, limit);
List<StreamMeta> frames = streams.writeStreamFrames(payload, limit, true);
recovery.onPacketSent(now, SpaceId.DATA, pn, new SentPacket(now, size, true, -1, sent, frames));

// Receiving
recovery.onAckReceived(now, SpaceId.DATA, ackFrame, listener);
streams.received(streamFrame, payloadLength);         // QuicException: close with its code
try (Chunks chunks = streams.read(id, true, pending)) { ... chunks.next(max) ... }

// Timers: sleep until timers.nextTimeout(), then
for (Timer t; (t = timers.pollExpired(clock.nanoTime())) != null; ) { ... }
```

| Area | Classes | Notes |
| --- | --- | --- |
| Ranges and reassembly | `RangeSet`, `Assembler`, `Chunk`, `SendBuffer` | Ordered or unordered reads; duplicate and overlap removal; compaction when small frames pin large buffers, and a hard bound of 1024 pieces per stream |
| Streams (RFC 9000 sections 2 to 4) | `StreamsState`, `StreamId`, `Side`, `Dir`, `SendState`, `RecvState`, `StreamEvent`, `StreamException`, `Chunks`, `StreamMeta` | Send states Ready, Send, DataSent, ResetSent, DataRecvd, ResetRecvd and the six receive states; MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS credit moved by an eighth of the window, as quinn does; DATA_BLOCKED, STREAM_DATA_BLOCKED and STREAMS_BLOCKED once per limit; priorities with fair round-robin; events Opened, Readable, Writable, Finished, Stopped, Available |
| Packet number spaces | `PacketSpace`, `SpaceId`, `SentPacket`, `SentPackets`, `Retransmits`, `PendingAcks`, `Dedup`, `PacketNumberFilter` | Duplicate detection; ACK frames with at most 64 ranges, the ACK delay and ECN counts; an immediate ACK every second ack-eliciting packet or on reordering, else after `max_ack_delay`; skipped packet numbers against optimistic ACKs |
| Loss detection (RFC 9002) | `Recovery`, `RecoveryConfig`, `RttEstimator` | Packet and time thresholds, PTO with exponential backoff (capped at 2^16) and probes, the client's anti-deadlock probe, discarding Initial and Handshake spaces, persistent congestion, spurious loss detection, ECN validation, the anti-amplification limit |
| Congestion control | `Controller`, `ControllerFactory`, `NewReno`, `Cubic` (default), `Pacer` | RFC 9002 NewReno and RFC 9438 CUBIC with fast convergence and spurious-loss undo; a token-bucket pacer |
| MTU discovery | `MtuDiscovery`, `MtuDiscoveryConfig` | DPLPMTUD (RFC 8899) by binary search up to 1452 bytes by default, three retransmissions per probe size, black hole detection |
| Connection IDs | `ConnectionIdGenerator`, `RandomConnectionIdGenerator`, `LocalCidState`, `RemoteCidQueue`, `IssuedCid` | Sequence numbers, HMAC-derived stateless reset tokens, at most `min(active_connection_id_limit, 8)` issued, rotation through Retire Prior To when IDs have a lifetime, the peer's IDs bounded by our `active_connection_id_limit` |
| ACK frequency | `AckFrequencyState` | The `max_ack_delay` each side uses, and ACK_FREQUENCY thresholds |
| Timers | `Timer`, `TimerTable`, `NanoClock` | Loss detection and PTO, idle, close and drain, key discard, path validation, keep-alive, pacing, CID rotation, ACK delay |
| Address validation (`...quic.token`) | `TokenKey`, `Token`, `TokenPayload`, `TokenValidator`, `IncomingToken`, `TokenLog`, `BloomTokenLog` | Retry tokens bound to the client's address and port (15 s) and NEW_TOKEN tokens bound to its IP (two weeks), sealed with a one-time AES-256-GCM key derived by HKDF from the server's key; expiry from an injectable `InstantSource`; a bounded replay log |

- **Time.** Every method that depends on time takes `now` in nanoseconds from one monotonic clock;
  nothing reads a clock itself. `NanoClock.NONE` (`Long.MIN_VALUE`) marks an unset time. Tests use
  a fake clock and never sleep.
- **Threads.** None of these classes is thread-safe and none takes a lock: each belongs to one
  connection, which serializes access (the blocking stream layer included). `BloomTokenLog` is
  shared by an endpoint, which must serialize calls to it. Configurations are immutable.
- **Errors.** Peer misbehaviour is a `QuicException` with the RFC 9000 code: `FLOW_CONTROL_ERROR`,
  `FINAL_SIZE_ERROR`, `STREAM_STATE_ERROR`, `STREAM_LIMIT_ERROR`, `CONNECTION_ID_LIMIT_ERROR`,
  `PROTOCOL_VIOLATION` (an ACK of an unsent or skipped packet number, a bad RETIRE_CONNECTION_ID),
  `INVALID_TOKEN` (an authentic Retry token from another address, or expired). Application-level
  conditions are a `StreamException` (`BLOCKED`, `STOPPED`, `RESET`, `CLOSED_STREAM`,
  `ILLEGAL_ORDERED_READ`), which leaves the connection open.
- **Data ownership.** The assembler and send buffer keep views, not copies: copy STREAM and CRYPTO
  data out of reusable packet buffers before handing it over, and do not change written buffers.
  `StreamsState.write` copies; `writeChunks` does not.

Ported faithfully, with quinn's unit tests: the assembler, send buffer, range set, streams,
packet spaces and sent-packet tracking, pacing, MTU discovery (full DPLPMTUD with black hole
detection), CUBIC, connection ID queue, ACK frequency state and tokens with the bloom log (a small
bloom filter replaces the `fastbloom` crate). Differences, mostly where RFC 9000 and 9002 are
stricter than quinn:

- Single path: no path generations, migration or path validation logic (only its timer), so the
  in-flight counts are per connection.
- The explicit RFC state names (Ready versus Send, DataRecvd, ResetRecvd; SizeKnown, DataRecvd,
  DataRead, ResetRead) are tracked for inspection; quinn folds them into three and two states.
- A FIN below data already received is a `FINAL_SIZE_ERROR`; STOP_SENDING beyond the stream limit
  is a `STREAM_LIMIT_ERROR`; RETIRE_CONNECTION_ID for a sequence number not yet issued or for the
  packet's own Destination Connection ID, and NEW_CONNECTION_ID reusing a sequence number for
  another ID, are `PROTOCOL_VIOLATION`s.
- Discarding Initial or Handshake keys resets the PTO backoff (RFC 9002 appendix A.11), and the
  client's anti-deadlock probe goes in the Handshake space once it has Handshake keys.
- MTU probes and black hole detection only count application data packets.
- No flow-control window auto-tuning (quinn has none); windows can be changed at run time.
- Not ported: BBR, the hashed connection ID generator, quinn's qlog module (the connection layer
  has a smaller qlog-style sink instead), and connection statistics beyond the loss counters on
  `Recovery`. DATAGRAM buffering lives in the connection layer.
- ECN: counts on received packets, ACK frames with ECN counts and validation of the peer's
  counts are here; marking outgoing packets is the socket layer's job.

## Connections and endpoints

The protocol layer is sans-I/O, ported from quinn-proto (`connection/mod.rs`,
`connection/packet_builder.rs`, `connection/packet_crypto.rs`, `connection/datagrams.rs`,
`endpoint.rs`, `config/`): a `Connection` takes datagrams, timeouts and application calls, and hands
out datagrams, deadlines and events; an `Endpoint` routes datagrams to connections. On top, a small
I/O runtime gives each endpoint one `DatagramChannel` and each connection one virtual thread, behind
a blocking API.

```java
// Server: per-SNI certificates, an ALPN, Retry-based address validation
ServerConfig serverConfig = ServerConfig.builder(TlsConfig.builder()
                .certificateSelector(hello -> certificateFor(hello.serverName()))
                .alpnProtocols("echo")
                .build())
        .transport(TransportConfig.builder()
                .maxIdleTimeout(Duration.ofSeconds(30))
                .maxConcurrentBidiStreams(100)
                .congestionControl(TransportConfig.CongestionControl.CUBIC)
                .mtuDiscovery(true)
                .build())
        .retry(true)
        .build();
try (QuicServer server = QuicServer.bind(new InetSocketAddress(4433), serverConfig)) {
    while (true) {
        QuicConnection connection = server.accept();          // handshake done
        Thread.ofVirtual().start(() -> {
            try {
                while (true) {
                    QuicStream stream = connection.acceptStream();
                    Thread.ofVirtual().start(() -> {
                        try (InputStream in = stream.getInputStream(); OutputStream out = stream.getOutputStream()) {
                            in.transferTo(out);                    // echo; closing the output sends the FIN
                        } catch (IOException e) { /* reset by the peer, or the connection ended */ }
                    });
                }
            } catch (IOException e) { /* QuicConnectionException: the connection ended */ }
        });
    }
}

// Client: trust and the server name to check
ClientConfig clientConfig = ClientConfig.builder(TlsConfig.builder()
        .serverName("example.com")
        .alpnProtocols("echo")
        .build()).build();
try (QuicClient client = QuicClient.create(clientConfig);
        QuicConnection connection = client.connect(new InetSocketAddress("example.com", 4433))) {
    QuicStream stream = connection.openBidirectionalStream();
    try (OutputStream out = stream.getOutputStream()) {
        out.write("hello".getBytes(StandardCharsets.UTF_8));
    }
    byte[] echo = stream.getInputStream().readAllBytes();   // read() returns -1 at the FIN
    connection.sendDatagram(new byte[] {1, 2, 3});           // RFC 9221, unreliable
    connection.close(0, "done");                             // CONNECTION_CLOSE with an application code
}
```

### API

| Type | Role |
| --- | --- |
| `QuicServer` | `bind(address, ServerConfig[, EndpointConfig])`, `accept()` (blocks until a handshake completes), `localAddress()`, `close()` |
| `QuicClient` | `create(ClientConfig[, bindAddress, EndpointConfig])`, `connect(remote[, serverName, timeout])`, `close()` |
| `QuicConnection` | `openBidirectionalStream()`, `openUnidirectionalStream()` (block while the peer's stream limit is reached), `acceptStream()`, `sendDatagram`, `receiveDatagram([timeout])`, `maxDatagramSize()`, `updateKeys()`, `close(code, reason)`, `awaitClosed(timeout)`, `closeReason()`, `alpn()`, `serverName()`, `peerCertificates()`, `cipherSuite()`, `keyExchangeGroup()`, `version()`, `remoteAddress()`, `localAddress()`, `stats()` |
| `QuicStream` | `getInputStream()` (blocks for data, -1 at the FIN), `getOutputStream()` (blocks on flow control and the send window; `close()` is the FIN), `reset(code)`, `stopSending(code)`, `close()` (FIN, and STOP_SENDING if unread) |
| `QuicConnectionException`, `QuicStreamException` | `IOException`s: the connection ended (with its `ConnectionError`), or the peer reset or stopped the stream (with its code) |
| `...connection.Connection` | sans-I/O: `handleDatagram(now, remote, ecn, bytes)`, `pollTransmit(now, maxDatagrams)`, `handleTimeout(now)`, `pollTimeout()`, `pollEvent()`, `pollEndpointEvent()`; stream, datagram and close calls |
| `...connection.Endpoint` | sans-I/O: `handle(now, remote, ecn, bytes)` returns `Deliver`, `NewConnection` or `Response`; `connect(...)`; `handleEvent(connection, event)` |
| `...connection.ConnectionEvent` | `HandshakeDataReady` (ALPN and SNI known), `Connected`, `HandshakeConfirmed`, `Stream(StreamEvent)`, `DatagramReceived`, `ConnectionLost(ConnectionError)` |
| `...connection.TransportConfig`, `ServerConfig`, `ClientConfig`, `EndpointConfig` | Immutable builders: idle timeout, windows, stream limits, congestion controller, MTU discovery, DATAGRAM buffers, keep-alive, key log, qlog; certificates (per SNI), ALPN, Retry, connection cap; trust, server name, version; CID length and lifetime, reset key, versions |

### What a connection does

- **Handshake.** CRYPTO frames per encryption level feed `TlsSession`; keys are installed as
  `Secrets` arrive, with the next 1-RTT generation derived in advance. A client discards Initial keys
  when it sends its first Handshake packet, a server when it receives one (RFC 9001 section 4.9.1);
  the server confirms the handshake with HANDSHAKE_DONE and drops Handshake keys. A server buffers up
  to 100 1-RTT packets that overtake the client's Finished. Client Initials, and server datagrams
  with ack-eliciting Initials, are padded to 1200 bytes.
- **Transport parameters** are built from `TransportConfig`, exchanged through TLS and authenticated
  (`original_destination_connection_id`, `initial_source_connection_id`,
  `retry_source_connection_id`). The idle timeout is the smaller of both sides' non-zero values.
- **Address validation.** Until the client's address is validated (a Handshake packet, or a Retry
  token) a server sends at most three times what it received. With `retry(true)` the endpoint
  answers token-less Initials with Retry and a sealed token from `...quic.token`, and checks it on
  the client's second Initial; an invalid or expired token gets CONNECTION_CLOSE `INVALID_TOKEN`.
- **Packets.** Coalesced packets are split, protection removed, packet numbers decoded against the
  largest received, duplicates dropped, frames checked against the packet type (RFC 9000 Table 3).
  ACKs go into `Recovery` (RTT, loss detection, congestion, MTU probes); lost STREAM, CRYPTO and
  control frames are queued again. ACKs are sent at once in Initial and Handshake, by `PendingAcks`
  rules in 1-RTT, and bundled with other frames once per RTT.
- **Sending** builds one datagram at a time, Initial then Handshake then 1-RTT, within the congestion
  window, the pacer and the anti-amplification budget; probes and CONNECTION_CLOSE bypass the window.
  Pacing starts with the first RTT sample, so the 333 ms initial RTT guess does not spread the
  handshake flight out. Path MTU probes follow when there is nothing else to send.
- **Key update.** Routine updates when a key's packet budget runs out (the first one after 10 to 1000
  packets, as quinn does, so peers that mishandle updates fail early), `updateKeys()` on demand, and
  updates started by the peer. The previous keys stay for three PTOs to decrypt reordered packets;
  a second update before the first is acknowledged is `KEY_UPDATE_ERROR`.
- **Connection IDs.** After the handshake each side issues `min(active_connection_id_limit, 8)` IDs;
  RETIRE_CONNECTION_ID gets a replacement; IDs with a lifetime (`RandomConnectionIdGenerator`) are
  rotated through Retire Prior To. Every change reaches the endpoint's routes. Zero-length IDs are
  routed by the peer's address.
- **Closing** (RFC 9000 section 10). `close(code, reason)` sends CONNECTION_CLOSE in every space
  with keys (an application close becomes `APPLICATION_ERROR` without a reason in Initial and
  Handshake packets), repeats it in answer to packets while closing, and drains for three PTOs; a
  peer's close starts draining. The idle timeout and a stateless reset (the peer's token at the end
  of a datagram) end the connection at once. Version Negotiation without our version ends a client
  connection.
- **Datagrams** (RFC 9221) are bounded in both directions; the oldest are dropped first.
- **Errors** from the peer become CONNECTION_CLOSE with the RFC 9000 code and the frame type;
  `ConnectionError` says why a connection ended (`TRANSPORT_ERROR`, `CONNECTION_CLOSED`,
  `APPLICATION_CLOSED`, `LOCALLY_CLOSED`, `TIMED_OUT`, `RESET`, `VERSION_MISMATCH`).

The endpoint sends Version Negotiation (with a GREASE version) for unknown versions in datagrams of
at least 1200 bytes, drops shorter Initials, rejects Initials whose Destination Connection ID is
shorter than 8 bytes, authenticates the first Initial before creating any state, refuses connections
beyond `maxConnections` with `CONNECTION_REFUSED`, and answers packets for unknown connection IDs
with a stateless reset, at most one per 20 ms and always smaller than the packet that caused it.

### Threads and limits

- One virtual thread per endpoint receives datagrams, copies each into a buffer of its own (the
  connection keeps views of stream data), routes it under the endpoint's lock and queues it for the
  connection. One virtual thread per connection owns it under a `ReentrantLock` (no `synchronized`
  anywhere), and wakes on datagrams, on `pollTimeout()` and on application calls. Each wake-up
  handles at most 64 datagrams in and 64 out, then releases the lock and yields, so streams and other
  connections get their turn. Application threads block on a `Condition` of the connection's lock.
- Memory a peer can drive is bounded: 1024 queued datagrams per connection (more are dropped, like
  a full socket buffer), the stream and connection receive windows, the CRYPTO buffer (16 KiB of
  out-of-order data per level), 100 early 1-RTT packets, the DATAGRAM receive buffer, 1024 pieces
  per reassembled stream, the connection ID limits, and `maxConnections` per server.
- Closing a `QuicServer` or `QuicClient` closes its connections with code 0, waits briefly for the
  CONNECTION_CLOSE packets to go out, stops the threads and closes the socket.
- The socket asks for 4 MiB buffers and sets `IP_DONTFRAGMENT`; where that is unsupported, MTU
  discovery stays off.

### Debugging

`TransportConfig.Builder.keyLog(KeyLog.file(path))` (or `KeyLog.fromEnvironment()` for
`SSLKEYLOGFILE`) writes the TLS secrets in the NSS key log format, so Wireshark can decrypt a
capture. `qlog(QlogSink.logger(System.getLogger("quic")))` reports qlog-style events (packets sent,
received and lost, key updates, state changes) as JSON lines. Both are off by default.

### Tests

- `ConnectionTest` ports quinn-proto's connection tests to an in-memory pair (`Pair`): two endpoints
  on a fake clock, with an MTU, latency, random loss and reordering from a fixed seed, and hooks to
  drop or hold back datagrams. Handshakes over every cipher suite and both versions, stream
  transfer, flow-control blocking, stream limits, loss recovery and tail loss, key updates (simple,
  reordered, routine), idle timeout and keep-alive, closes in every state, stateless resets (and
  their rate limit), Version Negotiation, Retry (and expired tokens), CID rotation and retirement,
  zero-length CIDs, datagrams, MTU discovery, anti-amplification, the connection cap.
- `LoopbackTest` runs the blocking API over real UDP on loopback: 32 concurrent streams echoing 1 MB
  each with SHA-256 checks, a 24 MB upload, parallel connections, datagrams, closes, resets, key
  updates during a transfer. On a 4-core container, with an 8 KB MTU, the 32-stream echo moves
  100 to 125 MB/s (both directions together) and a single upload 160 to 225 MB/s; with the default 1452-byte
  MTU a warmed-up single stream uploads 150 to 185 MB/s.
- `ConnectionFuzzTest` feeds a connection random and mutated datagrams (nothing may throw or close
  it) and authenticated 1-RTT packets of random frames (they may close it with a protocol error,
  never `INTERNAL_ERROR`).
- `AioquicInteropTest` runs against aioquic 1.4.0 as an external peer, with the echo client and
  server in `src/test/resources/interop/` (raw streams, ALPN `microproxy-test`). It covers a Java
  server with an aioquic client and an aioquic server with a Java client: all three cipher suites
  with X25519, P-256 and P-384 (the server choosing), many streams and multi-megabyte transfers,
  unidirectional streams, datagrams, key updates started by either side, Retry, QUIC version 2, and
  closes from either side with their codes and reasons. An HTTP/3 client on aioquic's
  `H3Connection` also runs GET and POST requests (2 MB down, 1 MB echoed, concurrent and
  sequential) against a small HTTP/3 server built on the blocking API and `http3-codec` (a
  test-scoped dependency; static QPACK only).

The interop tests are skipped unless Python 3 with aioquic is available. To run them, keep the
virtual environment out of the sources, under `target/` or elsewhere:

```sh
python3 -m venv quic/target/aioquic
quic/target/aioquic/bin/pip install aioquic==1.4.0
mvn -pl quic -am test -Dtest=AioquicInteropTest -Dsurefire.failIfNoSpecifiedTests=false \
    -Dquic.interop.python=$PWD/quic/target/aioquic/bin/python
```

`QUIC_INTEROP_PYTHON` works as well as `-Dquic.interop.python`; `-Dquic.interop.required=true`
turns a missing aioquic into a failure, as the `quic-interop` CI job does.

### Not yet

0-RTT and session resumption (and so NEW_TOKEN, which is ignored), connection migration and path
validation (datagrams from another address are dropped; PATH_CHALLENGE is answered on the current
path), the preferred address, BBR, sending ACK_FREQUENCY, ECN marking (the JDK cannot set or read
ECN bits), GSO, and an HTTP/3 layer in the main sources (the interop test's HTTP/3 server is test
code).
