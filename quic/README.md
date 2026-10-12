# quic

A dependency-free QUIC transport for JDK 21 and newer: RFC 9000 (transport), RFC 9001 (TLS for QUIC)
and RFC 9002 (loss detection and congestion control), with its own TLS 1.3 handshake, since the JDK's
`SSLEngine` cannot carry TLS in QUIC CRYPTO frames or hand out the traffic secrets QUIC needs.

The design follows [quinn](https://github.com/quinn-rs/quinn)'s `quinn-proto` (a sans-I/O state
machine) and the TLS 1.3 client and server of [rustls](https://github.com/rustls/rustls), both used
under the Apache License 2.0. Cryptography comes from the JDK: AES-GCM, ChaCha20-Poly1305, HMAC for
HKDF, X25519 and P-256, ECDSA, RSA-PSS and Ed25519.

The stack runs end to end: a blocking API for virtual threads over the sans-I/O connection and
endpoint, with session resumption, 0-RTT, NEW_TOKEN and a choice of CUBIC, NewReno or BBR
congestion control, tested against itself on loopback and against aioquic as client and
server. Not yet: connection migration (see [Connections and
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
| Extensions | `server_name`, `supported_groups`, `signature_algorithms` (`_cert` parsed), ALPN, `supported_versions`, `key_share`, `cookie`, `quic_transport_parameters` (0x39), `psk_key_exchange_modes` (`psk_dhe_ke` only), `pre_shared_key`, `early_data` |
| Resumption | NewSessionTicket from a server with a `Ticketer` (stateless, AES-256-GCM, rotating keys); PSK resumption with `psk_dhe_ke` (always a fresh key exchange); 0-RTT with an anti-replay `EarlyDataPolicy` |
| Certificates | client: an `X509TrustManager` (the JDK default by default) plus host name verification as HTTPS does it, or `trustAllCertificates(true)` for tests; server: one `CertifiedKey` or a per-ClientHello selector (`ClientHelloInfo`: SNI, ALPN, signature schemes, suites, groups) |
| Client authentication | `clientAuth(REQUEST or REQUIRE)` with a `clientTrustManager`; the client presents `clientCertificate(...)` |

Validation follows rustls: message order, TLS 1.3 only, the null compression method, an empty
`legacy_session_id` echo, repeated extensions, extensions not offered or not allowed in a message,
key shares in `supported_groups`, the cipher suite and group kept across a retry, no renegotiation and
no KeyUpdate message (QUIC has its own key update). No middlebox compatibility mode and no
EndOfEarlyData, as RFC 9001 requires.

### Resumption and 0-RTT

Session tickets, PSK resumption and early data follow rustls (`client/hs.rs`, `client/tls13.rs`,
`server/tls13.rs`, `ticketer.rs` and the ring ticketer, `client/handy.rs`, `msgs/persist.rs`,
`quic.rs`), with the QUIC rules of RFC 9001 section 4.6.

```java
Ticketer ticketer = Ticketer.create();                // AES-256-GCM, a new key every 6 hours
TlsConfig server = TlsConfig.builder()
        .certificate(chain, key).alpnProtocols("h3")
        .sessionTickets(ticketer)                     // NewSessionTicket and PSK resumption
        .earlyData(true)                              // tickets allow 0-RTT, and it is accepted
        .earlyDataPolicy(EarlyDataPolicy.antiReplay().and(attempt -> !"admin".equals(attempt.serverName())))
        .build();
TlsConfig client = TlsConfig.builder().serverName("example.com").alpnProtocols("h3")
        .earlyData(true)                              // offer 0-RTT when the ticket allows it
        .build();
TlsSession session = TlsSession.client(client, "example.com", params, cache.take("example.com"));
for (SessionTicket t; (t = session.pollNewTicket()) != null; ) cache.put("example.com", t);
```

- **Tickets.** A server with a `Ticketer` sends `ticketsPerConnection` NewSessionTickets (2 by
  default) at `ONE_RTT` once the client's Finished checks out, to clients that offered
  `psk_dhe_ke`; none when it asks for client certificates. Each ticket seals, with AES-256-GCM
  under the ticketer's current key (its 16-byte name as additional data, a random 12-byte nonce),
  the resumption PSK, suite, `ticket_age_add`, issue time, lifetime, `max_early_data_size`, server
  name, ALPN protocol, the server's encoded transport parameters and a random ticket id. The key
  rotates every lifetime (6 hours by default, announced as the ticket lifetime); the previous key
  still opens tickets for one more lifetime, as rustls' `TicketRotator` does. Servers that share a
  `Ticketer` resume each other's sessions.
- **Client.** A client always offers `psk_dhe_ke` and keeps the tickets it receives
  (`pollNewTicket()`) as `SessionTicket`s, with the server's certificates and transport
  parameters; a `ClientSessionStore` (`ClientSessionMemoryCache`: up to 256 servers, 8 tickets
  each, oldest dropped) hands each out once. A ticket is offered only unexpired, for the same
  server name and with a suite the client offers, in `pre_shared_key`, the last extension, with
  its obfuscated age and a binder over the ClientHello up to the binders. After a
  HelloRetryRequest to a suite of another hash the ticket is dropped.
- **Server.** The first identity that opens, has not expired, and has the server name and a suite
  of the selected hash is taken; its binder must be right (`decrypt_error` otherwise). Others, and
  `psk_ke` alone, mean a full handshake. A resumed handshake has no Certificate or
  CertificateVerify, but always a fresh (EC)DHE exchange.
- **0-RTT.** With `earlyData(true)` a client offers early data when its ticket allows it (QUIC
  tickets carry `max_early_data_size` 0xffffffff; any other value is `PROTOCOL_VIOLATION`) and the
  ticket's ALPN is offered; its `ZERO_RTT` secrets (the client early traffic secret) come first,
  at once. A server accepts only with the first PSK identity, the ticket's suite, ALPN protocol
  and server name, no HelloRetryRequest, transport parameters the connection layer accepts
  (`TlsSession.server(config, params, check)`), and its `EarlyDataPolicy`; it says so with
  `early_data` in EncryptedExtensions, and hands out the same secrets before the Handshake ones.
  `isEarlyDataAccepted()` tells either side; `isResumed()` whether a PSK was used.
- **Replay.** 0-RTT data can be replayed by anyone who captured it (RFC 8446 section 8). The
  default policy, `EarlyDataPolicy.antiReplay()`, accepts a ticket's early data only while the
  client's ticket age (de-obfuscated) and the server's agree within 10 seconds, and only once: a
  record of ticket ids, kept for twice the window and bounded (100,000 by default; when full it
  refuses rather than forgets). A capture replayed later fails the age check, one replayed sooner
  hits the record. The record is per process: servers sharing a ticketer but not the record can
  each accept a replay once. Applications must still send only replay-safe data early, and may
  veto with `policy.and(veto)` (the veto runs first, so vetoed tickets are not recorded). A
  rejection costs the client only the data's retransmission after the handshake.

Tests check the key schedule, Finished values and transcript (including the HelloRetryRequest
`message_hash`) against RFC 8448 sections 3 and 5, and the resumed 0-RTT handshake of section 4
byte for byte (the PSK from section 3's ticket, the early secret, the PSK binder, the client early
traffic secret, the resumed handshake, application and resumption secrets); run in-memory
handshakes for every suite, group and signature scheme with randomly fragmented CRYPTO data, and
resumptions with early data accepted, rejected (the server's setting, a replay, a stale ticket
age, an ALPN or suite change, the transport parameter check, a veto, a HelloRetryRequest), expired
and foreign tickets and bad binders; and fuzz the decoders from a fixed seed.

Out of scope for now, as follow-ups: external PSKs, `psk_ke`, `rsa_pss_pss` schemes, secp521r1 and
ML-KEM hybrids, certificate compression, OCSP stapling and raw public keys.

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
| Congestion control | `Controller`, `ControllerFactory`, `NewReno`, `Cubic` (default), `Bbr`, `Pacer` | RFC 9002 NewReno and RFC 9438 CUBIC with fast convergence and spurious-loss undo; quinn's experimental BBR (see [BBR](#bbr)); a token-bucket pacer, under the controller's pacing rate when it sets one |
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
- A poll that builds datagrams until it runs out of data leaves the connection application
  limited, as quinn's last `poll_transmit` call, which builds nothing, does.
- BBR samples the delivery rate as draft-cheng-iccrg-delivery-rate-estimation does and follows
  the BBRv1 draft where quinn's port does not (see [BBR](#bbr)).
- Not ported: the hashed connection ID generator, quinn's qlog module (the connection layer
  has a smaller qlog-style sink instead), and connection statistics beyond the loss counters on
  `Recovery`. DATAGRAM buffering lives in the connection layer.
- ECN: counts on received packets, ACK frames with ECN counts and validation of the peer's
  counts are here; marking outgoing packets is the socket layer's job.

### BBR

`Bbr` (`TransportConfig.CongestionControl.BBR`, or `BbrConfig` as the controller factory) is
ported from quinn's `congestion/bbr` (`mod.rs`, `bw_estimation.rs`, `min_max.rs`), itself based on
a BBRv1 sender (`bbr_sender.cc`); quinn calls it experimental. Where quinn's port departs from
BBRv1 (draft-cardwell-iccrg-bbr-congestion-control), this one follows the draft instead.

It models the path instead of reacting to loss: the bottleneck bandwidth (`BtlBw`, the windowed
maximum of the delivery rate samples over ten round trips, `BandwidthEstimation` and `MinMax`) and
the minimum RTT (`RTprop`). From them it sets the window (a gain times the bandwidth-delay
product, plus the ack aggregation seen) and a pacing rate, in four modes: STARTUP (gain 2.885,
until the estimate grows less than 25% in three rounds, or a loss in that round), DRAIN (gain
1/2.885, until the bytes in flight are down to one BDP), PROBE_BW (pacing gains 1.25, 0.75 and six
rounds of 1.0, from a random point of the cycle; window gain 2) and PROBE_RTT (window 0.75 BDP for
at least 200 ms and a round) when the minimum RTT is ten seconds old. Losses cap the window in
conservation, then growth, until a round passes without one. The default initial window is
quinn's 240000 bytes.

**Delivery rate.** `DeliveryRate` in the connection layer is the sampler of
draft-cheng-iccrg-delivery-rate-estimation: each packet sent in flight is stamped (`SentPacket`)
with the connection's delivered bytes, their time, the send time of the first packet of its flight
and whether sending was application limited (the connection marks the bytes then in flight as an
application-limited bubble when a poll runs out of data); each ACK yields one `RateSample` from
the newest packet it acknowledges, over the longer of its send and ACK intervals, with no rate
when that is shorter than the minimum RTT. `Controller.onRateSample` hands it to the controller
before `onEndAcks`. An application-limited sample counts only if it beats the estimate.

What the port adds to the controller interface, and where it departs from quinn:

- `Controller.onRateSample` and `RateSample`, with `DeliveryRate` and the delivery fields of
  `SentPacket`. quinn's estimator took, per acknowledged packet, the lower of the rates between
  its last two sends and last two acknowledgements: with ACKs covering two packets a sample was
  half the rate, and its estimate could stay there.
- The max filter is fed every sample, so a maximum expires after ten round trips and the
  estimate follows a path that slows down. quinn fed it only samples above the estimate, so its
  estimate never fell.
- PROBE_RTT starts only when the minimum RTT has expired: ten seconds without a sample at or
  below it (`rtprop_expired`); leaving PROBE_RTT renews it. quinn started one at the first
  acknowledgement that was not application limited, since none had started yet, and skipped
  them while application limited, which the draft does not.
- STARTUP grows the window by the bytes acknowledged only below its target or before the
  initial window is delivered; quinn compared the gain, not the window, with the target, so its
  window grew without bound, even while application limited.
- `Controller.pacingRate()` (default -1): the pacer sends at no more than BBR's rate, nor than
  1.25 windows per smoothed RTT (`Pacer.rateLimitedWindow`). quinn computes the rate but only
  reports it; its pacer paces the window, so DRAIN could not drain.
- `ControllerMetrics.bandwidthEstimate()`, in bits per second, as quinn's metrics have.
- `Bbr.mode()`, `bandwidthEstimate()`, `minRtt()`, `isAtFullBandwidth()` and `roundCount()` for
  inspection, and a constructor taking the random source of the gain cycle.

Still different from the draft, as in quinn:

- Round trips are counted by packet number (a round ends when a packet sent after the previous
  round's end is acknowledged), not by delivered bytes.
- The PROBE_RTT window is 0.75 BDP (quiche's moderate PROBE_RTT), not four packets, and the cwnd
  is not saved and restored around it; PROBE_RTT ends 200 ms after the bytes in flight first fit
  that window, at a round start.
- Loss recovery uses quiche's conservation and growth recovery window, and a loss during STARTUP
  ends it at the next round without 25% growth. There is no idle restart (`exitingQuiescence` is
  never set) and no special handling of ECN.
- The pacing rate in STARTUP starts at the initial window per minimum RTT once there is a
  bandwidth sample, and never falls during STARTUP; before the first sample the pacer paces the
  window.
- The gain cycle's 0.75 phase lasts until the bytes in flight are down to the BDP
  (`DRAIN_TO_TARGET`), and the ack aggregation seen is added to the window.

**Simulations.** `BbrTest` drives the controller on a fake clock with the connection's
`DeliveryRate` and `Pacer` and a receiver that acknowledges every second packet: STARTUP, DRAIN
and PROBE_BW on 100 Mbit/s and 40 ms (99% of the link used), PROBE_RTT exactly when the minimum
RTT turns ten seconds old (and a new minimum after a route change from 40 to 60 ms), the estimate
and pacing rate following a drop from 50 to 10 Mbit/s within 12 round trips (the ten-round filter)
and a rise at once, application-limited phases, and ten gain-cycle seeds on three paths.
`BbrConnectionTest` runs connections on the in-memory pair through a bottleneck with a drop-tail
queue (`Pair.bandwidth`, `Pair.queueLimit`), seeded so that every run repeats exactly
(`Pair.seeded`): on 20 Mbit/s and 40 ms the estimate is 2.5000 MB/s for each of twenty seeds and
4 MB transfers run at 2.40 MB/s; a drop from 50 to 10 Mbit/s mid-transfer is followed in 13
round trips (3.9 s, with the queue the drop builds); on 50 Mbit/s and 40 ms with 1% random loss,
BBR moves 5.98 MB/s (6.02 without loss) where CUBIC manages 0.45 MB/s.

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
| `QuicServer` | `bind(address, ServerConfig[, EndpointConfig[, DatagramFilter]])`, `unbound(local, ServerConfig, EndpointConfig, DatagramFilter, DatagramSink)` (no socket), `accept()` (blocks until a handshake completes), `receive(from, datagram)`, `inject(from, datagram[, ServerConfig])`, `send(datagram, to)`, `localAddress()`, `close()` |
| `QuicClient` | `create(ClientConfig[, bindAddress, EndpointConfig])`, `connect(remote[, serverName, timeout[, SessionCache]])`, `connectEarly(remote, serverName, timeout[, SessionCache])` (returns at once when it can send 0-RTT data), `sessionCache()`, `close()` |
| `QuicConnection` | `openBidirectionalStream()`, `openUnidirectionalStream()` (block while the peer's stream limit is reached), `acceptStream()`, `sendDatagram`, `receiveDatagram([timeout])`, `maxDatagramSize()`, `updateKeys()`, `close(code, reason)`, `awaitClosed(timeout)`, `closeReason()`, `alpn()`, `serverName()`, `peerCertificates()`, `cipherSuite()`, `keyExchangeGroup()`, `version()`, `initialDestinationId()`, `remoteAddress()`, `localAddress()`, `stats()`, `isResumed()`, `isZeroRtt()`, `earlyDataAccepted()`, `isHandshakeComplete()`, `awaitHandshake(timeout)` |
| `QuicStream` | `getInputStream()` (blocks for data, -1 at the FIN), `getOutputStream()` (blocks on flow control and the send window; `close()` is the FIN), `reset(code)`, `stopSending(code)`, `awaitStopped()` (the peer's STOP_SENDING code, for a writer that is not writing), `close()` (FIN, and STOP_SENDING if unread), `receivedEarlyData()` |
| `...connection.SessionCache` | A client's session tickets (`ClientSessionStore`) and NEW_TOKEN tokens (`TokenStore`, `TokenMemoryCache` after quinn's), by server name: `memory()`, `none()` |
| `QuicConnectionException`, `QuicStreamException` | `IOException`s: the connection ended (with its `ConnectionError`), or the peer reset or stopped the stream (with its code) |
| `...connection.Connection` | sans-I/O: `handleDatagram(now, remote, ecn, bytes)`, `pollTransmit(now, maxDatagrams)`, `handleTimeout(now)`, `pollTimeout()`, `pollEvent()`, `pollEndpointEvent()`; stream, datagram and close calls |
| `...connection.Endpoint` | sans-I/O: `handle(now, remote, ecn, bytes)` returns `Deliver`, `NewConnection` or `Response`; `knows(remote, bytes)`; `connect(...)`; `handleEvent(connection, event)` |
| `...connection.ConnectionEvent` | `HandshakeDataReady` (ALPN and SNI known), `Connected`, `HandshakeConfirmed`, `Stream(StreamEvent)`, `DatagramReceived`, `ConnectionLost(ConnectionError)` |
| `...connection.TransportConfig`, `ServerConfig`, `ClientConfig`, `EndpointConfig` | Immutable builders: idle timeout, windows, stream limits, congestion controller, MTU discovery, DATAGRAM buffers, keep-alive, key log, qlog; certificates (per SNI), ALPN, Retry, NEW_TOKEN tokens and their lifetime, connection cap; trust, server name, version, session cache; CID length and lifetime, reset key, versions |

With a `Ticketer` and `earlyData(true)` in its TLS configuration, a server's `accept()` hands out
a connection that accepted 0-RTT data as soon as its handshake data is ready, before the handshake
completes, so the early requests can be served at once; `QuicStream.receivedEarlyData()` marks
what may be a replay, and `awaitHandshake` waits for the client's Finished. On the client:

```java
QuicConnection c = client.connectEarly(address, "example.com", null);   // at once with a 0-RTT ticket
QuicStream s = c.openBidirectionalStream();       // within the limits of the earlier session
s.getOutputStream().write(idempotentRequest);    // 0-RTT data
c.awaitHandshake(null);
c.earlyDataAccepted();                            // if not, the data went again in 1-RTT
```

A server's `DatagramFilter` sees the datagrams none of its connections claims (by Destination
Connection ID: a client's first Initial, unknown versions, unknown connections) before its endpoint
does, on the receiving thread. It may take a datagram, and later hand it back with `inject`, which
routes it as if it had just arrived (a client's first Initial then starts a connection), or answer
it from the server's socket with `send`. Once a connection exists, its datagrams go straight to it.
MicroProxy's transparent QUIC listener is built this way: it reads each new client's ClientHello
from its Initials, then injects them to intercept the connection, or relays the client's datagrams
elsewhere. `inject(from, datagram, config)` accepts the connection a datagram starts with a
`ServerConfig` of its own (certificates, ALPN, transport parameters, Retry), so one server can offer
each client what another server it reaches offered.

An unbound server (`QuicServer.unbound`) has no socket and no receiving thread: its owner hands it
the datagrams it receives with `receive(from, datagram)`, which routes them as the socket's
receiving thread would (connections first, then the filter, then the endpoint), and the server
hands those it sends to a `DatagramSink`. QUIC then runs over any datagram transport: MicroProxy
intercepts QUIC inside CONNECT-UDP flows this way, the addresses being names it gives each flow.
Path MTU discovery stays off on such a server.

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
  Once the handshake completes, a server sends `newTokens` NEW_TOKEN frames (2 by default, a fresh
  token for each loss), bound to the client's IP for two weeks; a client keeps them by server
  name and presents one in the first Initial of its next connection, which validates its address
  and skips the Retry. A `BloomTokenLog` per endpoint refuses a token's second use.
- **Resumption and 0-RTT.** A client takes a ticket and a token for the server from its
  `SessionCache` (`ClientConfig.sessionCache`, or `QuicClient`'s own) and keeps those it receives.
  With a ticket that allows 0-RTT, it installs the 0-RTT keys at once and keeps within the
  transport parameters the ticket remembers (as quinn's `init_0rtt` filters them, RFC 9000
  section 7.4.1): stream data and datagrams go out in 0-RTT packets, coalesced with the Initial,
  without ACK, CRYPTO, NEW_CONNECTION_ID or PATH_RESPONSE frames. If the server accepts, its new
  parameters must not lower those limits (`PROTOCOL_VIOLATION`). If it rejects, the 0-RTT packets
  are forgotten without counting as lost, their control frames are queued again, and the streams
  send everything again in 1-RTT packets, when what they used fits the server's new limits; else
  the local streams are forgotten, as quinn does. A server with 0-RTT on decrypts 0-RTT packets
  with the client early traffic keys and processes them during the handshake (the endpoint routes
  them by the Initials' connection ID), refuses 0-RTT when a limit is now below the ticket's,
  records which streams carried early data (`receivedEarlyData`), and drops the keys three PTOs
  after the first 1-RTT packet.
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
  on a fake clock, with an MTU, latency, random loss and reordering from a fixed seed, a bottleneck
  rate with a drop-tail queue, and hooks to drop or hold back datagrams. `Pair.seeded` also draws
  both endpoints' randomness (`EndpointConfig.Builder.random`), the TLS randoms, key shares and
  signatures (`TlsConfig.Builder.secureRandom`) and the certificate from a seed, so a run repeats
  exactly in any JVM. Handshakes over every cipher suite and both versions, stream
  transfer, flow-control blocking, stream limits, loss recovery and tail loss, key updates (simple,
  reordered, routine), idle timeout and keep-alive, closes in every state, stateless resets (and
  their rate limit), Version Negotiation, Retry (and expired tokens), CID rotation and retirement,
  zero-length CIDs, datagrams, MTU discovery, anti-amplification, the connection cap.
- `ZeroRttTest` runs resumption between `Pair`s: 0-RTT accepted (the request coalesced with the
  Initial and read by the server before its handshake completes), rejected and sent again in
  1-RTT without counting as lost, a captured first flight replayed from another address (no early
  data, nothing processed), an expired ticket, an ALPN change, smaller transport parameters (the
  streams that no longer fit are forgotten), an application veto, NEW_TOKEN skipping Retry, and a
  reused token. `ZeroRttLoopbackTest` does the same over the blocking API on loopback.
- `LoopbackTest` runs the blocking API over real UDP on loopback: 32 concurrent streams echoing 1 MB
  each with SHA-256 checks, a 24 MB upload, parallel connections, datagrams, closes, resets, key
  updates during a transfer. On a 4-core container, with an 8 KB MTU, the 32-stream echo moves
  100 to 125 MB/s (both directions together) and a single upload 160 to 225 MB/s; with the default 1452-byte
  MTU a warmed-up single stream uploads 150 to 185 MB/s. A 16 MB echo runs with BBR on both sides.
- `BbrTest` and `BbrConnectionTest` simulate BBR on bottleneck links (see [BBR](#bbr)).
- `ConnectionFuzzTest` feeds a connection random and mutated datagrams (nothing may throw or close
  it) and authenticated 1-RTT packets of random frames (they may close it with a protocol error,
  never `INTERNAL_ERROR`).
- `AioquicInteropTest` runs against aioquic 1.4.0 as an external peer, with the echo client and
  server in `src/test/resources/interop/` (raw streams, ALPN `microproxy-test`). It covers a Java
  server with an aioquic client and an aioquic server with a Java client: all three cipher suites
  with X25519, P-256 and P-384 (the server choosing), many streams and multi-megabyte transfers,
  unidirectional streams, datagrams, key updates started by either side, Retry, QUIC version 2,
  closes from either side with their codes and reasons, and resumption with 0-RTT both ways:
  aioquic's client resumes against the Java server and has its request served from early data
  (`resume_client.py`), and the Java client resumes against aioquic's server (`--tickets`) through
  `connectEarly`, both with the early data accepted. An HTTP/3 client on aioquic's
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

Connection migration and path validation (datagrams from another address are dropped;
PATH_CHALLENGE is answered on the current path), the preferred address, sending ACK_FREQUENCY,
ECN marking (the JDK cannot set or read
ECN bits) and GSO. HTTP/3 is not this module's: MicroProxy builds it on this module and
`http3-codec` (its reverse proxy's HTTP/3 listener and its HTTP/3 connections to servers; see
the main README's HTTP/3 section), and the interop test's HTTP/3 server is test code.
