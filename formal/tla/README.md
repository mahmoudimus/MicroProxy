# Bounded TLS 1.3 traffic-key checks

`TrafficKeys.tla` models the post-handshake directional record counters, fragmented
application writes, local and peer-requested KeyUpdate, actual candidate-key
acceptance/rejection, I/O failures, and directional close. It starts after the
initial read/write traffic keys have been accepted. It is an independent model,
not an extraction or a refinement proof of the Java implementation.

## Mapping to Java

| Model | Java owning transition |
| --- | --- |
| `Consume` | `TlsRecordLayer.Tls13.cipher` (line 95): IV/sequence nonce construction, then `sequence++` before cipher initialization and output. Attempts count even if encryption/decryption or output subsequently fails. |
| `ApplicationFragment`, `BeginAutomaticUpdate` | `TlsRecordLayer.write(..., KeyUpdater)` (line 299): test the current counter before **each** fragment; reserve the old key's final slot for KeyUpdate. |
| `SendKeyUpdate`, `FlushKeyUpdate`, write-key decision | `TlsClientConnection.updateWriteKeys` (line 1161): old-key KeyUpdate, flush, derive next secret, validate and install protection. |
| `AcceptWriteKey`, `RejectWriteKey`, read-key decision | `TlsRecordLayer.writeKeys/readKeys` (lines 240/247): construct the actual candidate protection, call `policy.trafficKey` on its key, assign only on acceptance. A rejected label is never activated. |
| `ReceiveKeyUpdate`, `RespondToPeer` | `TlsClientConnection.onKeyUpdate` (line 1144): consume the peer record using old read protection, validate/install next read protection, optionally acquire `writeLock` and answer using the current write protection. |
| `ExhaustedKeyUpdate`, `ReadLimitFailure` | `writeRecord` (line 323) and `read` (line 367): reject an exhausted protection before another nonce attempt. |
| `Fail`, `HandleReadFailure`, `CloseWrite` | `TlsClientConnection.fail` (line 1244), `closeWrite` (line 1204): lock the writer, attempt an old-key alert if a nonce slot remains, and close the applicable directions. |
| Generic failed write/flush, `ReadIOException` | `write` (line 1192) and `read` catch only the relevant `QuicException` paths. Ordinary `IOException` does **not** imply closure or counter reset. |

Line numbers describe the source used when this artifact was added; method names
are the stable mapping. Read records can interleave with a writer holding the
lock. A read-policy failure or requested response waits for that entire write to
finish. Alert construction/output is abstracted atomically with closing; its
nonce attempt is retained even when output fails. Valid decoded KeyUpdates and
single-record KeyUpdate messages are modeled; parsing and message validation are
outside this lifecycle model.

## Checked properties

The safe configurations check `TypeOK`, `NoNonceReuse`, `NonceEventsBelowCap`,
`SequenceBounded`, `NoRejectedKeyActive`, `NoRejectedKeyInstalled`,
`NoDataOnRejectedKey`, `FinalOldKeySlotReserved`, and `ClosedAbsorbing`.

`uses[(direction, epoch, sequence)]` is an incrementing observer, not a guard
against reuse. It records all modeled AEAD attempts, including failed attempts,
so the below-cap property also covers every successfully emitted record.
`installed`, `rejected`, and `dataKeys` retain history. `previousClosed` observes
the preceding state to detect any reopening. The invariants are not conjoined
to `Init` or `Next`; only the production counter/lock/policy control flow
restricts transitions.

| Configuration | Cap | Epoch labels per direction | Fragments per call | Expected result |
| --- | ---: | --- | --- | --- |
| `TrafficKeys-cap2.cfg` | 2 | 0..1 | 1..2 | Complete search, exit 0 |
| `TrafficKeys-cap3.cfg` | 3 | 0..2 | 1..2 | Complete search, exit 0 |
| `TrafficKeys-unsafe-reuse.cfg` | 2 | 0..1 | 1..2 | `NoNonceReuse` violation, exit 12 |
| `TrafficKeys-witness.cfg` | 2 | 0..2 | 1..2 | `NoCoverageWitness` violation, exit 12 |

These are finite, exhaustive searches of the specified model. At a transition
that would install label `MaxEpoch+1`, the explicit `bounded` marker stops that
direction's modeled traffic. This is a finite-prefix boundary, **not** a claim
that Java closes there. No TLC `CONSTRAINT`, action constraint, depth limit, or
disabled-deadlock option truncates the graph. Fully closed/bounded terminal states
have an explicit stuttering transition. No fairness or liveness claim is made.

The witness is a separate expected-failure reachability check. Its counterexample
must contain successful read and write rotations, two successfully emitted
application fragments in one call, a generic I/O failure, an actual candidate
rejection, and both directions closed. This prevents a passing safety check from
being presented as evidence that these branches were reachable when they were
not. It is not a safety-model failure.

The unsafe mutation changes only accepted write-key installation to reset the
sequence while retaining the old key label. TLC must report a real duplicate
nonce attempt, not a parser/type error. A shortest counterexample accepts a peer
update, sends the response under write epoch 0/sequence 0, resets that same key's
counter, then tries close_notify with epoch 0/sequence 0 again.

## Running TLC

Use the pinned official TLA+ tools release 1.7.4 (`tlc2.TLC` identifies its bundled
checker as TLC2 2.19). From this directory, with `TLA2TOOLS_JAR` and `JAVA` pointing
to the pinned jar and a Java 21 executable:

```sh
"$JAVA" -XX:+UseParallelGC -Xmx2g -cp "$TLA2TOOLS_JAR" tlc2.TLC \
  -workers 1 -seed 1 -fp 0 -metadir /tmp/microproxy-tlc-cap2 \
  -config TrafficKeys-cap2.cfg TrafficKeys.tla
```

Repeat with each configuration and a separate `-metadir`. A checker must require
exit 0 and the completed-search success message for safe configurations. For the
two expected failures it must require exit 12 **and** the specifically named
invariant violation. Accepting an arbitrary nonzero exit would allow syntax and
tool failures to masquerade as successful negative controls.

Recorded run on 2026-10-28 with Java 21 and the pinned jar:

| Configuration | Generated states | Distinct states | Depth | Exit / observation |
| --- | ---: | ---: | ---: | --- |
| cap2 | 34,429 | 12,070 | 20 | 0; complete graph, no errors |
| cap3 | 2,402,564 | 801,935 | 35 | 0; complete graph, no errors |
| unsafe-reuse | 3,321 | 1,470 | 7 | 12; `NoNonceReuse` violation |
| witness | 27,680 | 11,273 | 12 | 12; `NoCoverageWitness` violation |

Both successful searches ended with zero queued states. The expected failures
stop at their counterexamples, so their counts are partial searches. These runs
used `-workers 1 -seed 1` and TLC's selected fingerprint polynomial; cap2/unsafe
used the default collector, and cap3/witness used `-XX:+UseParallelGC`. The command
above fixes the polynomial for reproducible subsequent checks. TLC uses 64-bit
state fingerprints: its reported collision estimates were about `1.5e-11` for
cap2 and `1.3e-7` for cap3. This is an additional model-checking limitation, not a
cryptographic assurance bound.

## Assurance limit

Fresh directional epoch labels assume that the actual key/IV derivation yields
distinct protection material; this model does not prove HKDF, AEAD, key
independence, certificate authentication, record encoding, or interoperability.
It does not explore all Java executions, arbitrary epoch counts, real record
caps, TLS 1.2, application thread misuse, or all exceptions. It provides bounded
evidence for the lifecycle abstraction above and a negative control showing that
the nonce invariant can detect reset-without-rekey. It is not evidence of full
TLS correctness or security parity with an established TLS implementation.
