# QUIC Interop Runner endpoint

This optional application exposes MicroProxy's QUIC library as the file server and
client required by the [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner).
It uses `hq-interop` (HTTP/0.9 over QUIC) and `h3` for the HTTP/3 case. It does not
participate in proxy routing or change browser profiles.

## Protocol scope

The library implements QUIC v1 and direct v2, TLS 1.3, bidirectional/unidirectional
streams, Retry, AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305, key updates, ticket
resumption, 0-RTT, DATAGRAM, and client/server migration machinery. Stream priority
scheduling is exposed through the sans-I/O `Connection` API, not the blocking facade.

Basic Version Negotiation includes server responses and client version-mismatch
detection, without automatic retry. The library also has partial client-side
RFC 9368 compatible-version following and chosen-version validation. Complete
client/server conformance and the adapter's `v2` case remain unverified;
direct v2 alone does not satisfy that test. Reliable stream resets with partial
delivery are absent.

| Endpoint TESTCASE | Client | Server | Behavior |
|---|---|---|---|
| `handshake` | yes | yes | Verified certificate/hostname, file download |
| `transfer` | yes | yes | Concurrent request streams, small flow-control windows |
| `retry` | yes | yes | Server requires Retry |
| `chacha20` | yes | yes | Restrict TLS cipher selection |
| `keyupdate` | yes | unsupported | Client initiates update; runner uses `transfer` for server |
| `multiconnect` | yes | yes | Separate connection per request |
| `resumption`, `zerortt` | yes | yes | First connection obtains ticket, second resumes; 0-RTT uses early connection API |
| `http3` | yes | yes | Static QPACK, control stream, framed file response |
| `rebind-port`, `rebind-addr` | yes | yes | Ordinary transfer; runner normally sends `transfer` and mutates the network |
| `v2`, `connectionmigration`, unknown cases/roles | unsupported | unsupported | Exit 127 before configuration or network setup; library version negotiation is partial |

The preferred-address `connectionmigration` runner setup is not exposed by this
adapter. This is distinct from the migration machinery already in the library.
For the tiny `zerortt` transfers, the client disables MTU discovery: padded MTU
probes alone otherwise exceed the runner's 1-RTT byte ceiling. Request bytes are
queued before response tasks and filesystem work so they can leave as early data.
The runner maps other scenarios (loss, corruption, multiplexing, amplification,
rebinding) onto these endpoint TESTCASE values. Endpoint support is not itself a
passing result. The upstream runner checks downloaded bytes and packet traces.
Interoperability results are separate from [security assurance](../docs/formal-security.md).

## Recorded local runner results

The [2026-10-28 result manifest](results/2026-10-28.json) records the source revision,
image digest, peer/simulator pins and raw result hashes. All 22 selected test/role
pairs passed: nine cases in each direction against aioquic (handshake, transfer,
ChaCha20, Retry, resumption, 0-RTT, key update, HTTP/3, IPv6), plus handshake and
transfer in each direction against quic-go. These were local executions of the
upstream runner; they are not results from the public testing service.

An earlier bringup run passed multiplexing and port/address rebinding, but failed
the 0-RTT byte ceiling. The adapter fix and the successful replay are recorded;
those earlier passes are excluded from the 22-case final-image count. The complete
loss/corruption/measurement matrix has not been rerun here. Logs, packet captures
and test traffic secrets remain outside the repository.

## Build and run

From the repository root, with JDK 21 and Maven:

```sh
mvn --batch-mode -Pinterop -pl quic-interop -am verify
python3 -m unittest discover -s quic-interop -p 'test_*.py' -v
docker build --platform linux/amd64 -f quic-interop/Dockerfile \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  -t mahmoudimus/microproxy-quic-interop:local .
```

The default reactor excludes this module. The shaded jar is
`quic-interop/target/quic-interop.jar`. The Dockerfile pins base images and uses the
official simulator endpoint's routing setup. Its build context allowlist excludes
the checkout's history, tests, local files and generated artifacts.

The [runner contract](https://github.com/quic-interop/quic-interop-runner/blob/master/quic.md)
supplies `ROLE`, `TESTCASE`, `REQUESTS`, `/certs`, `/www`, `/downloads`,
`SSLKEYLOGFILE` and `QLOGDIR`. Both SEC1 EC and PKCS#8 private keys are accepted.
Files are constrained to their roots, symlinks/traversal are rejected, and client
downloads are published atomically after stream completion. Key logs and qlogs
contain test connection secrets; retain them with the test evidence, not in Git.

For direct local smoke tests only, `MICROPROXY_INTEROP_SKIP_SETUP=1` bypasses the
simulator routing setup. `PORT`, `CERTS`, `WWW`, and `DOWNLOADS` allow temporary
local fixtures; the standard container defaults are used by the upstream runner.

In a clone of the runner, add the `microproxy` entry from the registration PR to
`implementations_quic.json`, install its requirements and tshark >= 4.5, then run:

```sh
python run.py -s aioquic -c microproxy -t handshake,transfer \
  -r microproxy=mahmoudimus/microproxy-quic-interop:local \
  -l logs-client -j client-results.json
python run.py -s microproxy -c aioquic -t handshake,transfer \
  -r microproxy=mahmoudimus/microproxy-quic-interop:local \
  -l logs-server -j server-results.json
```

The endpoint CI builds and tests the optional module and image; it does not claim
the upstream simulator matrix runs in CI. Public images are manually published
from a tested revision. Update `latest` only after repeating both-role runner
checks, and keep the revision tag and immutable image digest with the results.
