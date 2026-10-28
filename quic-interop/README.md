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

Basic Version Negotiation means server responses and client version-mismatch
detection; it does not automatically retry another version. **RFC 9368 compatible
version negotiation and reliable stream resets with partial delivery are absent.**
Direct v2 support does not satisfy the runner's compatible-negotiation `v2` case.

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
| `v2`, `connectionmigration`, unknown cases/roles | unsupported | unsupported | Exit 127 before configuration or network setup |

The preferred-address `connectionmigration` runner setup is not exposed by this
adapter. This is distinct from the migration machinery already in the library.
For the tiny `zerortt` transfers, the client disables MTU discovery: padded MTU
probes alone otherwise exceed the runner's 1-RTT byte ceiling. Request bytes are
queued before response tasks and filesystem work so they can leave as early data.
The runner maps other scenarios (loss, corruption, multiplexing, amplification,
rebinding) onto these endpoint TESTCASE values. Endpoint support is not itself a
passing result. The upstream runner checks downloaded bytes and packet traces.
Interoperability results are separate from [security assurance](../docs/formal-security.md).

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
