# Secret comparisons and local timing assessment

This source review distinguishes secret authentication material from public protocol data. The
JDK's [`MessageDigest.isEqual`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/MessageDigest.html#isEqual%28byte%5B%5D,byte%5B%5D%29) avoids stopping at a matching prefix; its first argument is the
expected bytes. Input length, parsing, allocation, and the rest of an authentication decision
can still affect timing. A source review or passing equality test cannot prove constant-time
behavior of JIT-generated code, JCA providers, or a deployed service.

## Reviewed paths

| Path | Classification and decision |
|---|---|
| `impl/AdminServer.authorized` / `matches` | Secret admin bearer token or Basic credential. Retain cached expected UTF-8 bytes first in `MessageDigest.isEqual`. Scheme names and Basic delimiters are public parsing. |
| `ProxyAuthenticator` / SOCKS authentication | Basic decoding forwards to the configured authenticator; there is no built-in username/password database. Custom authenticators and script decisions own verification. The guides use byte comparisons or a verifier API. |
| `UpstreamProxyManager.UrlProxy.equals` | Configured upstream credentials affect account and HTTP/2 connection reuse. Compare cached username and password bytes, evaluating both. Redacted URL equality alone must not merge different users. |
| Starlark `digest.equal` and `hmac.compare_digest` | Secret-comparison helpers already use `MessageDigest.isEqual`. Keep them. Scripts must call these helpers themselves; arbitrary script `==` is not timing-safe. |
| TLS Finished, TLS 1.2 Finished, PSK binders, ECH confirmations | Secret-dependent authentication values already use `MessageDigest.isEqual` with the expected value first. Keep them. |
| QUIC reset tokens | Secret tokens already use `MessageDigest.isEqual` on fixed 16-byte arrays. Keep them. |
| QUIC protected packet-number fields | These fields are confidential before authentication. Receive-side header unmasking, fixed-prefix reading and number reconstruction now use generated scalar code and fixed-address adapters, with scoped functional/trace evidence described below. Downstream AEAD/key-phase/metadata handling remains outside that trace claim. |
| QUIC Retry integrity / address-validation tokens / TLS tickets | Retry tags use `MessageDigest.isEqual`; sealed tokens and tickets use JCA AEAD verification. A Retry integrity key is protocol-defined public material. Ticket key names are public routing metadata. Provider timing remains a separate assessment. |
| `MlKem768.DecapsulationKey.decapsulate` | Dafny refinement proves the full 1088-byte comparison and 32-byte candidate/fallback selection with both keys computed. Compiled checks below address source/runtime regressions; JVM timing remains unproved. |
| Key exchange all-zero result | A fixed loop accumulates the zero result, followed by the required rejection decision. JCA agreement/provider internals remain outside this source comparison review. |
| Hostnames, ALPN, cipher/signature/group IDs, session IDs, downgrade markers, HTTP schemes, connection IDs | Public routing or wire data; retain ordinary comparisons. DNSSEC DS digests and NSEC3 hashes are published data, not secret authenticators. General content and object equality are not credential checks. |

The concrete regression found during this audit was account conflation: two upstream URLs with
different usernames and the same password were equal after URL redaction, so HTTPS could reuse
the HTTP account. The regression exercises real `UpstreamProxyManager` routes. Correctness tests
cover identity separation, UTF-8 values, mismatches, absent credentials, and unchanged equal
credentials. They do not establish timing properties.

## QUIC packet-number trace follow-up

The EverQUIC assessment identified additional source-dependent work before AEAD
authentication: header unmasking looped over the recovered PN length, and number
recovery branched on the reconstructed value. The receive path now uses a verified
Dafny scalar implementation with mask selections; its ByteBuffer adapters use
fixed addresses for all four possible PN octets and preserve following ciphertext.
Ordinary string/credential comparison checks do not address this class of leak.

The new packet replay proves full functional equations and two-run observations
under an idealized atomic-word/register observer. It applies the trace theorem to
SSA programs extracted from actual built scalar classes. Trusted structural,
taint and range checkers restrict the emitted code and valid-domain adapters.
Compiler trust includes a documented lowering of two proved bounded-shift helpers;
the generated kernel has no Dafny runtime dependency.

This establishes a scoped conditional source/bytecode trace property. It does not
prove JIT/CPU/JCA/GC timing, ByteBuffer/provider internals, downstream AEAD lengths,
key-phase handling, returned metadata processing or whole-record constant time.
The existing outbound protection path is outside this receive-side theorem.
See the packet trace section in [formal security](formal-security.md) for replay
and remaining trust boundaries. No remote timing exploit was demonstrated by the
source review, and no new empirical timing result is inferred from these proofs.

## Generated crypto runtime follow-up

Production SHAKE/ML-KEM uses Java generated from verified Dafny through the checked
delivery route. An initial prototype used
coefficient division where the earlier Java used shifts/Barrett reduction.
Those paths now use proved primitive arithmetic. Codec checks also reject
payload-sized allocations that could hide a secret length across a native call.

Bytecode inspection found a separate regression before adoption: a narrow Dafny
right-shift helper branches on signed payload, making its selector helper depend
on ciphertext equality. The revised selector widens to 64 bits and shifts by
public literal 56. Compiled controls reject the old helper, an equality-based
branch and payload boxing. Runtime helpers, JDK byte conversions, metadata and
fixed-zero allocations are inspected explicitly. Secret values in some validation
paths have proved bounds making branch outcomes constant; they are not public.

These checks supply no whole-program noninterference or JVM/JIT/CPU timing theorem.
Source zeroing does not prove physical erasure. Earlier timing samples preceded
this backend; the new CPU/throughput measurements are performance evidence only.
See [formal security](formal-security.md)
for exact scope and toolchain assumptions.

## Advisory relevance

[Bouncy Castle CVE-2024-30171](https://github.com/bcgit/bc-java/wiki/CVE%E2%80%902024%E2%80%9030171)
concerns RSA key-exchange timing through the interaction of its TLS APIs and low-level exception
handling. MicroProxy does not depend on Bouncy Castle. Its TLS 1.2 RSA key-exchange path encrypts
with the server's public key; it does not implement the server-side private-key decryption path
described by Marvin. Constant-time equality alone would not address such an exception oracle.

[Bouncy Castle CVE-2026-5598](https://github.com/bcgit/bc-java/wiki/CVE%E2%80%902026%E2%80%905598)
concerns FrodoKEM decapsulation, including verification and sampling. This project implements
ML-KEM-768 independently and does not implement FrodoKEM. Its rejection-selection code warrants
review and measurement, but this advisory is not evidence that this project has that CVE.

[Guava CVE-2026-102554](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94)
concerns allocation during Java deserialization. The parent pins `33.7.2-jre` for the Starlark
runtime and also manages transitive Guava from LittleProxy in the optional `bench` profile.
The affected-version metadata is available in [OSV](https://osv.dev/vulnerability/GHSA-xxph-c9ww-hj94).
Upgrading the dependency does not imply a demonstrated reachable deserialization vulnerability
in the proxy.

## Opt-in local observations

With JDK 21 or newer and Maven configured, from the repository root run:

```bash
scripts/security/assess-local-timing.sh --run /tmp/microproxy-timing 20000 2000 20261028
```

Arguments are output directory, samples per class for comparisons, samples per class for KEM,
and a synthetic input seed. The command builds the relevant test classes and runs a standalone
test-side main. It is not part of JUnit, and neither the script nor the Java main applies a
statistical pass/fail threshold. It emits raw batch elapsed times to `samples.csv` and records
the runtime, means, and Welch t statistics in `summary.txt`. Repeat in fresh JVMs and preserve
the raw samples; a seed reproduces inputs and cohort order, not elapsed times.

Each scenario warms both classes, randomly interleaves balanced classes, uses one operation
call site, and consumes results. Inputs have equal lengths. Comparison scenarios cover first
versus last mismatch, fixed versus random mismatch, equal versus unequal digests, reset tokens,
and the actual upstream comparator. The admin scenario calls the actual private authentication
parser through a test-side method handle, with a real constructor fixture that binds loopback
but never starts an HTTP listener or sends requests. ML-KEM scenarios use a fixed synthetic key
with fixed/random valid ciphertexts, fixed/random rejected ciphertexts, and valid/rejected
ciphertexts. No deployed endpoints, supplied secrets, adaptive guesses, or key recovery are used.

These are exploratory leakage observations. JIT compilation, GC, CPU scheduling and frequency,
cache footprint, fixed-input reuse, batching, and input conversion can create or hide signals.
A large absolute t statistic calls for an isolated repeat and investigation; a small statistic
only says this workload did not distinguish the selected classes in that run. No disassembly,
formal noninterference proof, provider audit, or network threat-model validation is supplied.
