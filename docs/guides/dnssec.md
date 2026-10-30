# DNSSEC

Resolve server names with a validating DNSSEC resolver written for this project, over UDP/TCP or
DNS over HTTPS, with no dependencies. Use this page when the proxy must not be fooled by forged DNS
answers.

`withUseDnsSec(true)` (or `--dnssec`) resolves server names with
`org.microproxy.dns.DnssecHostResolver`, a validating resolver written for this project:

- **Validation:** queries go to a recursive resolver with the DO and CD bits set, and every answer
  is validated locally from the IANA root trust anchors (KSK-2017 and KSK-2024) down through DS
  records.
- **Algorithms:** RSA/SHA-1/256/512, ECDSA P-256/P-384, Ed25519 and Ed448.
- **Unsigned zones:** names in unsigned zones resolve only with a validated NSEC or NSEC3
  (including opt-out) proof that their delegation is unsigned. Signed wildcards need their
  denial proof.
- **Rejection:** anything else is *bogus* and fails with `DnssecValidationException`. Stripping
  signatures therefore cannot downgrade a signed zone. `Policy.REQUIRE_SECURE` also rejects
  unsigned zones.
- **Failure behaviour:** network failures fail the lookup. Unlike dnssec4j, there is no silent
  fallback to unvalidated DNS.
- **Transport:** UDP/TCP to the resolvers in `/etc/resolv.conf` by default, or DNS over HTTPS:
  `DnssecHostResolver.builder().resolver("https://cloudflare-dns.com/dns-query").build()`.
  Use DoH where port 53 is intercepted or blocked.

## Resource limits

Each resolution has an aggregate work budget of 8192 units, shared by aliases, trust-chain
validation and IPv4-to-IPv6 fallback. A signature check costs 128 units, a DS digest costs 8,
and each NSEC3 SHA-1 round costs 1. The resolver refuses an NSEC3 record with more than 150
additional iterations. Exceeding either limit fails validation; it does not mark the answer
unsigned or fall back to unvalidated DNS. These are operation-count limits, not wall-clock
guarantees for every cryptographic provider.

Answer, zone-key, unsigned-delegation and non-delegation caches each retain at most 1024
entries. Access and insertion discard expired entries; eviction causes authenticated
revalidation when the name is needed again. An idle cache may retain its bounded entries
until the next access.

For deployments that need different bounds, configure the resolver through its builder:

```java
DnssecHostResolver resolver = DnssecHostResolver.builder()
        .maxValidationWork(8192)
        .cacheCapacity(1024) // per cache; zero disables retention
        .build();
```

LittleProxy used dnssec4j, which checked signatures where present but never anchored them to the
root key or compared DS digests. It fell back to plain DNS on network errors.
