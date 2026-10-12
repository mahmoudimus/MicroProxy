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

LittleProxy used dnssec4j, which checked signatures where present but never anchored them to the
root key or compared DS digests. It fell back to plain DNS on network errors.
