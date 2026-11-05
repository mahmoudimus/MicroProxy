# Reviewed source candidate for epoch 004

These templates publish the instrumented executable Dafny source for review and
replay before production adoption. They are not production `.dfy` files and do
not expand the strict 85-source production inventory. The existing production
sources are adopted only after the separate consumer and delivery gates pass.

The selected epoch manifest requires exactly these current replacements:

| Production destination | Template SHA256 |
| --- | --- |
| `formal/crypto/NativeKeccak.dfy` | `d1682b1b9f6014d2d8d290841801bd70d4771feaf90581bde6bb0791723d60df` |
| `formal/crypto/NativeShake.dfy` | `97a25d13a672b46b2e947af1537a6eabbd1ada5d3912c83c0f5a8457e31df816` |
| `formal/crypto/native_shake_domain.dfy` | `0029621ea31b6edf10c69b62c197f904f0202270e5f6b3f45b789a031622e084` |

Prepare a fresh source copy of this branch outside Git. Copy each `.dfy.in`
template to its corresponding production destination in that private copy,
removing only the `.in` suffix. Keep every other production source unchanged.
Run the [source-view constructor](../README.md) against that explicit candidate
root, with the externally selected epoch manifest digest. The constructor checks
the complete source, support and tooling inventories; these hashes alone do not
authorize arbitrary other changes.

The resulting authenticated current view retains the paired harness as a
template. Materializing that additional live `.dfy` file belongs to a separate
proof stage, which has 86 sources and cannot be admitted as production85.

Source specifications, logical trace properties and coverage checks have
distinct proof and trusted-tool boundaries. These templates themselves are not
a proof result, artifact qualification, production adoption or JVM timing claim.
