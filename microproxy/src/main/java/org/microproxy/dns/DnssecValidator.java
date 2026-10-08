package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.microproxy.dns.DnsRecord.Dnskey;
import org.microproxy.dns.DnsRecord.Ds;
import org.microproxy.dns.DnsRecord.Rrsig;

/**
 * Validates DNS answers against the DNSSEC chain of trust (RFC 4033-4035, RFC 5155, RFC 6840).
 *
 * <p>Each RRset is either <em>secure</em> (its signature verifies with a key that chains up to a
 * trust anchor through DS records), <em>insecure</em> (a validated NSEC/NSEC3 proof shows it lies
 * below an unsigned delegation), or <em>bogus</em>, which raises {@link DnssecValidationException}.
 * Unsigned data is never accepted without such a proof, so stripping signatures cannot downgrade a
 * signed zone.
 *
 * <p>The chain is walked top-down: for every label of a name, a DS query decides whether that name
 * is a signed delegation, an unsigned delegation, or not a zone cut. Validated zone keys and
 * delegation facts are cached for their TTL (at most an hour).
 */
final class DnssecValidator {

    private static final System.Logger LOG = System.getLogger(DnssecValidator.class.getName());
    private static final long MAX_CACHE_MILLIS = 3_600_000;
    private static final int MAX_NSEC3_ITERATIONS = 150;
    private static final int MAX_CHAIN = 12;

    enum Security { SECURE, INSECURE }

    /** An RRset and the RRSIGs covering it. */
    record RRset(DnsName name, int type, List<DnsRecord> records, List<DnsRecord> sigs) {
        long minTtl() {
            long ttl = Long.MAX_VALUE;
            for (DnsRecord r : records) ttl = Math.min(ttl, r.ttl());
            return ttl == Long.MAX_VALUE ? 0 : ttl;
        }
    }

    /** The validated DNSKEYs of a signed zone. */
    record ZoneKeys(DnsName zone, List<Dnskey> keys, long expiresAtMillis) {}

    /** The answer to a lookup: records and whether every RRset involved was secure. */
    record Answer(List<DnsRecord> records, boolean secure, long ttlSeconds) {}

    private enum CutKind { SECURE_DELEGATION, INSECURE_DELEGATION, NOT_A_CUT }

    private record Cut(CutKind kind, RRset ds, long ttlSeconds) {}

    private final DnsTransport transport;
    private final List<DnsRecord> trustAnchors;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final Map<DnsName, ZoneKeys> zoneKeys = new ConcurrentHashMap<>();
    private final Map<DnsName, Long> insecureCuts = new ConcurrentHashMap<>();
    private final Map<DnsName, Long> notCuts = new ConcurrentHashMap<>();

    DnssecValidator(DnsTransport transport, List<DnsRecord> trustAnchors, Clock clock) {
        this.transport = transport;
        this.trustAnchors = List.copyOf(trustAnchors);
        this.clock = clock;
    }

    // ---------------------------------------------------------------------------------------
    // Lookups
    // ---------------------------------------------------------------------------------------

    /**
     * Looks up {@code qtype} records for {@code qname}, following and validating CNAME/DNAME
     * chains. Returns an empty answer for NXDOMAIN/NODATA.
     */
    Answer lookup(DnsName qname, int qtype) throws IOException {
        DnsName current = qname;
        DnsMessage message = query(qname, qtype);
        boolean secure = true;
        long ttl = MAX_CACHE_MILLIS / 1000;
        Set<DnsName> seen = new HashSet<>();
        for (int hops = 0; hops < MAX_CHAIN * 2; hops++) {
            if (message.rcode() == DnsMessage.RCODE_NXDOMAIN) {
                return new Answer(List.of(), secure, 0);
            }
            if (message.rcode() != DnsMessage.RCODE_NOERROR) {
                throw new IOException("DNS server returned RCODE " + message.rcode() + " for " + current);
            }
            Map<String, RRset> sets = group(message.answer);
            RRset target = sets.get(key(current, qtype));
            if (target != null) {
                secure &= validate(target, message) == Security.SECURE;
                return new Answer(target.records(), secure, Math.min(ttl, target.minTtl()));
            }
            RRset cname = sets.get(key(current, DnsRecord.CNAME));
            RRset dname = cname == null ? findDname(sets.values(), current) : null;
            if (cname != null || dname != null) {
                RRset alias = cname != null ? cname : dname;
                secure &= validate(alias, message) == Security.SECURE;
                ttl = Math.min(ttl, alias.minTtl());
                current = cname != null ? cname.records().getFirst().target() : substitute(current, dname);
                if (!seen.add(current) || seen.size() > MAX_CHAIN) {
                    throw new IOException("alias chain too long or looping at " + current);
                }
                String prefix = nameKey(current);
                if (group(message.answer).keySet().stream().noneMatch(k -> k.startsWith(prefix))) {
                    message = query(current, qtype);
                }
                continue;
            }
            if (!current.equals(message.questionName)) {
                message = query(current, qtype);
                continue;
            }
            return new Answer(List.of(), secure, 0);
        }
        throw new IOException("alias chain too long for " + qname);
    }

    private static RRset findDname(Iterable<RRset> sets, DnsName name) {
        for (RRset s : sets) {
            if (s.type() == DnsRecord.DNAME && name.isSubdomainOf(s.name()) && !name.equals(s.name())) {
                return s;
            }
        }
        return null;
    }

    /** RFC 6672: replaces the DNAME owner suffix of {@code name} with the DNAME target. */
    private static DnsName substitute(DnsName name, RRset dname) {
        DnsName target = dname.records().getFirst().target();
        int keep = name.labelCount() - dname.name().labelCount();
        byte[][] labels = new byte[keep + target.labelCount()][];
        for (int i = 0; i < keep; i++) labels[i] = name.label(i);
        for (int i = 0; i < target.labelCount(); i++) labels[keep + i] = target.label(i);
        return DnsName.of(labels);
    }

    // ---------------------------------------------------------------------------------------
    // RRset validation
    // ---------------------------------------------------------------------------------------

    /** Validates one RRset from {@code response}; throws if bogus. */
    Security validate(RRset set, DnsMessage response) throws IOException {
        if (set.sigs().isEmpty()) {
            if (walk(set.name()) != null) {
                throw new DnssecValidationException(
                        "unsigned " + typeName(set.type()) + " for " + set.name() + " in a signed zone");
            }
            return Security.INSECURE;
        }
        DnssecValidationException failure = null;
        for (DnsRecord sigRecord : set.sigs()) {
            Rrsig sig = sigRecord.rrsig();
            if (!DnssecCrypto.supportsAlgorithm(sig.algorithm()) || !set.name().isSubdomainOf(sig.signer())) {
                continue;
            }
            ZoneKeys keys = walk(sig.signer());
            if (keys == null) {
                return Security.INSECURE;
            }
            if (!keys.zone().equals(sig.signer())) {
                failure = new DnssecValidationException(sig.signer() + " signs " + set.name() + " but is not a zone");
                continue;
            }
            if (verifyWithKeys(set, sig, keys)) {
                if (sig.labels() < ownerLabels(set.name())) {
                    requireWildcardProof(set.name(), sig.labels(), keys, response);
                }
                return Security.SECURE;
            }
            failure = new DnssecValidationException("signature over " + typeName(set.type()) + " " + set.name()
                    + " by " + sig.signer() + " does not verify");
        }
        throw failure != null ? failure
                : new DnssecValidationException("no usable signature for " + typeName(set.type()) + " " + set.name());
    }

    private boolean verifyWithKeys(RRset set, Rrsig sig, ZoneKeys keys) {
        for (Dnskey key : keys.keys()) {
            if (key.keyTag() == sig.keyTag() && key.algorithm() == sig.algorithm() && verify(set, sig, key)) {
                return true;
            }
        }
        return false;
    }

    /** Whether any signature on {@code set} by {@code keys.zone()} verifies. */
    private boolean signedBy(RRset set, ZoneKeys keys) {
        for (DnsRecord sigRecord : set.sigs()) {
            Rrsig sig = sigRecord.rrsig();
            if (sig.signer().equals(keys.zone()) && set.name().isSubdomainOf(keys.zone())
                    && verifyWithKeys(set, sig, keys)) {
                return true;
            }
        }
        return false;
    }

    /** Verifies one signature over an RRset (RFC 4035 section 5.3). */
    boolean verify(RRset set, Rrsig sig, Dnskey key) {
        if (sig.typeCovered() != set.type() || !set.name().isSubdomainOf(sig.signer())
                || !key.isZoneKey() || key.isRevoked() || key.protocol() != 3) {
            return false;
        }
        int ownerLabels = ownerLabels(set.name());
        if (sig.labels() > ownerLabels) {
            return false;
        }
        long now = clock.instant().getEpochSecond() & 0xffffffffL;
        // RFC 1982 serial arithmetic on the 32-bit timestamps.
        if ((int) (now - sig.inception()) < 0 || (int) (sig.expiration() - now) < 0) {
            LOG.log(Level.DEBUG, "signature over {0} outside its validity period", set.name());
            return false;
        }
        byte[] data = signedData(set, sig.rdataWithoutSignature(), sig.labels(), sig.originalTtl());
        return DnssecCrypto.verify(sig.algorithm(), key.publicKey(), data, sig.signature());
    }

    /**
     * The data an RRSIG signs (RFC 4034 section 3.1.8.1): the RRSIG RDATA without the signature,
     * then each RR in canonical form and order, with the owner name reconstructed for wildcards.
     */
    static byte[] signedData(RRset set, byte[] rrsigPrefix, int sigLabels, long originalTtl) {
        DnsName owner = sigLabels < ownerLabels(set.name()) ? set.name().suffix(sigLabels).wildcardChild() : set.name();
        byte[] ownerWire = owner.toCanonicalWire();
        List<byte[]> rdatas = new ArrayList<>();
        for (DnsRecord r : set.records()) rdatas.add(r.canonicalRdata());
        rdatas.sort(Arrays::compareUnsigned);
        ByteArrayOutputStream data = new ByteArrayOutputStream(512);
        data.writeBytes(rrsigPrefix);
        byte[] previous = null;
        for (byte[] rdata : rdatas) {
            if (previous != null && Arrays.equals(previous, rdata)) continue;
            previous = rdata;
            data.writeBytes(ownerWire);
            data.write(set.type() >> 8);
            data.write(set.type());
            data.write(0);
            data.write(DnsRecord.CLASS_IN);
            data.write((int) (originalTtl >> 24));
            data.write((int) (originalTtl >> 16));
            data.write((int) (originalTtl >> 8));
            data.write((int) originalTtl);
            data.write(rdata.length >> 8);
            data.write(rdata.length);
            data.writeBytes(rdata);
        }
        return data.toByteArray();
    }

    private static int ownerLabels(DnsName name) {
        return name.labelCount() - (name.isWildcard() ? 1 : 0);
    }

    /** RFC 4035 5.3.4 / RFC 5155 8.8: a wildcard answer needs proof that no closer name exists. */
    private void requireWildcardProof(DnsName owner, int sigLabels, ZoneKeys keys, DnsMessage response)
            throws IOException {
        DnsName nextCloser = owner.suffix(sigLabels + 1);
        for (RRset nsec : group(response.authority).values()) {
            if (nsec.type() == DnsRecord.NSEC && signedBy(nsec, keys)) {
                DnsRecord r = nsec.records().getFirst();
                if (nsecCovers(r.name(), r.nsec().next(), owner)) return;
            }
            if (nsec.type() == DnsRecord.NSEC3 && signedBy(nsec, keys)) {
                DnsRecord r = nsec.records().getFirst();
                DnsRecord.Nsec3 n3 = r.nsec3();
                if (n3.hashAlgorithm() == 1 && nsec3Covers(r, DnssecCrypto.nsec3Hash(nextCloser, n3.salt(), n3.iterations()))) {
                    return;
                }
            }
        }
        throw new DnssecValidationException("wildcard answer for " + owner + " without a denial proof");
    }

    // ---------------------------------------------------------------------------------------
    // Chain of trust
    // ---------------------------------------------------------------------------------------

    /**
     * Walks from the root toward {@code name}, validating every delegation. Returns the keys of
     * the deepest signed zone containing {@code name}, or {@code null} if {@code name} lies below
     * a provably unsigned delegation.
     */
    ZoneKeys walk(DnsName name) throws IOException {
        ZoneKeys current = rootKeys();
        long now = clock.millis();
        for (int depth = 1; depth <= name.labelCount(); depth++) {
            DnsName child = name.suffix(depth);
            ZoneKeys cached = zoneKeys.get(child);
            if (cached != null && cached.expiresAtMillis() > now) {
                current = cached;
                continue;
            }
            if (fresh(insecureCuts, child, now)) {
                return null;
            }
            if (fresh(notCuts, child, now)) {
                continue;
            }
            Cut cut = cutStatus(child, current);
            long expires = now + Math.clamp(cut.ttlSeconds() * 1000, 1_000L, MAX_CACHE_MILLIS);
            switch (cut.kind()) {
                case SECURE_DELEGATION -> {
                    ZoneKeys keys = validateDnskeys(child, cut.ds().records(), cut.ttlSeconds());
                    if (keys == null) {
                        insecureCuts.put(child, expires);
                        return null;
                    }
                    zoneKeys.put(child, keys);
                    current = keys;
                }
                case INSECURE_DELEGATION -> {
                    insecureCuts.put(child, expires);
                    return null;
                }
                case NOT_A_CUT -> notCuts.put(child, expires);
            }
        }
        return current;
    }

    private static boolean fresh(Map<DnsName, Long> cache, DnsName name, long now) {
        Long expires = cache.get(name);
        return expires != null && expires > now;
    }

    private ZoneKeys rootKeys() throws IOException {
        ZoneKeys cached = zoneKeys.get(DnsName.ROOT);
        if (cached != null && cached.expiresAtMillis() > clock.millis()) {
            return cached;
        }
        ZoneKeys keys = validateDnskeys(DnsName.ROOT, trustAnchors, MAX_CACHE_MILLIS / 1000);
        if (keys == null) {
            throw new DnssecValidationException("no supported trust anchor for the root zone");
        }
        zoneKeys.put(DnsName.ROOT, keys);
        return keys;
    }

    /**
     * Fetches the DNSKEY set of {@code zone} and checks that a key matching one of the
     * (already validated) DS records signs it. Returns null if no DS uses a supported algorithm,
     * which makes the zone insecure (RFC 4035 section 5.2).
     */
    private ZoneKeys validateDnskeys(DnsName zone, List<DnsRecord> dsRecords, long dsTtl) throws IOException {
        List<Ds> supported = new ArrayList<>();
        for (DnsRecord r : dsRecords) {
            Ds ds = r.ds();
            if (DnssecCrypto.supportsAlgorithm(ds.algorithm()) && DnssecCrypto.supportsDigest(ds.digestType())) {
                supported.add(ds);
            }
        }
        if (supported.isEmpty()) {
            return null;
        }
        DnsMessage message = query(zone, DnsRecord.DNSKEY);
        RRset set = group(message.answer).get(key(zone, DnsRecord.DNSKEY));
        if (set == null) {
            throw new DnssecValidationException("no DNSKEY records for " + zone);
        }
        if (set.sigs().isEmpty()) {
            throw new DnssecValidationException("DNSKEY set of " + zone + " has no signatures"
                    + (zone.isRoot() ? "; the configured DNS server does not return DNSSEC records" : ""));
        }
        List<Dnskey> keys = new ArrayList<>();
        for (DnsRecord r : set.records()) {
            Dnskey k = r.dnskey();
            if (k.isZoneKey() && !k.isRevoked()) keys.add(k);
        }
        for (Dnskey key : keys) {
            for (Ds ds : supported) {
                if (ds.keyTag() != key.keyTag() || ds.algorithm() != key.algorithm()) continue;
                byte[] digest;
                try {
                    digest = DnssecCrypto.dsDigest(ds.digestType(), zone, key.rdata());
                } catch (GeneralSecurityException e) {
                    continue;
                }
                if (!Arrays.equals(digest, ds.digest())) continue;
                for (DnsRecord sigRecord : set.sigs()) {
                    Rrsig sig = sigRecord.rrsig();
                    if (sig.keyTag() == key.keyTag() && sig.algorithm() == key.algorithm()
                            && sig.signer().equals(zone) && verify(set, sig, key)) {
                        long ttl = Math.min(Math.min(dsTtl, set.minTtl()), MAX_CACHE_MILLIS / 1000);
                        long sigExpiryMillis = epochMillis(sig.expiration());
                        long expires = Math.min(clock.millis() + Math.max(1, ttl) * 1000, sigExpiryMillis);
                        return new ZoneKeys(zone, List.copyOf(keys), expires);
                    }
                }
            }
        }
        throw new DnssecValidationException("DNSKEY set of " + zone + " is not signed by a key matching its DS");
    }

    private long epochMillis(long serialSeconds) {
        long now = clock.instant().getEpochSecond();
        return (now + (int) (serialSeconds - (now & 0xffffffffL))) * 1000;
    }

    /** Classifies {@code child} using a DS query answered by the zone of {@code parent}. */
    private Cut cutStatus(DnsName child, ZoneKeys parent) throws IOException {
        DnsMessage message = query(child, DnsRecord.DS);
        if (message.rcode() == DnsMessage.RCODE_NXDOMAIN) {
            // The name does not exist; continuing with the parent's keys can only make data bogus.
            return new Cut(CutKind.NOT_A_CUT, null, 60);
        }
        if (message.rcode() != DnsMessage.RCODE_NOERROR) {
            throw new IOException("DNS server returned RCODE " + message.rcode() + " for DS " + child);
        }
        Map<String, RRset> answer = group(message.answer);
        RRset ds = answer.get(key(child, DnsRecord.DS));
        if (ds != null) {
            if (!signedBy(ds, parent)) {
                throw new DnssecValidationException("DS for " + child + " is not validly signed by " + parent.zone());
            }
            return new Cut(CutKind.SECURE_DELEGATION, ds, ds.minTtl());
        }
        if (answer.containsKey(key(child, DnsRecord.CNAME))) {
            return new Cut(CutKind.NOT_A_CUT, null, 60);
        }
        return denialOfDs(child, parent, message);
    }

    /** Interprets the NSEC/NSEC3 proof in a NODATA response to a DS query. */
    private Cut denialOfDs(DnsName child, ZoneKeys parent, DnsMessage message) throws IOException {
        List<DnsRecord> nsecs = new ArrayList<>();
        List<DnsRecord> nsec3s = new ArrayList<>();
        for (RRset set : group(message.authority).values()) {
            if ((set.type() == DnsRecord.NSEC || set.type() == DnsRecord.NSEC3) && signedBy(set, parent)) {
                (set.type() == DnsRecord.NSEC ? nsecs : nsec3s).addAll(set.records());
            }
        }
        for (DnsRecord r : nsecs) {
            if (r.name().equals(child)) {
                return fromBitmap(child, r.nsec().typeBitmaps(), r.ttl());
            }
        }
        for (DnsRecord r : nsecs) {
            if (nsecCovers(r.name(), r.nsec().next(), child)) {
                // Either an empty non-terminal (next lies below child) or a name that does not
                // exist: neither is a delegation.
                return new Cut(CutKind.NOT_A_CUT, null, r.ttl());
            }
        }
        if (!nsec3s.isEmpty()) {
            DnsRecord.Nsec3 params = nsec3s.getFirst().nsec3();
            if (params.hashAlgorithm() != 1) {
                throw new DnssecValidationException("unsupported NSEC3 hash algorithm " + params.hashAlgorithm());
            }
            if (params.iterations() > MAX_NSEC3_ITERATIONS) {
                // RFC 9276 section 3.2: validators may treat such zones as insecure.
                return new Cut(CutKind.INSECURE_DELEGATION, null, nsec3s.getFirst().ttl());
            }
            byte[] childHash = DnssecCrypto.nsec3Hash(child, params.salt(), params.iterations());
            for (DnsRecord r : nsec3s) {
                if (Arrays.equals(nsec3OwnerHash(r), childHash)) {
                    return fromBitmap(child, r.nsec3().typeBitmaps(), r.ttl());
                }
            }
            // No exact match: closest encloser proof (RFC 5155 8.6). Find the closest ancestor
            // with a matching NSEC3; the next-closer name must be covered.
            for (DnsName encloser = child.parent(); encloser.isSubdomainOf(parent.zone()); encloser = encloser.parent()) {
                byte[] encloserHash = DnssecCrypto.nsec3Hash(encloser, params.salt(), params.iterations());
                boolean matched = nsec3s.stream().anyMatch(r -> Arrays.equals(nsec3OwnerHash(r), encloserHash));
                if (matched) {
                    DnsName nextCloser = child.suffix(encloser.labelCount() + 1);
                    byte[] nextHash = DnssecCrypto.nsec3Hash(nextCloser, params.salt(), params.iterations());
                    for (DnsRecord r : nsec3s) {
                        if (nsec3Covers(r, nextHash)) {
                            // Opt-out spans may hide unsigned delegations; otherwise the name
                            // simply does not exist.
                            return new Cut(r.nsec3().optOut() ? CutKind.INSECURE_DELEGATION : CutKind.NOT_A_CUT,
                                    null, r.ttl());
                        }
                    }
                    break;
                }
                if (encloser.isRoot()) break;
            }
        }
        throw new DnssecValidationException("no valid proof that " + child + " is not a signed delegation of "
                + parent.zone());
    }

    private static Cut fromBitmap(DnsName child, byte[] bitmap, long ttl) throws DnssecValidationException {
        if (DnsRecord.bitmapHas(bitmap, DnsRecord.DS)) {
            throw new DnssecValidationException("denial for DS " + child + " lists DS");
        }
        boolean delegation = DnsRecord.bitmapHas(bitmap, DnsRecord.NS) && !DnsRecord.bitmapHas(bitmap, DnsRecord.SOA);
        return new Cut(delegation ? CutKind.INSECURE_DELEGATION : CutKind.NOT_A_CUT, null, ttl);
    }

    /** Whether an NSEC from {@code owner} to {@code next} covers {@code name} (RFC 4034 6.1 order). */
    static boolean nsecCovers(DnsName owner, DnsName next, DnsName name) {
        int afterOwner = owner.compareTo(name);
        if (afterOwner >= 0) {
            return false;
        }
        // The last NSEC of a zone wraps around to the apex.
        return next.compareTo(owner) <= 0 || name.compareTo(next) < 0;
    }

    private static byte[] nsec3OwnerHash(DnsRecord nsec3) {
        return nsec3.name().labelCount() == 0 ? null : DnssecCrypto.base32HexDecode(nsec3.name().label(0));
    }

    /** Whether an NSEC3 record's hash interval strictly covers {@code hash}. */
    static boolean nsec3Covers(DnsRecord nsec3, byte[] hash) {
        byte[] owner = nsec3OwnerHash(nsec3);
        if (owner == null) return false;
        byte[] next = nsec3.nsec3().nextHashed();
        if (DnssecCrypto.compareUnsigned(owner, next) < 0) {
            return DnssecCrypto.compareUnsigned(owner, hash) < 0 && DnssecCrypto.compareUnsigned(hash, next) < 0;
        }
        return DnssecCrypto.compareUnsigned(hash, owner) > 0 || DnssecCrypto.compareUnsigned(hash, next) < 0;
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private DnsMessage query(DnsName name, int type) throws IOException {
        int id = random.nextInt(0x10000);
        byte[] response = transport.exchange(DnsMessage.query(id, name, type));
        DnsMessage message;
        try {
            message = DnsMessage.parse(response);
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed DNS response for " + name, e);
        }
        if (message.id != id || !message.isResponse() || message.questionName == null
                || !message.questionName.equals(name) || message.questionType != type) {
            throw new IOException("DNS response does not match query for " + name);
        }
        LOG.log(Level.DEBUG, "DNS {0} {1}: rcode {2}, {3} answers", name, typeName(type), message.rcode(),
                message.answer.size());
        return message;
    }

    /** Groups records into RRsets (by owner and type), attaching RRSIGs to what they cover. */
    static Map<String, RRset> group(List<DnsRecord> records) {
        Map<String, RRset> sets = new LinkedHashMap<>();
        for (DnsRecord r : records) {
            if (r.type() == DnsRecord.RRSIG || r.type() == DnsRecord.OPT || r.dnsClass() != DnsRecord.CLASS_IN) continue;
            sets.computeIfAbsent(key(r.name(), r.type()),
                    k -> new RRset(r.name(), r.type(), new ArrayList<>(), new ArrayList<>())).records().add(r);
        }
        for (DnsRecord r : records) {
            if (r.type() != DnsRecord.RRSIG) continue;
            RRset set = sets.get(key(r.name(), r.rrsig().typeCovered()));
            if (set != null) set.sigs().add(r);
        }
        return sets;
    }

    private static String nameKey(DnsName name) {
        return name.toString().toLowerCase(Locale.ROOT) + "/";
    }

    static String key(DnsName name, int type) {
        return nameKey(name) + type;
    }

    static String typeName(int type) {
        return switch (type) {
            case DnsRecord.A -> "A";
            case DnsRecord.AAAA -> "AAAA";
            case DnsRecord.CNAME -> "CNAME";
            case DnsRecord.DNAME -> "DNAME";
            case DnsRecord.DS -> "DS";
            case DnsRecord.DNSKEY -> "DNSKEY";
            case DnsRecord.NSEC -> "NSEC";
            case DnsRecord.NSEC3 -> "NSEC3";
            default -> "TYPE" + type;
        };
    }
}
