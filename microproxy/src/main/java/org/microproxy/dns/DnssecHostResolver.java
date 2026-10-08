package org.microproxy.dns;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.microproxy.HostResolver;

/**
 * A {@link HostResolver} that validates answers with DNSSEC, the replacement for LittleProxy's
 * dnssec4j-based {@code DnsSecServerResolver}.
 *
 * <p>Queries go to a recursive resolver (by default those in {@code /etc/resolv.conf}) with the DO
 * and CD bits set; every answer is validated locally against the root zone trust anchors (KSK-2017
 * and KSK-2024). With the default {@link Policy#REJECT_BOGUS}, names in signed zones resolve only
 * with valid signatures, names in provably unsigned zones resolve normally, and anything else
 * fails with {@link DnssecValidationException}. Network failures also fail resolution: there is
 * no silent fallback to unvalidated lookups.
 *
 * <p>IP literals and {@code localhost} are returned without a lookup. Answers, zone keys and
 * delegation facts are cached for their TTL, up to an hour.
 */
public final class DnssecHostResolver implements HostResolver {

    /** What to accept. */
    public enum Policy {
        /** Accept secure and provably insecure answers; reject bogus ones. */
        REJECT_BOGUS,
        /** Accept only answers proven secure; names in unsigned zones do not resolve. */
        REQUIRE_SECURE
    }

    /** The result of a lookup. */
    // @value-candidate: becomes a value class in the valhalla build profile
    public record Resolution(List<InetAddress> addresses, boolean secure) {}

    /** IANA root zone trust anchors (https://data.iana.org/root-anchors/root-anchors.xml). */
    public static final List<String> ROOT_TRUST_ANCHORS = List.of(
            ". 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
            ". 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16");

    // @value-candidate: becomes a value class in the valhalla build profile
    private record Cached(Resolution resolution, long expiresAtMillis) {}

    private final DnssecValidator validator;
    private final Policy policy;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    /** Uses the system's resolvers, the IANA root anchors and {@link Policy#REJECT_BOGUS}. */
    public DnssecHostResolver() {
        this(builder());
    }

    private DnssecHostResolver(Builder b) {
        DnsTransport transport = b.transport != null ? b.transport
                : DnsTransport.udp(b.servers != null ? b.servers : DnsTransport.systemServers(), b.timeout);
        List<DnsRecord> anchors = new ArrayList<>();
        for (String ds : b.trustAnchors) {
            anchors.add(parseDs(ds));
        }
        this.validator = new DnssecValidator(transport, anchors, b.clock);
        this.policy = b.policy;
        this.clock = b.clock;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public InetSocketAddress resolve(String host, int port) throws UnknownHostException {
        Resolution resolution = lookup(host);
        if (resolution.addresses().isEmpty()) {
            throw new UnknownHostException(host);
        }
        return new InetSocketAddress(resolution.addresses().getFirst(), port);
    }

    /**
     * Resolves {@code host} to its IPv4 addresses, or IPv6 addresses if it has none.
     *
     * @throws DnssecValidationException if the answer is bogus, or insecure under {@link
     *     Policy#REQUIRE_SECURE}
     * @throws UnknownHostException if the name does not exist or DNS cannot be reached
     */
    public Resolution lookup(String host) throws UnknownHostException {
        Objects.requireNonNull(host, "host");
        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) normalized = normalized.substring(0, normalized.length() - 1);
        if (isIpLiteral(normalized)) {
            return new Resolution(List.of(InetAddress.getByName(host)), true);
        }
        if (normalized.equals("localhost") || normalized.endsWith(".localhost")) {
            return new Resolution(List.of(InetAddress.getLoopbackAddress()), true);
        }
        Cached cached = cache.get(normalized);
        if (cached != null && cached.expiresAtMillis() > clock.millis()) {
            return checkPolicy(host, cached.resolution());
        }
        DnsName name;
        try {
            name = DnsName.parse(normalized);
        } catch (IllegalArgumentException e) {
            throw new UnknownHostException("invalid host name: " + host);
        }
        try {
            DnssecValidator.Answer answer = validator.lookup(name, DnsRecord.A);
            if (answer.records().isEmpty()) {
                answer = validator.lookup(name, DnsRecord.AAAA);
            }
            List<InetAddress> addresses = new ArrayList<>();
            for (DnsRecord r : answer.records()) {
                addresses.add(r.address());
            }
            if (addresses.isEmpty()) {
                throw new UnknownHostException(host);
            }
            Resolution resolution = new Resolution(List.copyOf(addresses), answer.secure());
            long ttlMillis = Math.clamp(answer.ttlSeconds() * 1000, 1_000L, 3_600_000L);
            cache.put(normalized, new Cached(resolution, clock.millis() + ttlMillis));
            return checkPolicy(host, resolution);
        } catch (UnknownHostException e) {
            throw e;
        } catch (IOException e) {
            UnknownHostException failure = new UnknownHostException("DNS lookup for " + host + " failed: " + e.getMessage());
            failure.initCause(e);
            throw failure;
        }
    }

    private Resolution checkPolicy(String host, Resolution resolution) throws DnssecValidationException {
        if (policy == Policy.REQUIRE_SECURE && !resolution.secure()) {
            throw new DnssecValidationException(host + " is in an unsigned zone");
        }
        return resolution;
    }

    private static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) return true;
        if (host.isEmpty()) return false;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) return false;
        }
        return true;
    }

    /** Parses {@code "<owner> <keytag> <algorithm> <digesttype> <hexdigest>"}. */
    static DnsRecord parseDs(String text) {
        String[] parts = text.strip().split("\\s+");
        if (parts.length != 5) throw new IllegalArgumentException("expected '<owner> <tag> <alg> <digest type> <digest>'");
        int tag = Integer.parseInt(parts[1]);
        byte[] digest = HexFormat.of().parseHex(parts[4].toLowerCase(Locale.ROOT));
        byte[] rdata = new byte[4 + digest.length];
        rdata[0] = (byte) (tag >> 8);
        rdata[1] = (byte) tag;
        rdata[2] = (byte) Integer.parseInt(parts[2]);
        rdata[3] = (byte) Integer.parseInt(parts[3]);
        System.arraycopy(digest, 0, rdata, 4, digest.length);
        return new DnsRecord(DnsName.parse(parts[0]), DnsRecord.DS, DnsRecord.CLASS_IN, 86_400, rdata);
    }

    /** Configures a {@link DnssecHostResolver}. */
    public static final class Builder {
        private List<InetSocketAddress> servers;
        private DnsTransport transport;
        private Duration timeout = Duration.ofSeconds(3);
        private Policy policy = Policy.REJECT_BOGUS;
        private List<String> trustAnchors = ROOT_TRUST_ANCHORS;
        private Clock clock = Clock.systemUTC();

        private Builder() {}

        /** Recursive resolvers to query; they must pass DNSSEC records through. */
        public Builder servers(List<InetSocketAddress> servers) {
            this.servers = List.copyOf(servers);
            return this;
        }

        /**
         * Where to send queries, as a DNS-over-HTTPS URL ({@code https://cloudflare-dns.com/dns-query})
         * or a comma-separated list of resolver addresses ({@code 9.9.9.9,149.112.112.112:53}).
         */
        public Builder resolver(String spec) {
            String s = spec.strip();
            if (s.regionMatches(true, 0, "https://", 0, 8)) {
                return transport(DnsTransport.https(URI.create(s), timeout.multipliedBy(3)));
            }
            List<InetSocketAddress> list = new ArrayList<>();
            for (String part : s.split(",")) {
                String p = part.strip();
                int colon = p.lastIndexOf(':');
                boolean hasPort = colon > 0 && p.indexOf(':') == colon;
                String host = hasPort ? p.substring(0, colon) : p.replace("[", "").replace("]", "");
                int port = hasPort ? Integer.parseInt(p.substring(colon + 1)) : 53;
                if (!isIpLiteral(host.toLowerCase(Locale.ROOT))) {
                    throw new IllegalArgumentException("DNS resolver must be an IP address or https URL: " + p);
                }
                try {
                    list.add(new InetSocketAddress(InetAddress.getByName(host), port));
                } catch (UnknownHostException e) {
                    throw new IllegalArgumentException(e);
                }
            }
            return servers(list);
        }

        /** A custom transport (e.g. DNS over HTTPS); overrides {@link #servers}. */
        public Builder transport(DnsTransport transport) {
            this.transport = transport;
            return this;
        }

        /** Per-attempt UDP/TCP timeout. */
        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout);
            return this;
        }

        public Builder policy(Policy policy) {
            this.policy = Objects.requireNonNull(policy);
            return this;
        }

        /** Root DS records in the form {@code ". 20326 8 2 E06D..."}; defaults to the IANA anchors. */
        public Builder trustAnchors(List<String> dsRecords) {
            if (dsRecords.isEmpty()) throw new IllegalArgumentException("at least one trust anchor required");
            this.trustAnchors = List.copyOf(dsRecords);
            return this;
        }

        /** The clock used for signature validity and caching. */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock);
            return this;
        }

        public DnssecHostResolver build() {
            return new DnssecHostResolver(this);
        }
    }
}
