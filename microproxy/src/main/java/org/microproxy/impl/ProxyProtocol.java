package org.microproxy.impl;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import org.microproxy.http.HttpResponseStatus;

/** Reads PROXY protocol v1/v2 headers and writes v1 headers (HAProxy PROXY protocol spec). */
final class ProxyProtocol {

    private static final byte[] V2_SIGNATURE = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    /** How a v1 header starts. */
    private static final byte[] V1_SIGNATURE = "PROXY ".getBytes(StandardCharsets.US_ASCII);
    /** The longest a v1 header may be, CRLF included (the spec's 107 bytes). */
    static final int V1_MAX_LENGTH = 107;
    /** A v2 header's fixed part: the signature, version and command, family, and length. */
    static final int V2_FIXED_LENGTH = 16;

    /** What a connection's first bytes are, as far as PROXY protocol goes. */
    enum Start {
        /** A v1 header's signature, {@code "PROXY "}. */
        V1,
        /** A v2 header's 12-byte signature. */
        V2,
        /** Something else: not a PROXY header. */
        OTHER,
        /** Bytes so far match a signature, but are fewer than it. */
        PARTIAL
    }

    /**
     * What {@code first} (the bytes received so far, at least one) start with: a whole signature,
     * a prefix of one, or something that is neither. Leading bytes that match no signature decide
     * at once, so an HTTP request or a TLS ClientHello is told apart by its first byte or few.
     */
    static Start start(byte[] first) {
        if (startsWith(first, V1_SIGNATURE)) return Start.V1;
        if (startsWith(first, V2_SIGNATURE)) return Start.V2;
        if (isPrefix(first, V1_SIGNATURE) || isPrefix(first, V2_SIGNATURE)) return Start.PARTIAL;
        return Start.OTHER;
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        return bytes.length >= prefix.length && Arrays.equals(bytes, 0, prefix.length, prefix, 0, prefix.length);
    }

    /** Whether all of {@code bytes} (fewer than {@code signature}'s) match its start. */
    private static boolean isPrefix(byte[] bytes, byte[] signature) {
        return bytes.length < signature.length && Arrays.equals(bytes, 0, bytes.length, signature, 0, bytes.length);
    }

    /**
     * How many bytes the header that {@code buffered} starts with ({@code start} {@link Start#V1}
     * or {@link Start#V2}) takes, or -1 while that is not known: a v1 header ends at its LF (and
     * is malformed if it has none within {@link #V1_MAX_LENGTH} bytes), a v2 header's length
     * field follows its fixed part.
     */
    static int headerLength(Start start, byte[] buffered) throws ProtocolException {
        if (start == Start.V1) {
            for (int i = 0; i < Math.min(buffered.length, V1_MAX_LENGTH); i++) {
                if (buffered[i] == '\n') return i + 1;
            }
            if (buffered.length >= V1_MAX_LENGTH) throw new ProtocolException("PROXY v1 header too long");
            return -1;
        }
        if (buffered.length < V2_FIXED_LENGTH) return -1;
        return V2_FIXED_LENGTH + (((buffered[14] & 0xff) << 8) | (buffered[15] & 0xff));
    }

    /** The addresses carried by a PROXY header; addresses are null for LOCAL/UNKNOWN. */
    // @value-candidate: becomes a value class in the valhalla build profile
    record Header(InetSocketAddress source, InetSocketAddress destination) {}

    private ProxyProtocol() {}

    static Header read(ByteReader in) throws IOException {
        int first = in.read();
        if (first == 'P') {
            String line = in.readLine(106, HttpResponseStatus.BAD_REQUEST);
            if (line == null || !line.startsWith("ROXY ")) throw new ProtocolException("bad PROXY v1 header");
            return parseV1(line.substring(5));
        }
        if (first == 0x0D) {
            byte[] rest = new byte[15];
            in.readFully(rest, 0, 15);
            for (int i = 1; i < 12; i++) {
                if (rest[i - 1] != V2_SIGNATURE[i]) throw new ProtocolException("bad PROXY v2 signature");
            }
            int verCmd = rest[11] & 0xff;
            int family = rest[12] & 0xff;
            int len = ((rest[13] & 0xff) << 8) | (rest[14] & 0xff);
            byte[] body = new byte[len];
            in.readFully(body, 0, len);
            if ((verCmd >> 4) != 2) throw new ProtocolException("bad PROXY v2 version");
            if ((verCmd & 0x0f) == 0) return new Header(null, null); // LOCAL
            return switch (family >> 4) {
                case 1 -> addresses(body, 4);
                case 2 -> addresses(body, 16);
                default -> new Header(null, null);
            };
        }
        throw new ProtocolException("missing PROXY protocol header");
    }

    private static Header parseV1(String rest) throws IOException {
        String[] parts = rest.split(" ");
        if (parts.length >= 1 && parts[0].equals("UNKNOWN")) return new Header(null, null);
        if (parts.length != 5 || !(parts[0].equals("TCP4") || parts[0].equals("TCP6"))) {
            throw new ProtocolException("bad PROXY v1 header");
        }
        try {
            InetAddress src = literal(parts[1]);
            InetAddress dst = literal(parts[2]);
            return new Header(
                    new InetSocketAddress(src, port(parts[3])), new InetSocketAddress(dst, port(parts[4])));
        } catch (IllegalArgumentException e) {
            throw new ProtocolException("bad PROXY v1 header");
        }
    }

    private static Header addresses(byte[] body, int addrLen) throws IOException {
        if (body.length < addrLen * 2 + 4) throw new ProtocolException("short PROXY v2 address block");
        byte[] src = Arrays.copyOfRange(body, 0, addrLen);
        byte[] dst = Arrays.copyOfRange(body, addrLen, addrLen * 2);
        int sport = ((body[addrLen * 2] & 0xff) << 8) | (body[addrLen * 2 + 1] & 0xff);
        int dport = ((body[addrLen * 2 + 2] & 0xff) << 8) | (body[addrLen * 2 + 3] & 0xff);
        return new Header(
                new InetSocketAddress(InetAddress.getByAddress(src), sport),
                new InetSocketAddress(InetAddress.getByAddress(dst), dport));
    }

    private static InetAddress literal(String text) throws IOException {
        // Only accept literals: never trigger a DNS lookup on untrusted input.
        if (!Tls.isIpLiteral(text)) throw new IllegalArgumentException(text);
        return InetAddress.getByName(text);
    }

    private static int port(String text) {
        int p = Integer.parseInt(text);
        if (p < 0 || p > 65535) throw new IllegalArgumentException(text);
        return p;
    }

    /**
     * The peers whose PROXY headers are honored ({@code withProxyProtocolTrustedSources}): IP
     * addresses and CIDR ranges, parsed strictly (no host names, so no DNS lookups). Empty trusts
     * every peer.
     */
    static final class TrustedSources {

        static final TrustedSources ALL = new TrustedSources(List.of(), List.of());

        private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
        /** Hex digits and colons (dots for an embedded IPv4 address): parsed as a literal, never looked up. */
        private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*");

        // @value-candidate: becomes a value class in the valhalla build profile
        private record Range(byte[] network, int prefixLength) {}

        private final List<Range> ranges;
        private final List<String> entries;

        private TrustedSources(List<Range> ranges, List<String> entries) {
            this.ranges = List.copyOf(ranges);
            this.entries = List.copyOf(entries);
        }

        /**
         * Parses {@code sources}: each an IP address or a CIDR range.
         *
         * @throws IllegalArgumentException for an entry that is neither
         */
        static TrustedSources parse(List<String> sources) {
            List<Range> ranges = new ArrayList<>();
            List<String> entries = new ArrayList<>();
            for (String raw : sources) {
                String entry = raw.strip();
                if (entry.isEmpty()) continue;
                int slash = entry.indexOf('/');
                String text = slash < 0 ? entry : entry.substring(0, slash);
                byte[] network = address(text, raw);
                // An IPv4-mapped IPv6 range (::ffff:10.0.0.0/104) is matched as the IPv4 range it maps.
                int bits = IPV4.matcher(text).matches() || network.length == 16 ? network.length * 8 : 128;
                int prefix = bits;
                if (slash >= 0) {
                    String length = entry.substring(slash + 1);
                    if (length.isEmpty() || length.length() > 3 || !length.chars().allMatch(c -> c >= '0' && c <= '9')) {
                        throw new IllegalArgumentException("bad CIDR prefix length in PROXY protocol trusted source: " + raw);
                    }
                    prefix = Integer.parseInt(length);
                    if (prefix > bits || (bits == 128 && network.length == 4 && prefix < 96)) {
                        throw new IllegalArgumentException("bad CIDR prefix length in PROXY protocol trusted source: " + raw);
                    }
                }
                ranges.add(new Range(network, bits == 128 && network.length == 4 ? prefix - 96 : prefix));
                entries.add(entry);
            }
            return new TrustedSources(ranges, entries);
        }

        private static byte[] address(String text, String raw) {
            String bad = "PROXY protocol trusted source is not an IP address or CIDR range: " + raw;
            if (IPV4.matcher(text).matches()) {
                String[] octets = text.split("\\.");
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    int octet = Integer.parseInt(octets[i]);
                    if (octet > 255) throw new IllegalArgumentException(bad);
                    bytes[i] = (byte) octet;
                }
                return bytes;
            }
            if (!IPV6.matcher(text).matches()) throw new IllegalArgumentException(bad);
            try {
                // A string with ':' is parsed as an IPv6 literal, never looked up.
                return normalize(InetAddress.getByName(text));
            } catch (IOException e) {
                throw new IllegalArgumentException(bad);
            }
        }

        /** The address's bytes, an IPv4-mapped IPv6 address as IPv4. */
        private static byte[] normalize(InetAddress address) {
            byte[] bytes = address.getAddress();
            if (bytes.length == 16) {
                boolean mapped = bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
                for (int i = 0; i < 10 && mapped; i++) mapped = bytes[i] == 0;
                if (mapped) return Arrays.copyOfRange(bytes, 12, 16);
            }
            return bytes;
        }

        /** Whether every peer is trusted (no sources were given). */
        boolean all() {
            return ranges.isEmpty();
        }

        /** The entries as given (stripped), for configuration dumps. */
        List<String> entries() {
            return entries;
        }

        /** Whether headers from {@code peer} are honored. */
        boolean trusts(InetSocketAddress peer) {
            if (ranges.isEmpty()) return true;
            if (peer == null || peer.getAddress() == null) return false;
            byte[] address = normalize(peer.getAddress());
            for (Range range : ranges) {
                if (range.network().length == address.length && samePrefix(address, range.network(), range.prefixLength())) {
                    return true;
                }
            }
            return false;
        }

        private static boolean samePrefix(byte[] a, byte[] b, int bits) {
            int whole = bits / 8;
            for (int i = 0; i < whole; i++) {
                if (a[i] != b[i]) return false;
            }
            int rest = bits % 8;
            if (rest == 0) return true;
            int mask = (0xff << (8 - rest)) & 0xff;
            return (a[whole] & mask) == (b[whole] & mask);
        }
    }

    /** Encodes a v1 header for a TCP connection from {@code source} to {@code destination}. */
    static byte[] encodeV1(InetSocketAddress source, InetSocketAddress destination) {
        if (source == null || destination == null
                || source.getAddress() == null || destination.getAddress() == null) {
            return "PROXY UNKNOWN\r\n".getBytes(StandardCharsets.US_ASCII);
        }
        InetAddress src = source.getAddress();
        InetAddress dst = destination.getAddress();
        boolean v6 = src instanceof Inet6Address || dst instanceof Inet6Address;
        String line = "PROXY " + (v6 ? "TCP6 " : "TCP4 ")
                + text(src, v6) + " " + text(dst, v6) + " "
                + source.getPort() + " " + destination.getPort() + "\r\n";
        return line.getBytes(StandardCharsets.US_ASCII);
    }

    private static String text(InetAddress address, boolean v6) {
        if (v6 && !(address instanceof Inet6Address)) {
            return "::ffff:" + address.getHostAddress();
        }
        String s = address.getHostAddress();
        int scope = s.indexOf('%');
        return scope >= 0 ? s.substring(0, scope) : s;
    }
}
