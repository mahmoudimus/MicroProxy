package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A resource record. RDATA is stored uncompressed (embedded names expanded) in original case.
 */
// @value-candidate: becomes a value class in the valhalla build profile
record DnsRecord(DnsName name, int type, int dnsClass, long ttl, byte[] rdata) {

    static final int A = 1;
    static final int NS = 2;
    static final int CNAME = 5;
    static final int SOA = 6;
    static final int PTR = 12;
    static final int MX = 15;
    static final int AAAA = 28;
    static final int SRV = 33;
    static final int DNAME = 39;
    static final int OPT = 41;
    static final int DS = 43;
    static final int RRSIG = 46;
    static final int NSEC = 47;
    static final int DNSKEY = 48;
    static final int NSEC3 = 50;
    static final int CLASS_IN = 1;

    /** The address of an A or AAAA record. */
    InetAddress address() {
        try {
            return InetAddress.getByAddress(rdata);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The target of a CNAME or DNAME record. */
    DnsName target() {
        return readName(rdata, 0).name;
    }

    /**
     * RDATA in canonical form for signing: embedded names of the RFC 4034 6.2 / RFC 6840 5.1 types
     * are lowercased.
     */
    byte[] canonicalRdata() {
        return switch (type) {
            case NS, CNAME, PTR, DNAME -> readName(rdata, 0).name.toCanonicalWire();
            case MX -> concat(Arrays.copyOf(rdata, 2), readName(rdata, 2).name.toCanonicalWire());
            case SRV -> concat(Arrays.copyOf(rdata, 6), readName(rdata, 6).name.toCanonicalWire());
            case SOA -> {
                NameAt mname = readName(rdata, 0);
                NameAt rname = readName(rdata, mname.end);
                yield concat(mname.name.toCanonicalWire(), rname.name.toCanonicalWire(),
                        Arrays.copyOfRange(rdata, rname.end, rdata.length));
            }
            default -> rdata;
        };
    }

    /** A name read from uncompressed wire data and the offset just after it. */
    // @value-candidate: becomes a value class in the valhalla build profile
    record NameAt(DnsName name, int end) {}

    static NameAt readName(byte[] data, int offset) {
        List<byte[]> labels = new ArrayList<>();
        int pos = offset;
        while (true) {
            if (pos >= data.length) throw new IllegalArgumentException("truncated name");
            int len = data[pos] & 0xff;
            if (len == 0) {
                return new NameAt(DnsName.of(labels.toArray(byte[][]::new)), pos + 1);
            }
            if (len > 63 || pos + 1 + len > data.length) throw new IllegalArgumentException("bad label");
            labels.add(Arrays.copyOfRange(data, pos + 1, pos + 1 + len));
            pos += 1 + len;
        }
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }

    // --- RRSIG ----------------------------------------------------------------------------

    /** Parsed RRSIG RDATA (RFC 4034 section 3.1). */
    // @value-candidate: becomes a value class in the valhalla build profile
    record Rrsig(int typeCovered, int algorithm, int labels, long originalTtl, long expiration,
            long inception, int keyTag, DnsName signer, byte[] signature, byte[] rdataWithoutSignature) {}

    Rrsig rrsig() {
        ByteBuffer b = ByteBuffer.wrap(rdata);
        int typeCovered = b.getShort() & 0xffff;
        int algorithm = b.get() & 0xff;
        int labels = b.get() & 0xff;
        long originalTtl = b.getInt() & 0xffffffffL;
        long expiration = b.getInt() & 0xffffffffL;
        long inception = b.getInt() & 0xffffffffL;
        int keyTag = b.getShort() & 0xffff;
        NameAt signer = readName(rdata, 18);
        byte[] signature = Arrays.copyOfRange(rdata, signer.end, rdata.length);
        byte[] prefix = concat(Arrays.copyOf(rdata, 18), signer.name.toCanonicalWire());
        return new Rrsig(typeCovered, algorithm, labels, originalTtl, expiration, inception, keyTag,
                signer.name, signature, prefix);
    }

    // --- DNSKEY / DS ----------------------------------------------------------------------

    /** Parsed DNSKEY RDATA (RFC 4034 section 2.1). */
    // @value-candidate: becomes a value class in the valhalla build profile
    record Dnskey(int flags, int protocol, int algorithm, byte[] publicKey, int keyTag, byte[] rdata) {
        boolean isZoneKey() {
            return (flags & 0x0100) != 0;
        }

        boolean isRevoked() {
            return (flags & 0x0080) != 0;
        }
    }

    Dnskey dnskey() {
        int flags = ((rdata[0] & 0xff) << 8) | (rdata[1] & 0xff);
        return new Dnskey(flags, rdata[2] & 0xff, rdata[3] & 0xff,
                Arrays.copyOfRange(rdata, 4, rdata.length), keyTag(rdata), rdata);
    }

    /** RFC 4034 Appendix B key tag. */
    static int keyTag(byte[] dnskeyRdata) {
        long ac = 0;
        for (int i = 0; i < dnskeyRdata.length; i++) {
            ac += (i & 1) == 1 ? dnskeyRdata[i] & 0xff : (dnskeyRdata[i] & 0xff) << 8;
        }
        ac += (ac >> 16) & 0xffff;
        return (int) (ac & 0xffff);
    }

    /** Parsed DS RDATA (RFC 4034 section 5.1). */
    // @value-candidate: becomes a value class in the valhalla build profile
    record Ds(int keyTag, int algorithm, int digestType, byte[] digest) {}

    Ds ds() {
        return new Ds(((rdata[0] & 0xff) << 8) | (rdata[1] & 0xff), rdata[2] & 0xff, rdata[3] & 0xff,
                Arrays.copyOfRange(rdata, 4, rdata.length));
    }

    // --- NSEC / NSEC3 ---------------------------------------------------------------------

    /** Parsed NSEC RDATA (RFC 4034 section 4.1). */
    record Nsec(DnsName next, byte[] typeBitmaps) {}

    Nsec nsec() {
        NameAt next = readName(rdata, 0);
        return new Nsec(next.name, Arrays.copyOfRange(rdata, next.end, rdata.length));
    }

    /** Parsed NSEC3 RDATA (RFC 5155 section 3.2). */
    record Nsec3(int hashAlgorithm, int flags, int iterations, byte[] salt, byte[] nextHashed, byte[] typeBitmaps) {
        boolean optOut() {
            return (flags & 1) != 0;
        }
    }

    Nsec3 nsec3() {
        int pos = 0;
        int alg = rdata[pos++] & 0xff;
        int flags = rdata[pos++] & 0xff;
        int iterations = ((rdata[pos] & 0xff) << 8) | (rdata[pos + 1] & 0xff);
        pos += 2;
        int saltLen = rdata[pos++] & 0xff;
        byte[] salt = Arrays.copyOfRange(rdata, pos, pos + saltLen);
        pos += saltLen;
        int hashLen = rdata[pos++] & 0xff;
        byte[] next = Arrays.copyOfRange(rdata, pos, pos + hashLen);
        pos += hashLen;
        return new Nsec3(alg, flags, iterations, salt, next, Arrays.copyOfRange(rdata, pos, rdata.length));
    }

    /** Whether an NSEC/NSEC3 type bitmap (RFC 4034 4.1.2) contains {@code type}. */
    static boolean bitmapHas(byte[] bitmaps, int type) {
        int window = type >> 8;
        int bit = type & 0xff;
        int pos = 0;
        while (pos + 2 <= bitmaps.length) {
            int w = bitmaps[pos] & 0xff;
            int len = bitmaps[pos + 1] & 0xff;
            if (w == window) {
                int index = bit / 8;
                return index < len && pos + 2 + index < bitmaps.length
                        && (bitmaps[pos + 2 + index] & (0x80 >> (bit % 8))) != 0;
            }
            pos += 2 + len;
        }
        return false;
    }

    @Override
    public String toString() {
        return name + " " + ttl + " type" + type + " (" + rdata.length + " bytes)";
    }
}
