package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** A parsed DNS message (RFC 1035 section 4), and query construction. */
final class DnsMessage {

    static final int RCODE_NOERROR = 0;
    static final int RCODE_SERVFAIL = 2;
    static final int RCODE_NXDOMAIN = 3;

    final int id;
    final int flags;
    final DnsName questionName;
    final int questionType;
    final List<DnsRecord> answer;
    final List<DnsRecord> authority;
    final List<DnsRecord> additional;

    private DnsMessage(int id, int flags, DnsName questionName, int questionType,
            List<DnsRecord> answer, List<DnsRecord> authority, List<DnsRecord> additional) {
        this.id = id;
        this.flags = flags;
        this.questionName = questionName;
        this.questionType = questionType;
        this.answer = answer;
        this.authority = authority;
        this.additional = additional;
    }

    int rcode() {
        return flags & 0xf;
    }

    boolean isTruncated() {
        return (flags & 0x0200) != 0;
    }

    boolean isResponse() {
        return (flags & 0x8000) != 0;
    }

    /**
     * A recursive query with DNSSEC OK (EDNS0 DO) and Checking Disabled set, so the upstream
     * resolver returns signatures and passes through data it could not validate itself.
     */
    static byte[] query(int id, DnsName name, int type) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        ByteBuffer header = ByteBuffer.allocate(12);
        header.putShort((short) id);
        header.putShort((short) 0x0110); // RD | CD
        header.putShort((short) 1); // QDCOUNT
        header.putShort((short) 0);
        header.putShort((short) 0);
        header.putShort((short) 1); // ARCOUNT: OPT
        out.writeBytes(header.array());
        out.writeBytes(name.toWire());
        out.write(type >> 8);
        out.write(type);
        out.write(0);
        out.write(DnsRecord.CLASS_IN);
        // OPT pseudo-RR: root name, type 41, UDP size 1232, extended RCODE/version 0, DO bit.
        out.writeBytes(new byte[] {0, 0, 41, 0x04, (byte) 0xd0, 0, 0, (byte) 0x80, 0, 0, 0});
        return out.toByteArray();
    }

    static DnsMessage parse(byte[] data) {
        try {
            ByteBuffer b = ByteBuffer.wrap(data);
            int id = b.getShort() & 0xffff;
            int flags = b.getShort() & 0xffff;
            int qd = b.getShort() & 0xffff;
            int an = b.getShort() & 0xffff;
            int ns = b.getShort() & 0xffff;
            int ar = b.getShort() & 0xffff;
            DnsName qname = null;
            int qtype = 0;
            int[] pos = {12};
            for (int i = 0; i < qd; i++) {
                DnsName n = readName(data, pos);
                int t = u16(data, pos[0]);
                pos[0] += 4;
                if (i == 0) {
                    qname = n;
                    qtype = t;
                }
            }
            List<DnsRecord> answer = readRecords(data, pos, an);
            List<DnsRecord> authority = readRecords(data, pos, ns);
            List<DnsRecord> additional = readRecords(data, pos, ar);
            return new DnsMessage(id, flags, qname, qtype, answer, authority, additional);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("malformed DNS message", e);
        }
    }

    private static List<DnsRecord> readRecords(byte[] data, int[] pos, int count) {
        List<DnsRecord> records = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            DnsName name = readName(data, pos);
            int type = u16(data, pos[0]);
            int cls = u16(data, pos[0] + 2);
            long ttl = ((long) u16(data, pos[0] + 4) << 16) | u16(data, pos[0] + 6);
            int rdlen = u16(data, pos[0] + 8);
            int start = pos[0] + 10;
            int end = start + rdlen;
            if (end > data.length) throw new IllegalArgumentException("truncated RDATA");
            byte[] rdata = switch (type) {
                // Types whose RDATA may contain compressed names: expand them.
                case DnsRecord.NS, DnsRecord.CNAME, DnsRecord.PTR, DnsRecord.DNAME ->
                        readName(data, new int[] {start}).toWire();
                case DnsRecord.MX -> DnsRecord.concat(Arrays.copyOfRange(data, start, start + 2),
                        readName(data, new int[] {start + 2}).toWire());
                case DnsRecord.SOA -> {
                    int[] p = {start};
                    byte[] mname = readName(data, p).toWire();
                    byte[] rname = readName(data, p).toWire();
                    yield DnsRecord.concat(mname, rname, Arrays.copyOfRange(data, p[0], end));
                }
                default -> Arrays.copyOfRange(data, start, end);
            };
            if (ttl > 0x7fffffffL) ttl = 0;
            records.add(new DnsRecord(name, type, cls, ttl, rdata));
            pos[0] = end;
        }
        return records;
    }

    /** Reads a possibly compressed name at {@code pos[0]}, advancing it past the name. */
    static DnsName readName(byte[] data, int[] pos) {
        List<byte[]> labels = new ArrayList<>();
        int p = pos[0];
        int end = -1;
        int jumps = 0;
        while (true) {
            int len = data[p] & 0xff;
            if ((len & 0xc0) == 0xc0) {
                if (++jumps > 64) throw new IllegalArgumentException("compression loop");
                int target = ((len & 0x3f) << 8) | (data[p + 1] & 0xff);
                if (end < 0) end = p + 2;
                p = target;
                continue;
            }
            if (len > 63) throw new IllegalArgumentException("bad label type");
            if (len == 0) {
                if (end < 0) end = p + 1;
                break;
            }
            labels.add(Arrays.copyOfRange(data, p + 1, p + 1 + len));
            p += 1 + len;
        }
        pos[0] = end;
        return DnsName.of(labels.toArray(byte[][]::new));
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }
}
