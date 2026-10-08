package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/** Fixtures, a replaying transport and a tiny zone signer for DNSSEC tests. */
final class DnsTestSupport {

    private DnsTestSupport() {}

    static String key(DnsName name, int type) {
        return name.toString().toLowerCase(Locale.ROOT) + "/" + type;
    }

    /** Answers queries from {@code responses}, keyed by {@link #key}, patching the message ID. */
    static DnsTransport replay(Map<String, byte[]> responses) {
        return query -> {
            DnsMessage q = DnsMessage.parse(query);
            byte[] response = responses.get(key(q.questionName, q.questionType));
            if (response == null) {
                throw new IOException("no fixture for " + key(q.questionName, q.questionType));
            }
            byte[] copy = response.clone();
            copy[0] = query[0];
            copy[1] = query[1];
            return copy;
        };
    }

    /** Passes queries to {@code delegate} and stores every response in {@code sink}. */
    static DnsTransport recording(DnsTransport delegate, Map<String, byte[]> sink) {
        return query -> {
            byte[] response = delegate.exchange(query);
            DnsMessage q = DnsMessage.parse(query);
            sink.put(key(q.questionName, q.questionType), response);
            return response;
        };
    }

    record Fixtures(long recordedAtEpochSecond, Map<String, byte[]> responses) {}

    static void save(Path file, long recordedAt, Map<String, byte[]> responses) throws IOException {
        StringBuilder sb = new StringBuilder("# DNS responses recorded via DNS over HTTPS; replayed by DnssecRecordedTest\n");
        sb.append("recorded-at ").append(recordedAt).append('\n');
        new TreeMap<>(responses).forEach((k, v) ->
                sb.append(k).append(' ').append(Base64.getEncoder().encodeToString(v)).append('\n'));
        Files.writeString(file, sb.toString(), StandardCharsets.US_ASCII);
    }

    static Fixtures load(Path file) throws IOException {
        long recordedAt = 0;
        Map<String, byte[]> responses = new ConcurrentHashMap<>();
        for (String line : Files.readAllLines(file, StandardCharsets.US_ASCII)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split(" ");
            if (parts[0].equals("recorded-at")) {
                recordedAt = Long.parseLong(parts[1]);
            } else {
                responses.put(parts[0], Base64.getDecoder().decode(parts[1]));
            }
        }
        return new Fixtures(recordedAt, responses);
    }

    // --- building messages ------------------------------------------------------------------

    static byte[] response(DnsName qname, int qtype, int rcode, List<DnsRecord> answer, List<DnsRecord> authority) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {0, 0, (byte) 0x81, (byte) (0x80 | rcode), 0, 1,
            (byte) (answer.size() >> 8), (byte) answer.size(),
            (byte) (authority.size() >> 8), (byte) authority.size(), 0, 0});
        out.writeBytes(qname.toWire());
        out.writeBytes(new byte[] {(byte) (qtype >> 8), (byte) qtype, 0, 1});
        for (DnsRecord r : answer) writeRecord(out, r);
        for (DnsRecord r : authority) writeRecord(out, r);
        return out.toByteArray();
    }

    private static void writeRecord(ByteArrayOutputStream out, DnsRecord r) {
        out.writeBytes(r.name().toWire());
        out.writeBytes(new byte[] {(byte) (r.type() >> 8), (byte) r.type(), 0, 1,
            (byte) (r.ttl() >> 24), (byte) (r.ttl() >> 16), (byte) (r.ttl() >> 8), (byte) r.ttl(),
            (byte) (r.rdata().length >> 8), (byte) r.rdata().length});
        out.writeBytes(r.rdata());
    }

    static DnsRecord a(String name, int... octets) {
        byte[] rdata = new byte[4];
        for (int i = 0; i < 4; i++) rdata[i] = (byte) octets[i];
        return new DnsRecord(DnsName.parse(name), DnsRecord.A, 1, 300, rdata);
    }

    static DnsRecord nsec(String owner, String next, int... types) {
        return new DnsRecord(DnsName.parse(owner), DnsRecord.NSEC, 1, 300,
                DnsRecord.concat(DnsName.parse(next).toWire(), bitmap(types)));
    }

    static byte[] bitmap(int... types) {
        TreeSet<Integer> sorted = new TreeSet<>();
        for (int t : types) sorted.add(t);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int window = -1;
        byte[] bits = null;
        for (int t : sorted) {
            if (t >> 8 != window) {
                flushWindow(out, window, bits);
                window = t >> 8;
                bits = new byte[32];
            }
            bits[(t & 0xff) / 8] |= (byte) (0x80 >> (t % 8));
        }
        flushWindow(out, window, bits);
        return out.toByteArray();
    }

    private static void flushWindow(ByteArrayOutputStream out, int window, byte[] bits) {
        if (bits == null) return;
        int len = 32;
        while (len > 0 && bits[len - 1] == 0) len--;
        out.write(window);
        out.write(len);
        out.write(bits, 0, len);
    }

    // --- signing ----------------------------------------------------------------------------

    /** A test zone with one ECDSA P-256 key (flags 257) used as both KSK and ZSK. */
    record Zone(DnsName name, KeyPair keys, DnsRecord dnskey) {
        int keyTag() {
            return DnsRecord.keyTag(dnskey.rdata());
        }

        /** The DS record for this zone, as published in the parent. */
        DnsRecord ds() {
            try {
                byte[] digest = DnssecCrypto.dsDigest(2, name, dnskey.rdata());
                byte[] rdata = DnsRecord.concat(new byte[] {(byte) (keyTag() >> 8), (byte) keyTag(), 13, 2}, digest);
                return new DnsRecord(name, DnsRecord.DS, 1, 300, rdata);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        String trustAnchor() {
            DnsRecord.Ds ds = ds().ds();
            return name + " " + ds.keyTag() + " 13 2 " + HexFormat.of().formatHex(ds.digest());
        }

        /** Signs {@code records} (one RRset) with this zone's key. */
        DnsRecord sign(List<DnsRecord> records, long inception, long expiration) {
            return sign(records, inception, expiration, -1);
        }

        DnsRecord sign(List<DnsRecord> records, long inception, long expiration, int labelsOverride) {
            DnsRecord first = records.get(0);
            DnsName owner = first.name();
            int labels = labelsOverride >= 0 ? labelsOverride : owner.labelCount() - (owner.isWildcard() ? 1 : 0);
            ByteArrayOutputStream prefix = new ByteArrayOutputStream();
            prefix.writeBytes(new byte[] {(byte) (first.type() >> 8), (byte) first.type(), 13, (byte) labels});
            writeInt(prefix, first.ttl());
            writeInt(prefix, expiration);
            writeInt(prefix, inception);
            prefix.write(keyTag() >> 8);
            prefix.write(keyTag());
            prefix.writeBytes(name.toCanonicalWire());
            byte[] data = DnssecValidator.signedData(
                    new DnssecValidator.RRset(owner, first.type(), records, List.of()), prefix.toByteArray(),
                    labels, first.ttl());
            try {
                Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
                signer.initSign(keys.getPrivate());
                signer.update(data);
                return new DnsRecord(owner, DnsRecord.RRSIG, 1, first.ttl(),
                        DnsRecord.concat(prefix.toByteArray(), signer.sign()));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    static Zone zone(String name) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keys = gen.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) keys.getPublic();
            byte[] point = DnsRecord.concat(fixed(pub.getW().getAffineX()), fixed(pub.getW().getAffineY()));
            byte[] rdata = DnsRecord.concat(new byte[] {1, 1, 3, 13}, point);
            return new Zone(DnsName.parse(name), keys, new DnsRecord(DnsName.parse(name), DnsRecord.DNSKEY, 1, 300, rdata));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] fixed(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(32, b.length);
        System.arraycopy(b, b.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static void writeInt(ByteArrayOutputStream out, long v) {
        out.write((int) (v >> 24));
        out.write((int) (v >> 16));
        out.write((int) (v >> 8));
        out.write((int) v);
    }

    static List<DnsRecord> with(List<DnsRecord> records, DnsRecord... more) {
        List<DnsRecord> all = new ArrayList<>(records);
        all.addAll(List.of(more));
        return all;
    }
}
