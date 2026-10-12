package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * A DNS message (RFC 1035 section 4.1): its header, questions and resource records, decoded from
 * the wire format and encoded back. Records keep their RDATA as bytes, with embedded names expanded,
 * and {@link ResourceRecord#data()} reads the RDATA of the common types (A, AAAA, NS, CNAME, PTR,
 * DNAME, MX, SRV, TXT, SOA) as a typed {@link Rdata}.
 *
 * <p>Messages are immutable: the {@code with} methods return changed copies. {@link #encode()}
 * compresses the questions' and records' owner names; names inside RDATA are written as they are.
 *
 * <pre>{@code
 * DnsMessage answer = DnsMessage.decode(bytes);
 * List<DnsMessage.ResourceRecord> blocked = answer.answers().stream()
 *         .map(r -> r.type() == DnsMessage.A && r.name().equals("ads.example")
 *                 ? r.withData(DnsMessage.Address.of("0.0.0.0")) : r)
 *         .toList();
 * byte[] rewritten = answer.withAnswers(blocked).encode();
 * }</pre>
 *
 * <p>Names are given and shown in presentation format without the final dot ({@code
 * www.example.com}, {@code .} for the root), with {@code \.}, {@code \\} and {@code \DDD} escapes
 * for bytes that need them.
 */
public final class DnsMessage {

    /** Type A: an IPv4 address. */
    public static final int A = 1;
    /** Type NS: a name server. */
    public static final int NS = 2;
    /** Type CNAME: the canonical name of an alias. */
    public static final int CNAME = 5;
    /** Type SOA: the start of a zone of authority. */
    public static final int SOA = 6;
    /** Type PTR: a domain name pointer. */
    public static final int PTR = 12;
    /** Type MX: a mail exchange. */
    public static final int MX = 15;
    /** Type TXT: text strings. */
    public static final int TXT = 16;
    /** Type AAAA: an IPv6 address. */
    public static final int AAAA = 28;
    /** Type SRV: a service location. */
    public static final int SRV = 33;
    /** Type HTTPS: HTTPS service binding (RFC 9460). */
    public static final int HTTPS = 65;
    /** Class IN: the Internet. */
    public static final int IN = 1;

    static final int RCODE_NOERROR = 0;
    static final int RCODE_SERVFAIL = 2;
    static final int RCODE_NXDOMAIN = 3;

    private static final int QR = 0x8000;
    private static final int AA = 0x0400;
    private static final int TC = 0x0200;
    private static final int RD = 0x0100;
    private static final int RA = 0x0080;

    private static final Map<Integer, String> TYPE_NAMES = Map.ofEntries(
            Map.entry(A, "A"), Map.entry(NS, "NS"), Map.entry(CNAME, "CNAME"), Map.entry(SOA, "SOA"),
            Map.entry(PTR, "PTR"), Map.entry(MX, "MX"), Map.entry(TXT, "TXT"), Map.entry(AAAA, "AAAA"),
            Map.entry(SRV, "SRV"), Map.entry(DnsRecord.DNAME, "DNAME"), Map.entry(DnsRecord.OPT, "OPT"),
            Map.entry(DnsRecord.DS, "DS"), Map.entry(DnsRecord.RRSIG, "RRSIG"), Map.entry(DnsRecord.NSEC, "NSEC"),
            Map.entry(DnsRecord.DNSKEY, "DNSKEY"), Map.entry(DnsRecord.NSEC3, "NSEC3"), Map.entry(64, "SVCB"),
            Map.entry(HTTPS, "HTTPS"), Map.entry(255, "ANY"), Map.entry(257, "CAA"));
    private static final Map<String, Integer> TYPE_NUMBERS = new HashMap<>();
    private static final String[] RCODES = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
    private static final String[] OPCODES = {"QUERY", "IQUERY", "STATUS", null, "NOTIFY", "UPDATE"};

    static {
        TYPE_NAMES.forEach((number, name) -> TYPE_NUMBERS.put(name, number));
    }

    final int id;
    final int flags;
    /** The first question's name and type, as the validator reads them; null and 0 without one. */
    final DnsName questionName;
    final int questionType;
    final List<Question> questions;
    final List<DnsRecord> answer;
    final List<DnsRecord> authority;
    final List<DnsRecord> additional;

    private DnsMessage(int id, int flags, List<Question> questions,
            List<DnsRecord> answer, List<DnsRecord> authority, List<DnsRecord> additional) {
        this.id = id & 0xffff;
        this.flags = flags & 0xffff;
        this.questions = List.copyOf(questions);
        this.questionName = questions.isEmpty() ? null : DnsName.parse(questions.getFirst().name());
        this.questionType = questions.isEmpty() ? 0 : questions.getFirst().type();
        this.answer = List.copyOf(answer);
        this.authority = List.copyOf(authority);
        this.additional = List.copyOf(additional);
    }

    // ---------------------------------------------------------------------------------------
    // Public view
    // ---------------------------------------------------------------------------------------

    /**
     * A question: the name, type and class asked about.
     *
     * @param name the name, in presentation format
     * @param type the type ({@link #A}, ...)
     * @param dnsClass the class, {@link #IN} for nearly all
     */
    public record Question(String name, int type, int dnsClass) {

        /**
         * Checks the name.
         *
         * @param name the name, in presentation format
         * @param type the type ({@link #A}, ...)
         * @param dnsClass the class, {@link #IN} for nearly all
         * @throws IllegalArgumentException if the name is not a valid domain name
         */
        public Question {
            name = presentation(DnsName.parse(Objects.requireNonNull(name, "name")));
            type &= 0xffff;
            dnsClass &= 0xffff;
        }

        /**
         * A question of class IN.
         *
         * @param name the name, in presentation format
         * @param type the type
         */
        public Question(String name, int type) {
            this(name, type, IN);
        }

        /** {@return the type's mnemonic, such as {@code A}, or {@code TYPE<n>}} */
        public String typeName() {
            return DnsMessage.typeName(type);
        }

        @Override
        public String toString() {
            return name + " " + className(dnsClass) + " " + typeName();
        }
    }

    /**
     * A resource record. {@code rdata} holds its RDATA with embedded names expanded; {@link #data()}
     * reads it as a typed value.
     *
     * @param name the owner name, in presentation format
     * @param type the type ({@link #A}, ...)
     * @param dnsClass the class ({@link #IN}; an OPT record's holds the UDP payload size)
     * @param ttl the time to live in seconds, an unsigned 32-bit value (an OPT record's holds the
     *     extended RCODE and flags)
     * @param rdata the RDATA (not copied)
     */
    public record ResourceRecord(String name, int type, int dnsClass, long ttl, byte[] rdata) {

        /**
         * Checks the name and the RDATA's length.
         *
         * @param name the owner name, in presentation format
         * @param type the type
         * @param dnsClass the class
         * @param ttl the time to live in seconds
         * @param rdata the RDATA
         * @throws IllegalArgumentException if the name is not a valid domain name, or the RDATA is
         *     longer than 65535 bytes
         */
        public ResourceRecord {
            name = presentation(DnsName.parse(Objects.requireNonNull(name, "name")));
            type &= 0xffff;
            dnsClass &= 0xffff;
            ttl &= 0xffffffffL;
            Objects.requireNonNull(rdata, "rdata");
            if (rdata.length > 0xffff) throw new IllegalArgumentException("RDATA longer than 65535 bytes");
        }

        /**
         * A record of class IN with typed data.
         *
         * @param name the owner name
         * @param type the type, which must suit {@code data} ({@link Address} for A and AAAA, {@link
         *     Name} for NS, CNAME, PTR and DNAME, ...)
         * @param ttl the time to live in seconds
         * @param data the data
         * @return the record
         * @throws IllegalArgumentException if {@code data} does not suit {@code type}
         */
        public static ResourceRecord of(String name, int type, long ttl, Rdata data) {
            return new ResourceRecord(name, type, IN, ttl, data.encode(type));
        }

        /**
         * The RDATA read as its type's {@link Rdata}: an {@link Address} for A and AAAA, a {@link
         * Name} for NS, CNAME, PTR and DNAME, {@link Mx}, {@link Srv}, {@link Txt} and {@link Soa};
         * {@link Opaque} for other types, and for RDATA that does not parse.
         *
         * @return the data
         */
        public Rdata data() {
            try {
                return Rdata.decode(type, rdata);
            } catch (RuntimeException e) {
                return new Opaque(rdata);
            }
        }

        /** {@return the type's mnemonic, such as {@code A}, or {@code TYPE<n>}} */
        public String typeName() {
            return DnsMessage.typeName(type);
        }

        /**
         * This record with other data, encoded for its type.
         *
         * @param data the data
         * @return the copy
         * @throws IllegalArgumentException if {@code data} does not suit the type
         */
        public ResourceRecord withData(Rdata data) {
            return new ResourceRecord(name, type, dnsClass, ttl, data.encode(type));
        }

        /**
         * This record with another time to live.
         *
         * @param ttl the time to live in seconds
         * @return the copy
         */
        public ResourceRecord withTtl(long ttl) {
            return new ResourceRecord(name, type, dnsClass, ttl, rdata);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof ResourceRecord r && r.type == type && r.dnsClass == dnsClass && r.ttl == ttl
                    && r.name.equalsIgnoreCase(name) && Arrays.equals(r.rdata, rdata);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name.toLowerCase(Locale.ROOT), type, dnsClass, ttl, Arrays.hashCode(rdata));
        }

        @Override
        public String toString() {
            if (type == DnsRecord.OPT) {
                return "; EDNS: version " + ((ttl >> 16) & 0xff) + ", udp " + dnsClass
                        + ((ttl & 0x8000) != 0 ? ", do" : "");
            }
            return name + " " + ttl + " " + className(dnsClass) + " " + typeName() + " " + data().text();
        }

        DnsRecord internal() {
            return new DnsRecord(DnsName.parse(name), type, dnsClass, ttl, rdata);
        }

        static ResourceRecord of(DnsRecord r) {
            return new ResourceRecord(presentation(r.name()), r.type(), r.dnsClass(), r.ttl(), r.rdata());
        }
    }

    /**
     * The RDATA of a record, read as its type. {@link ResourceRecord#data()} returns one; {@link
     * ResourceRecord#of} and {@link ResourceRecord#withData} encode one.
     */
    public sealed interface Rdata permits Address, Name, Mx, Srv, Txt, Soa, Opaque {

        /** {@return the data in presentation format, as a zone file shows it} */
        String text();

        /**
         * The RDATA for a record of {@code type}.
         *
         * @param type the record's type
         * @return the RDATA bytes
         * @throws IllegalArgumentException if this data does not suit {@code type}
         */
        byte[] encode(int type);

        private static Rdata decode(int type, byte[] rdata) {
            return switch (type) {
                case A, AAAA -> {
                    if (rdata.length != (type == A ? 4 : 16)) throw new IllegalArgumentException("bad address length");
                    try {
                        yield new Address(InetAddress.getByAddress(rdata));
                    } catch (UnknownHostException e) {
                        throw new IllegalArgumentException(e);
                    }
                }
                case NS, CNAME, PTR, DnsRecord.DNAME -> new Name(presentation(whole(rdata, 0)));
                case MX -> new Mx(u16(rdata, 0), presentation(whole(rdata, 2)));
                case SRV -> new Srv(u16(rdata, 0), u16(rdata, 2), u16(rdata, 4), presentation(whole(rdata, 6)));
                case TXT -> {
                    List<String> strings = new ArrayList<>();
                    int p = 0;
                    while (p < rdata.length) {
                        int len = rdata[p] & 0xff;
                        if (p + 1 + len > rdata.length) throw new IllegalArgumentException("truncated TXT string");
                        strings.add(new String(rdata, p + 1, len, StandardCharsets.UTF_8));
                        p += 1 + len;
                    }
                    yield new Txt(strings);
                }
                case SOA -> {
                    DnsRecord.NameAt mname = DnsRecord.readName(rdata, 0);
                    DnsRecord.NameAt rname = DnsRecord.readName(rdata, mname.end());
                    if (rname.end() + 20 != rdata.length) throw new IllegalArgumentException("bad SOA length");
                    ByteBuffer b = ByteBuffer.wrap(rdata, rname.end(), 20);
                    yield new Soa(presentation(mname.name()), presentation(rname.name()), b.getInt() & 0xffffffffL,
                            b.getInt() & 0xffffffffL, b.getInt() & 0xffffffffL, b.getInt() & 0xffffffffL,
                            b.getInt() & 0xffffffffL);
                }
                default -> new Opaque(rdata);
            };
        }

        /** A name that fills the RDATA from {@code offset} to its end. */
        private static DnsName whole(byte[] rdata, int offset) {
            DnsRecord.NameAt n = DnsRecord.readName(rdata, offset);
            if (n.end() != rdata.length) throw new IllegalArgumentException("bytes after the name");
            return n.name();
        }
    }

    /**
     * An address, the data of A (IPv4) and AAAA (IPv6) records.
     *
     * @param address the address
     */
    public record Address(InetAddress address) implements Rdata {

        /**
         * Checks the address.
         *
         * @param address the address
         */
        public Address {
            Objects.requireNonNull(address, "address");
        }

        /**
         * An address from its literal, never looked up.
         *
         * @param literal an IPv4 address ({@code 192.0.2.1}) or an IPv6 one ({@code 2001:db8::1})
         * @return the address
         * @throws IllegalArgumentException if {@code literal} is not an IP address literal
         */
        public static Address of(String literal) {
            return new Address(literal(literal));
        }

        /** {@return the address as RFC 5952 writes it: {@code 192.0.2.1}, {@code 2001:db8::1}} */
        @Override
        public String text() {
            if (!(address instanceof Inet6Address)) return address.getHostAddress();
            byte[] b = address.getAddress();
            int[] groups = new int[8];
            for (int i = 0; i < 8; i++) groups[i] = ((b[2 * i] & 0xff) << 8) | (b[2 * i + 1] & 0xff);
            // The longest run of two or more zero groups, the first of equal ones, becomes "::".
            int bestStart = -1;
            int bestLength = 1;
            for (int i = 0; i < 8; ) {
                int j = i;
                while (j < 8 && groups[j] == 0) j++;
                if (j - i > bestLength) {
                    bestStart = i;
                    bestLength = j - i;
                }
                i = j == i ? i + 1 : j;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                if (i == bestStart) {
                    sb.append("::");
                    i += bestLength - 1;
                    continue;
                }
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') sb.append(':');
                sb.append(Integer.toHexString(groups[i]));
            }
            return sb.toString();
        }

        @Override
        public byte[] encode(int type) {
            if (type == A && address instanceof Inet4Address || type == AAAA && address instanceof Inet6Address) {
                return address.getAddress();
            }
            throw new IllegalArgumentException("an " + (address instanceof Inet4Address ? "IPv4" : "IPv6")
                    + " address is not the data of a " + typeName(type) + " record");
        }
    }

    /**
     * A domain name, the data of NS, CNAME, PTR and DNAME records.
     *
     * @param name the name, in presentation format
     */
    public record Name(String name) implements Rdata {

        /**
         * Checks the name.
         *
         * @param name the name, in presentation format
         * @throws IllegalArgumentException if it is not a valid domain name
         */
        public Name {
            name = presentation(DnsName.parse(Objects.requireNonNull(name, "name")));
        }

        @Override
        public String text() {
            return name + (name.equals(".") ? "" : ".");
        }

        @Override
        public byte[] encode(int type) {
            if (type != NS && type != CNAME && type != PTR && type != DnsRecord.DNAME) {
                throw new IllegalArgumentException("a name is not the data of a " + typeName(type) + " record");
            }
            return DnsName.parse(name).toWire();
        }
    }

    /**
     * The data of an MX record.
     *
     * @param preference the preference, lower first
     * @param exchange the mail exchange's name
     */
    public record Mx(int preference, String exchange) implements Rdata {

        /**
         * Checks the name.
         *
         * @param preference the preference
         * @param exchange the mail exchange's name
         */
        public Mx {
            exchange = presentation(DnsName.parse(Objects.requireNonNull(exchange, "exchange")));
        }

        @Override
        public String text() {
            return preference + " " + exchange + ".";
        }

        @Override
        public byte[] encode(int type) {
            check(type, MX, "MX");
            return DnsRecord.concat(new byte[] {(byte) (preference >> 8), (byte) preference},
                    DnsName.parse(exchange).toWire());
        }
    }

    /**
     * The data of an SRV record (RFC 2782).
     *
     * @param priority the priority, lower first
     * @param weight the weight among records of the same priority
     * @param port the port
     * @param target the target host's name
     */
    public record Srv(int priority, int weight, int port, String target) implements Rdata {

        /**
         * Checks the name.
         *
         * @param priority the priority
         * @param weight the weight
         * @param port the port
         * @param target the target host's name
         */
        public Srv {
            target = presentation(DnsName.parse(Objects.requireNonNull(target, "target")));
        }

        @Override
        public String text() {
            return priority + " " + weight + " " + port + " " + target + ".";
        }

        @Override
        public byte[] encode(int type) {
            check(type, SRV, "SRV");
            return DnsRecord.concat(new byte[] {(byte) (priority >> 8), (byte) priority, (byte) (weight >> 8),
                (byte) weight, (byte) (port >> 8), (byte) port}, DnsName.parse(target).toWire());
        }
    }

    /**
     * The data of a TXT record: its character strings, read as UTF-8 (use {@link
     * ResourceRecord#rdata()} for strings of other bytes).
     *
     * @param strings the strings, each at most 255 bytes in UTF-8
     */
    public record Txt(List<String> strings) implements Rdata {

        /**
         * Copies the list.
         *
         * @param strings the strings
         */
        public Txt {
            strings = List.copyOf(strings);
        }

        @Override
        public String text() {
            List<String> quoted = new ArrayList<>();
            for (String s : strings) quoted.add('"' + s.replace("\\", "\\\\").replace("\"", "\\\"") + '"');
            return String.join(" ", quoted);
        }

        @Override
        public byte[] encode(int type) {
            check(type, TXT, "TXT");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (String s : strings) {
                byte[] b = s.getBytes(StandardCharsets.UTF_8);
                if (b.length > 255) throw new IllegalArgumentException("a TXT string longer than 255 bytes");
                out.write(b.length);
                out.writeBytes(b);
            }
            return out.toByteArray();
        }
    }

    /**
     * The data of an SOA record.
     *
     * @param mname the zone's primary name server
     * @param rname the mailbox of the person responsible, as a name
     * @param serial the zone's serial number
     * @param refresh the secondaries' refresh interval, in seconds
     * @param retry the secondaries' retry interval, in seconds
     * @param expire when secondaries stop answering without a refresh, in seconds
     * @param minimum the TTL of negative answers, in seconds (RFC 2308)
     */
    public record Soa(String mname, String rname, long serial, long refresh, long retry, long expire, long minimum)
            implements Rdata {

        /**
         * Checks the names.
         *
         * @param mname the zone's primary name server
         * @param rname the mailbox of the person responsible
         * @param serial the serial number
         * @param refresh the refresh interval
         * @param retry the retry interval
         * @param expire the expiry
         * @param minimum the negative TTL
         */
        public Soa {
            mname = presentation(DnsName.parse(Objects.requireNonNull(mname, "mname")));
            rname = presentation(DnsName.parse(Objects.requireNonNull(rname, "rname")));
        }

        @Override
        public String text() {
            return mname + ". " + rname + ". " + serial + " " + refresh + " " + retry + " " + expire + " " + minimum;
        }

        @Override
        public byte[] encode(int type) {
            check(type, SOA, "SOA");
            ByteBuffer b = ByteBuffer.allocate(20);
            b.putInt((int) serial).putInt((int) refresh).putInt((int) retry).putInt((int) expire).putInt((int) minimum);
            return DnsRecord.concat(DnsName.parse(mname).toWire(), DnsName.parse(rname).toWire(), b.array());
        }
    }

    /**
     * RDATA of a type without a typed view, kept as bytes.
     *
     * @param bytes the RDATA (not copied)
     */
    public record Opaque(byte[] bytes) implements Rdata {

        /**
         * Checks the bytes.
         *
         * @param bytes the RDATA
         */
        public Opaque {
            Objects.requireNonNull(bytes, "bytes");
        }

        @Override
        public String text() {
            // RFC 3597's generic form.
            return "\\# " + bytes.length + (bytes.length == 0 ? "" : " " + java.util.HexFormat.of().formatHex(bytes));
        }

        @Override
        public byte[] encode(int type) {
            return bytes;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Opaque other && Arrays.equals(other.bytes, bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return "Opaque[" + text() + "]";
        }
    }

    private static void check(int type, int expected, String what) {
        if (type != expected) {
            throw new IllegalArgumentException(what + " data is not the data of a " + typeName(type) + " record");
        }
    }

    /**
     * Decodes a message from its wire format, following compression pointers.
     *
     * @param data the message
     * @return the message
     * @throws IllegalArgumentException if the bytes are not a well-formed DNS message
     */
    public static DnsMessage decode(byte[] data) {
        return parse(data);
    }

    /**
     * A query with recursion desired, for one name and type of class IN, without EDNS.
     *
     * @param id the message ID
     * @param name the name
     * @param type the type ({@link #A}, ...)
     * @return the query
     * @throws IllegalArgumentException if the name is not a valid domain name
     */
    public static DnsMessage query(int id, String name, int type) {
        return new DnsMessage(id, RD, List.of(new Question(name, type)), List.of(), List.of(), List.of());
    }

    /**
     * A message made of its parts.
     *
     * @param id the message ID, 16 bits
     * @param flags the header's flags, 16 bits (see {@link #flags()})
     * @param questions the question section
     * @param answers the answer section
     * @param authorities the authority section
     * @param additionals the additional section
     * @return the message
     */
    public static DnsMessage of(int id, int flags, List<Question> questions, List<ResourceRecord> answers,
            List<ResourceRecord> authorities, List<ResourceRecord> additionals) {
        return new DnsMessage(id, flags, questions, internal(answers), internal(authorities), internal(additionals));
    }

    /**
     * An answer to this query: a response with the same ID, opcode, questions and recursion desired
     * bit, recursion available, the RCODE NOERROR, and {@code answers}.
     *
     * @param answers the answer section
     * @return the response
     */
    public DnsMessage reply(List<ResourceRecord> answers) {
        int f = QR | RA | (flags & (0x7800 | RD));
        return new DnsMessage(id, f, questions, internal(answers), List.of(), List.of());
    }

    /**
     * Encodes the message, compressing the questions' and records' owner names.
     *
     * @return the wire format
     * @throws IllegalArgumentException if a section has more than 65535 entries
     */
    public byte[] encode() {
        if (questions.size() > 0xffff || answer.size() > 0xffff || authority.size() > 0xffff
                || additional.size() > 0xffff) {
            throw new IllegalArgumentException("a section with more than 65535 entries");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        Map<DnsName, Integer> names = new HashMap<>();
        writeU16(out, id);
        writeU16(out, flags);
        writeU16(out, questions.size());
        writeU16(out, answer.size());
        writeU16(out, authority.size());
        writeU16(out, additional.size());
        for (Question q : questions) {
            writeName(out, DnsName.parse(q.name()), names);
            writeU16(out, q.type());
            writeU16(out, q.dnsClass());
        }
        for (List<DnsRecord> section : List.of(answer, authority, additional)) {
            for (DnsRecord r : section) {
                writeName(out, r.name(), names);
                writeU16(out, r.type());
                writeU16(out, r.dnsClass());
                writeU16(out, (int) (r.ttl() >> 16));
                writeU16(out, (int) r.ttl());
                writeU16(out, r.rdata().length);
                out.writeBytes(r.rdata());
            }
        }
        return out.toByteArray();
    }

    /** Writes a name, pointing to an earlier occurrence of its longest known suffix (RFC 1035 4.1.4). */
    private static void writeName(ByteArrayOutputStream out, DnsName name, Map<DnsName, Integer> names) {
        int n = name.labelCount();
        for (int i = 0; i < n; i++) {
            DnsName suffix = name.suffix(n - i);
            Integer at = names.get(suffix);
            if (at != null) {
                writeU16(out, 0xc000 | at);
                return;
            }
            if (out.size() < 0x4000) names.put(suffix, out.size());
            byte[] label = name.label(i);
            out.write(label.length);
            out.writeBytes(label);
        }
        out.write(0);
    }

    private static void writeU16(ByteArrayOutputStream out, int v) {
        out.write(v >> 8);
        out.write(v);
    }

    /** {@return the message ID} */
    public int id() {
        return id;
    }

    /** {@return the header's flags: QR, opcode, AA, TC, RD, RA, Z, AD, CD and RCODE, as 16 bits} */
    public int flags() {
        return flags;
    }

    /** {@return the RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, ...} */
    public int rcode() {
        return flags & 0xf;
    }

    /** {@return the opcode: 0 for a standard query} */
    public int opcode() {
        return (flags >> 11) & 0xf;
    }

    /** {@return whether the message is a response (QR)} */
    public boolean isResponse() {
        return (flags & QR) != 0;
    }

    /** {@return whether the answer is authoritative (AA)} */
    public boolean isAuthoritative() {
        return (flags & AA) != 0;
    }

    /** {@return whether the message was truncated (TC)} */
    public boolean isTruncated() {
        return (flags & TC) != 0;
    }

    /** {@return whether recursion is desired (RD)} */
    public boolean isRecursionDesired() {
        return (flags & RD) != 0;
    }

    /** {@return whether recursion is available (RA)} */
    public boolean isRecursionAvailable() {
        return (flags & RA) != 0;
    }

    /** {@return the question section} */
    public List<Question> questions() {
        return questions;
    }

    /** {@return the answer section} */
    public List<ResourceRecord> answers() {
        return external(answer);
    }

    /** {@return the authority section} */
    public List<ResourceRecord> authorities() {
        return external(authority);
    }

    /** {@return the additional section, an EDNS OPT record included} */
    public List<ResourceRecord> additionals() {
        return external(additional);
    }

    /**
     * This message with another ID.
     *
     * @param id the ID, 16 bits
     * @return the copy
     */
    public DnsMessage withId(int id) {
        return new DnsMessage(id, flags, questions, answer, authority, additional);
    }

    /**
     * This message with other header flags (QR, opcode, AA, TC, RD, RA, Z, AD, CD and RCODE).
     *
     * @param flags the flags, 16 bits
     * @return the copy
     */
    public DnsMessage withFlags(int flags) {
        return new DnsMessage(id, flags, questions, answer, authority, additional);
    }

    /**
     * This message with another RCODE (3 for NXDOMAIN, ...).
     *
     * @param rcode the RCODE, 4 bits
     * @return the copy
     */
    public DnsMessage withRcode(int rcode) {
        return withFlags((flags & ~0xf) | (rcode & 0xf));
    }

    /**
     * This message with other questions.
     *
     * @param questions the question section
     * @return the copy
     */
    public DnsMessage withQuestions(List<Question> questions) {
        return new DnsMessage(id, flags, questions, answer, authority, additional);
    }

    /**
     * This message with other answers.
     *
     * @param answers the answer section
     * @return the copy
     */
    public DnsMessage withAnswers(List<ResourceRecord> answers) {
        return new DnsMessage(id, flags, questions, internal(answers), authority, additional);
    }

    /**
     * This message with another authority section.
     *
     * @param authorities the authority section
     * @return the copy
     */
    public DnsMessage withAuthorities(List<ResourceRecord> authorities) {
        return new DnsMessage(id, flags, questions, answer, internal(authorities), additional);
    }

    /**
     * This message with another additional section.
     *
     * @param additionals the additional section
     * @return the copy
     */
    public DnsMessage withAdditionals(List<ResourceRecord> additionals) {
        return new DnsMessage(id, flags, questions, answer, authority, internal(additionals));
    }

    /**
     * The mnemonic of a type.
     *
     * @param type the type
     * @return {@code A}, {@code AAAA}, ..., or {@code TYPE<n>} for a type without one (RFC 3597)
     */
    public static String typeName(int type) {
        String name = TYPE_NAMES.get(type);
        return name != null ? name : "TYPE" + type;
    }

    /**
     * The type a mnemonic names.
     *
     * @param name {@code A}, {@code aaaa}, ..., or {@code TYPE<n>}
     * @return the type
     * @throws IllegalArgumentException for a name this class does not know
     */
    public static int type(String name) {
        String n = name.strip().toUpperCase(Locale.ROOT);
        Integer t = TYPE_NUMBERS.get(n);
        if (t != null) return t;
        if (n.startsWith("TYPE")) {
            try {
                int v = Integer.parseInt(n.substring(4));
                if (v >= 0 && v <= 0xffff) return v;
            } catch (NumberFormatException e) {
                // below
            }
        }
        throw new IllegalArgumentException("unknown DNS type " + name);
    }

    /**
     * The name of an RCODE.
     *
     * @param rcode the RCODE
     * @return {@code NOERROR}, {@code NXDOMAIN}, ..., or {@code RCODE<n>}
     */
    public static String rcodeName(int rcode) {
        return rcode >= 0 && rcode < RCODES.length ? RCODES[rcode] : "RCODE" + rcode;
    }

    /**
     * The message as {@code dig} shows it: the header, then each section.
     *
     * @return the text, ending with a newline
     */
    public String render() {
        StringBuilder sb = new StringBuilder();
        int op = opcode();
        String opName = op < OPCODES.length && OPCODES[op] != null ? OPCODES[op] : "OPCODE" + op;
        sb.append(";; ").append(isResponse() ? "response" : "query").append(", opcode: ").append(opName)
                .append(", status: ").append(rcodeName(rcode())).append(", id: ").append(id).append('\n');
        List<String> f = new ArrayList<>();
        if (isResponse()) f.add("qr");
        if (isAuthoritative()) f.add("aa");
        if (isTruncated()) f.add("tc");
        if (isRecursionDesired()) f.add("rd");
        if (isRecursionAvailable()) f.add("ra");
        if ((flags & 0x20) != 0) f.add("ad");
        if ((flags & 0x10) != 0) f.add("cd");
        sb.append(";; flags: ").append(String.join(" ", f)).append('\n');
        if (!questions.isEmpty()) {
            sb.append(";; QUESTION:\n");
            for (Question q : questions) sb.append(q.name()).append(q.name().equals(".") ? "" : ".").append(' ')
                    .append(className(q.dnsClass())).append(' ').append(q.typeName()).append('\n');
        }
        section(sb, "ANSWER", answer);
        section(sb, "AUTHORITY", authority);
        section(sb, "ADDITIONAL", additional);
        return sb.toString();
    }

    private static void section(StringBuilder sb, String title, List<DnsRecord> records) {
        if (records.isEmpty()) return;
        sb.append(";; ").append(title).append(":\n");
        for (DnsRecord r : records) {
            ResourceRecord rr = ResourceRecord.of(r);
            if (r.type() == DnsRecord.OPT) {
                sb.append(rr).append('\n');
            } else {
                sb.append(rr.name()).append(rr.name().equals(".") ? "" : ".").append(' ').append(rr.ttl()).append(' ')
                        .append(className(rr.dnsClass())).append(' ').append(rr.typeName()).append(' ')
                        .append(rr.data().text()).append('\n');
            }
        }
    }

    @Override
    public String toString() {
        return (isResponse() ? "DNS response " : "DNS query ") + id + " " + questions
                + (isResponse() ? " " + rcodeName(rcode()) + ", " + answer.size() + " answers" : "");
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    private static String className(int dnsClass) {
        return switch (dnsClass) {
            case IN -> "IN";
            case 3 -> "CH";
            case 4 -> "HS";
            case 255 -> "ANY";
            default -> "CLASS" + dnsClass;
        };
    }

    /** A name in presentation format, without the final dot (the root is {@code .}). */
    static String presentation(DnsName name) {
        String s = name.toString();
        return name.isRoot() ? s : s.substring(0, s.length() - 1);
    }

    private static List<ResourceRecord> external(List<DnsRecord> records) {
        List<ResourceRecord> out = new ArrayList<>(records.size());
        for (DnsRecord r : records) out.add(ResourceRecord.of(r));
        return List.copyOf(out);
    }

    private static List<DnsRecord> internal(List<ResourceRecord> records) {
        List<DnsRecord> out = new ArrayList<>(records.size());
        for (ResourceRecord r : records) out.add(r.internal());
        return out;
    }

    /** An IP address literal, parsed without a lookup. */
    static InetAddress literal(String literal) {
        String s = Objects.requireNonNull(literal, "literal").strip();
        try {
            if (s.indexOf(':') >= 0) {
                // An IPv6 literal: InetAddress parses it without a lookup.
                String bare = s.startsWith("[") && s.endsWith("]") ? s.substring(1, s.length() - 1) : s;
                return InetAddress.getByName(bare);
            }
            String[] parts = s.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("not an IP address: " + literal);
            byte[] b = new byte[4];
            for (int i = 0; i < 4; i++) {
                if (parts[i].isEmpty() || parts[i].length() > 3 || !parts[i].chars().allMatch(Character::isDigit)) {
                    throw new IllegalArgumentException("not an IP address: " + literal);
                }
                int v = Integer.parseInt(parts[i]);
                if (v > 255) throw new IllegalArgumentException("not an IP address: " + literal);
                b[i] = (byte) v;
            }
            return InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("not an IP address: " + literal, e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Queries and parsing, for the validating resolver
    // ---------------------------------------------------------------------------------------

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
            List<Question> questions = new ArrayList<>(qd);
            int[] pos = {12};
            for (int i = 0; i < qd; i++) {
                DnsName n = readName(data, pos);
                int t = u16(data, pos[0]);
                int c = u16(data, pos[0] + 2);
                pos[0] += 4;
                questions.add(new Question(presentation(n), t, c));
            }
            List<DnsRecord> answer = readRecords(data, pos, an);
            List<DnsRecord> authority = readRecords(data, pos, ns);
            List<DnsRecord> additional = readRecords(data, pos, ar);
            return new DnsMessage(id, flags, questions, answer, authority, additional);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("malformed DNS message", e);
        }
    }

    private static List<DnsRecord> readRecords(byte[] data, int[] pos, int count) {
        List<DnsRecord> records = new ArrayList<>(Math.min(count, 64));
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
            // RFC 2181 section 8; an OPT record's TTL holds flags instead.
            if (ttl > 0x7fffffffL && type != DnsRecord.OPT) ttl = 0;
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
            if (p + 1 + len > data.length) throw new IllegalArgumentException("truncated name");
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
