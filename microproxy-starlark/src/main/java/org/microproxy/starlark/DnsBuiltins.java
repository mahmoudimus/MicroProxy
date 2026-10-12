package org.microproxy.starlark;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.microproxy.dns.DnsMessage;
import org.microproxy.dns.DnsMessage.Address;
import org.microproxy.dns.DnsMessage.Mx;
import org.microproxy.dns.DnsMessage.Name;
import org.microproxy.dns.DnsMessage.Opaque;
import org.microproxy.dns.DnsMessage.Question;
import org.microproxy.dns.DnsMessage.Rdata;
import org.microproxy.dns.DnsMessage.ResourceRecord;
import org.microproxy.dns.DnsMessage.Soa;
import org.microproxy.dns.DnsMessage.Srv;
import org.microproxy.dns.DnsMessage.Txt;
import org.microproxy.thirdparty.starlark.annot.Param;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.annot.StarlarkMethod;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkThread;
import org.microproxy.thirdparty.starlark.eval.StarlarkValue;

/**
 * The {@code dns} module: DNS messages (as DNS over QUIC, DNS over HTTPS and DNS over UDP carry
 * them) as plain dicts, built on {@link DnsMessage}.
 *
 * <p>A message is a dict with {@code id}, {@code flags} (16 bits), the flags by name ({@code
 * response}, {@code opcode}, {@code authoritative}, {@code truncated}, {@code recursion_desired},
 * {@code recursion_available}, {@code rcode}), {@code questions} (dicts of {@code name}, {@code
 * type} and {@code class}) and {@code answers}, {@code authorities} and {@code additionals} (dicts
 * of {@code name}, {@code type}, {@code class}, {@code ttl} and {@code data}). Types are names
 * ({@code "A"}, {@code "AAAA"}, {@code "TYPE65280"}); the data of A and AAAA records is the address,
 * that of NS, CNAME, PTR and DNAME the name, TXT a list of strings, MX, SRV and SOA dicts of their
 * fields, and other types' bytes. {@code encode} takes the same dicts, with defaults for what is
 * left out; the flags by name win over {@code flags}.
 */
final class DnsBuiltins {

    private DnsBuiltins() {}

    @StarlarkBuiltin(name = "dns", doc = "DNS messages as dicts: decode, encode and render.")
    public static final class DnsModule implements StarlarkValue {

        @StarlarkMethod(name = "decode", useStarlarkThread = true,
                doc = "Decodes a DNS message (wire format, as DNS over QUIC and DNS over HTTPS carry it) into a dict: "
                        + "id, flags and the flags by name, questions, answers, authorities and additionals.",
                parameters = {@Param(name = "data", doc = "the message")})
        public Dict<?, ?> decode(Object data, StarlarkThread thread) throws EvalException {
            DnsMessage m;
            try {
                m = DnsMessage.decode(Builtins.bytes(data, "data"));
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("dns.decode: %s", e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
            }
            return (Dict<?, ?>) ProtoBuiltins.toStarlark(toPlain(m), thread.mutability());
        }

        @StarlarkMethod(name = "encode",
                doc = "Encodes a dict as decode makes them into a DNS message's bytes, names compressed.",
                parameters = {@Param(name = "message", doc = "the message, a dict")})
        public StarlarkBytes encode(Object message) throws EvalException {
            if (!(message instanceof Dict<?, ?>)) throw Starlark.errorf("dns.encode takes a dict, not %s", Starlark.type(message));
            try {
                return StarlarkBytes.of(null, fromPlain((Map<?, ?>) ProtoBuiltins.toJava(message, 0)).encode());
            } catch (IllegalArgumentException | ClassCastException e) {
                throw Starlark.errorf("dns.encode: %s", e.getMessage());
            }
        }

        @StarlarkMethod(name = "render",
                doc = "The message as dig shows it: the header, then each section's records.",
                parameters = {@Param(name = "data", doc = "the message's bytes")})
        public String render(Object data) throws EvalException {
            try {
                return DnsMessage.decode(Builtins.bytes(data, "data")).render();
            } catch (IllegalArgumentException e) {
                throw Starlark.errorf("dns.render: %s", e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Between DnsMessage and plain values
    // ---------------------------------------------------------------------------------------

    static Map<String, Object> toPlain(DnsMessage m) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", m.id());
        out.put("flags", m.flags());
        out.put("response", m.isResponse());
        out.put("opcode", m.opcode());
        out.put("authoritative", m.isAuthoritative());
        out.put("truncated", m.isTruncated());
        out.put("recursion_desired", m.isRecursionDesired());
        out.put("recursion_available", m.isRecursionAvailable());
        out.put("rcode", m.rcode());
        List<Object> questions = new ArrayList<>();
        for (Question q : m.questions()) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("name", q.name());
            d.put("type", q.typeName());
            d.put("class", q.dnsClass());
            questions.add(d);
        }
        out.put("questions", questions);
        out.put("answers", records(m.answers()));
        out.put("authorities", records(m.authorities()));
        out.put("additionals", records(m.additionals()));
        return out;
    }

    private static List<Object> records(List<ResourceRecord> records) {
        List<Object> out = new ArrayList<>(records.size());
        for (ResourceRecord r : records) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("name", r.name());
            d.put("type", r.typeName());
            d.put("class", r.dnsClass());
            d.put("ttl", r.ttl());
            d.put("data", data(r.data()));
            out.add(d);
        }
        return out;
    }

    private static Object data(Rdata data) {
        return switch (data) {
            case Address a -> a.text();
            case Name n -> n.name();
            case Mx mx -> fields("preference", mx.preference(), "exchange", mx.exchange());
            case Srv srv -> fields("priority", srv.priority(), "weight", srv.weight(), "port", srv.port(),
                    "target", srv.target());
            case Txt txt -> new ArrayList<Object>(txt.strings());
            case Soa soa -> fields("mname", soa.mname(), "rname", soa.rname(), "serial", soa.serial(),
                    "refresh", soa.refresh(), "retry", soa.retry(), "expire", soa.expire(), "minimum", soa.minimum());
            case Opaque o -> o.bytes();
        };
    }

    private static Map<String, Object> fields(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) out.put((String) pairs[i], pairs[i + 1]);
        return out;
    }

    static DnsMessage fromPlain(Map<?, ?> m) {
        int flags = (int) number(m, "flags", 0);
        flags = bit(m, "response", flags, 0x8000);
        flags = bit(m, "authoritative", flags, 0x0400);
        flags = bit(m, "truncated", flags, 0x0200);
        flags = bit(m, "recursion_desired", flags, 0x0100);
        flags = bit(m, "recursion_available", flags, 0x0080);
        if (m.get("opcode") != null) flags = (flags & ~0x7800) | (((int) number(m, "opcode", 0) & 0xf) << 11);
        if (m.get("rcode") != null) flags = (flags & ~0xf) | ((int) number(m, "rcode", 0) & 0xf);
        List<Question> questions = new ArrayList<>();
        for (Object o : list(m, "questions")) {
            Map<?, ?> q = map(o, "a question");
            questions.add(new Question(string(q, "name"), type(q), (int) number(q, "class", DnsMessage.IN)));
        }
        return DnsMessage.of((int) number(m, "id", 0), flags, questions, records(m, "answers"),
                records(m, "authorities"), records(m, "additionals"));
    }

    private static List<ResourceRecord> records(Map<?, ?> m, String section) {
        List<ResourceRecord> out = new ArrayList<>();
        for (Object o : list(m, section)) {
            Map<?, ?> r = map(o, "a record");
            String name = string(r, "name");
            int type = type(r);
            int dnsClass = (int) number(r, "class", DnsMessage.IN);
            long ttl = number(r, "ttl", 0);
            out.add(new ResourceRecord(name, type, dnsClass, ttl, rdata(type, r.get("data"))));
        }
        return out;
    }

    private static byte[] rdata(int type, Object data) {
        if (data instanceof byte[] b) return b;
        if (data == null) throw new IllegalArgumentException("a " + DnsMessage.typeName(type) + " record needs its data");
        Rdata typed = switch (type) {
            case DnsMessage.A, DnsMessage.AAAA -> Address.of((String) data);
            case DnsMessage.NS, DnsMessage.CNAME, DnsMessage.PTR, 39 -> new Name((String) data);
            case DnsMessage.MX -> {
                Map<?, ?> d = map(data, "MX data");
                yield new Mx((int) number(d, "preference", 0), string(d, "exchange"));
            }
            case DnsMessage.SRV -> {
                Map<?, ?> d = map(data, "SRV data");
                yield new Srv((int) number(d, "priority", 0), (int) number(d, "weight", 0), (int) number(d, "port", 0),
                        string(d, "target"));
            }
            case DnsMessage.TXT -> {
                List<String> strings = new ArrayList<>();
                if (data instanceof String s) {
                    strings.add(s);
                } else {
                    for (Object o : (List<?>) data) strings.add((String) o);
                }
                yield new Txt(strings);
            }
            case DnsMessage.SOA -> {
                Map<?, ?> d = map(data, "SOA data");
                yield new Soa(string(d, "mname"), string(d, "rname"), number(d, "serial", 0), number(d, "refresh", 0),
                        number(d, "retry", 0), number(d, "expire", 0), number(d, "minimum", 0));
            }
            default -> throw new IllegalArgumentException("the data of a " + DnsMessage.typeName(type)
                    + " record is bytes");
        };
        return typed.encode(type);
    }

    private static int type(Map<?, ?> d) {
        Object t = d.get("type");
        if (t instanceof String s) return DnsMessage.type(s);
        if (t instanceof Long || t instanceof BigInteger) return (int) number(d, "type", 0);
        throw new IllegalArgumentException("a type is a name such as \"A\", or a number");
    }

    private static List<?> list(Map<?, ?> m, String key) {
        Object v = m.get(key);
        if (v == null) return List.of();
        if (v instanceof List<?> l) return l;
        throw new IllegalArgumentException(key + " must be a list");
    }

    private static Map<?, ?> map(Object o, String what) {
        if (o instanceof Map<?, ?> m) return m;
        throw new IllegalArgumentException(what + " must be a dict");
    }

    private static String string(Map<?, ?> m, String key) {
        if (m.get(key) instanceof String s) return s;
        throw new IllegalArgumentException(key + " must be a string");
    }

    private static long number(Map<?, ?> m, String key, long otherwise) {
        Object v = m.get(key);
        if (v == null) return otherwise;
        if (v instanceof Long l) return l;
        if (v instanceof BigInteger b && b.bitLength() < 64) return b.longValue();
        throw new IllegalArgumentException(key + " must be an int");
    }

    private static int bit(Map<?, ?> m, String key, int flags, int bit) {
        Object v = m.get(key);
        if (v == null) return flags;
        if (!(v instanceof Boolean b)) throw new IllegalArgumentException(key + " must be a bool");
        return b ? flags | bit : flags & ~bit;
    }
}
