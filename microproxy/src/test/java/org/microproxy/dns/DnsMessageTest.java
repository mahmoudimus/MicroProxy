package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.dns.DnsMessage.Address;
import org.microproxy.dns.DnsMessage.Mx;
import org.microproxy.dns.DnsMessage.Name;
import org.microproxy.dns.DnsMessage.Opaque;
import org.microproxy.dns.DnsMessage.Question;
import org.microproxy.dns.DnsMessage.ResourceRecord;
import org.microproxy.dns.DnsMessage.Soa;
import org.microproxy.dns.DnsMessage.Srv;
import org.microproxy.dns.DnsMessage.Txt;

/** {@link DnsMessage}'s public view: decoding, typed RDATA, encoding with compression. */
class DnsMessageTest {

    /** A response for example.com A as a resolver sends it, its answer's owner a compression pointer. */
    private static final byte[] RESPONSE = HexFormat.of().parseHex(
            "123481800001000200000001076578616d706c6503636f6d0000010001"
                    + "c00c000100010000012c00045db8d822"
                    + "c00c000500010000003c00050377777700"
                    + "0000291000000080000000");

    @Test
    void decodesAResponse() {
        DnsMessage m = DnsMessage.decode(RESPONSE);
        assertEquals(0x1234, m.id());
        assertTrue(m.isResponse());
        assertTrue(m.isRecursionDesired());
        assertTrue(m.isRecursionAvailable());
        assertFalse(m.isTruncated());
        assertEquals(0, m.opcode());
        assertEquals(0, m.rcode());
        assertEquals(List.of(new Question("example.com", DnsMessage.A)), m.questions());
        ResourceRecord a = m.answers().getFirst();
        assertEquals("example.com", a.name());
        assertEquals("A", a.typeName());
        assertEquals(300, a.ttl());
        assertEquals(Address.of("93.184.216.34"), a.data());
        assertEquals(new Name("www"), m.answers().get(1).data());
        ResourceRecord opt = m.additionals().getFirst();
        assertEquals(".", opt.name());
        assertEquals(41, opt.type());
        assertEquals(4096, opt.dnsClass());
        assertEquals(0x8000, opt.ttl());
        assertTrue(m.render().contains("example.com. 300 IN A 93.184.216.34"), m.render());
        assertTrue(m.render().contains("; EDNS: version 0, udp 4096, do"), m.render());
    }

    @Test
    void encodesWhatItDecodesWithCompressedNames() {
        DnsMessage m = DnsMessage.decode(RESPONSE);
        assertArrayEquals(RESPONSE, m.encode(), "the same bytes, owner names pointing back to the question's");
        byte[] encoded = m.withAnswers(List.of(
                ResourceRecord.of("example.com", DnsMessage.A, 60, Address.of("0.0.0.0")),
                ResourceRecord.of("mail.example.com", DnsMessage.MX, 60, new Mx(10, "mx.example.com")))).encode();
        DnsMessage back = DnsMessage.decode(encoded);
        assertEquals(Address.of("0.0.0.0"), back.answers().getFirst().data());
        assertEquals(new Mx(10, "mx.example.com"), back.answers().get(1).data());
        // "mail" plus a pointer to "example.com"
        assertTrue(indexOf(encoded, new byte[] {4, 'm', 'a', 'i', 'l', (byte) 0xc0, 12}) > 0);
    }

    @Test
    void typedRdataRoundTrips() {
        List<ResourceRecord> records = List.of(
                ResourceRecord.of("v6.test", DnsMessage.AAAA, 1, Address.of("2001:db8::1")),
                ResourceRecord.of("alias.test", DnsMessage.CNAME, 2, new Name("target.test")),
                ResourceRecord.of("_sip._tcp.test", DnsMessage.SRV, 3, new Srv(1, 2, 5060, "sip.test")),
                ResourceRecord.of("txt.test", DnsMessage.TXT, 4, new Txt(List.of("v=spf1 -all", "hé"))),
                ResourceRecord.of("test", DnsMessage.SOA, 5, new Soa("ns.test", "admin.test", 2024010101L, 7200,
                        3600, 1209600, 4294967295L)),
                new ResourceRecord("odd.test", 99, DnsMessage.IN, 6, new byte[] {1, 2, 3}));
        DnsMessage m = DnsMessage.query(7, "test", 255).reply(records);
        DnsMessage back = DnsMessage.decode(m.encode());
        assertEquals(records, back.answers());
        for (int i = 0; i < records.size(); i++) assertEquals(records.get(i).data(), back.answers().get(i).data());
        assertInstanceOf(Opaque.class, back.answers().getLast().data());
        assertEquals("\\# 3 010203", back.answers().getLast().data().text());
        assertEquals("1 2 5060 sip.test.", back.answers().get(2).data().text());
        assertTrue(back.isResponse());
        assertTrue(back.isRecursionDesired());
        assertEquals(7, back.id());
    }

    @Test
    void queriesRepliesAndHeaderChanges() {
        DnsMessage q = DnsMessage.query(0xbeef, "Blocked.Example.", DnsMessage.A);
        assertFalse(q.isResponse());
        assertEquals("Blocked.Example", q.questions().getFirst().name());
        DnsMessage r = q.reply(List.of()).withRcode(3);
        assertEquals("NXDOMAIN", DnsMessage.rcodeName(r.rcode()));
        assertEquals(0xbeef, DnsMessage.decode(r.encode()).id());
        assertEquals(0x0042, q.withId(0x10042).id());
        assertEquals(DnsMessage.AAAA, DnsMessage.type("aaaa"));
        assertEquals(1234, DnsMessage.type("TYPE1234"));
        assertEquals("TYPE1234", DnsMessage.typeName(1234));
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.type("NOPE"));
    }

    @Test
    void namesWithEscapes() {
        ResourceRecord r = new ResourceRecord("a\\.b.test", DnsMessage.A, DnsMessage.IN, 1, new byte[4]);
        DnsMessage back = DnsMessage.decode(DnsMessage.query(1, "x", 1).reply(List.of(r)).encode());
        assertEquals("a\\.b.test", back.answers().getFirst().name());
        assertEquals(2, DnsName.parse("a\\.b.test").labelCount());
        assertEquals("sp\\032ace.test", new Name("sp\\032ace.test").name());
        assertThrows(IllegalArgumentException.class, () -> new Name("a..b"));
        assertThrows(IllegalArgumentException.class, () -> new Name("bad\\99"));
    }

    @Test
    void rejectsWhatDoesNotFit() {
        assertThrows(IllegalArgumentException.class, () -> Address.of("example.com"));
        assertThrows(IllegalArgumentException.class, () -> Address.of("1.2.3.256"));
        assertThrows(IllegalArgumentException.class,
                () -> ResourceRecord.of("x", DnsMessage.A, 1, Address.of("::1")));
        assertThrows(IllegalArgumentException.class, () -> ResourceRecord.of("x", DnsMessage.A, 1, new Name("y")));
        assertThrows(IllegalArgumentException.class, () -> new Txt(List.of("x".repeat(256))).encode(DnsMessage.TXT));
    }

    @Test
    void malformedMessages() {
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.decode(new byte[5]));
        // A question whose label runs past the end.
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.decode(
                HexFormat.of().parseHex("000001000001000000000000" + "0a6578")));
        // A pointer to itself.
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.decode(
                HexFormat.of().parseHex("000001000001000000000000" + "c00c00010001")));
        // A records count larger than what follows.
        assertThrows(IllegalArgumentException.class, () -> DnsMessage.decode(Arrays.copyOf(RESPONSE, 40)));
        // RDATA that does not parse as its type reads as opaque bytes.
        ResourceRecord bad = new ResourceRecord("x", DnsMessage.A, DnsMessage.IN, 1, new byte[3]);
        assertInstanceOf(Opaque.class, bad.data());
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) if (haystack[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }
}
