package org.microproxy.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Checks against published values: the IANA root key, RFC 4034 ordering, RFC 5155 hashes. */
class DnssecPrimitivesTest {

    /** KSK-2017 from https://data.iana.org/root-anchors/root-anchors.xml. */
    private static final String ROOT_KSK_2017 =
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8O"
            + "g8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eN"
            + "buv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa"
            + "8subX2Nn6UwNR1AkUTV74bU=";

    @Test
    void rootKeyTagAndDsDigestMatchIana() throws Exception {
        byte[] rdata = DnsRecord.concat(new byte[] {1, 1, 3, 8}, Base64.getDecoder().decode(ROOT_KSK_2017));
        assertEquals(20326, DnsRecord.keyTag(rdata));
        assertEquals("e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
                HexFormat.of().formatHex(DnssecCrypto.dsDigest(2, DnsName.ROOT, rdata)));
        assertTrue(DnssecCrypto.publicKey(8, rdata.length > 4 ? java.util.Arrays.copyOfRange(rdata, 4, rdata.length) : rdata)
                .getAlgorithm().equals("RSA"));
    }

    @Test
    void nsec3HashesFromRfc5155AppendixA() {
        byte[] salt = HexFormat.of().parseHex("aabbccdd");
        assertEquals("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                DnssecCrypto.base32HexEncode(DnssecCrypto.nsec3Hash(DnsName.parse("example"), salt, 12)));
        assertEquals("35mthgpgcu1qg68fab165klnsnk3dpvl",
                DnssecCrypto.base32HexEncode(DnssecCrypto.nsec3Hash(DnsName.parse("a.example"), salt, 12)));
        byte[] hash = DnssecCrypto.nsec3Hash(DnsName.parse("a.example"), salt, 12);
        assertArrayEquals(hash, DnssecCrypto.base32HexDecode(
                DnssecCrypto.base32HexEncode(hash).toUpperCase().getBytes()));
    }

    @Test
    void canonicalOrderingFromRfc4034Section61() {
        List<DnsName> expected = new ArrayList<>();
        for (String n : List.of("example", "a.example", "yljkjljk.a.example", "Z.a.example", "zABC.a.EXAMPLE",
                "z.example", "\\001.z.example", "*.z.example", "\\200.z.example")) {
            expected.add(parse(n));
        }
        List<DnsName> shuffled = new ArrayList<>(expected);
        java.util.Collections.reverse(shuffled);
        java.util.Collections.sort(shuffled);
        assertEquals(expected, shuffled);
        assertEquals(DnsName.parse("WWW.Example.COM"), DnsName.parse("www.example.com."));
    }

    /** Parses names with RFC 1035 {@code \DDD} escapes. */
    private static DnsName parse(String text) {
        String[] parts = text.split("\\.");
        byte[][] labels = new byte[parts.length][];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            labels[i] = p.startsWith("\\") ? new byte[] {(byte) Integer.parseInt(p.substring(1))} : p.getBytes();
        }
        return DnsName.of(labels);
    }

    @Test
    void nsecCoverage() {
        DnsName a = DnsName.parse("a.example");
        DnsName c = DnsName.parse("c.example");
        assertTrue(DnssecValidator.nsecCovers(a, c, DnsName.parse("b.example")));
        assertFalse(DnssecValidator.nsecCovers(a, c, a));
        assertFalse(DnssecValidator.nsecCovers(a, c, c));
        // The last NSEC wraps to the apex.
        assertTrue(DnssecValidator.nsecCovers(DnsName.parse("z.example"), DnsName.parse("example"), DnsName.parse("zz.example")));
    }

    @Test
    void typeBitmaps() {
        byte[] bitmap = DnsTestSupport.bitmap(DnsRecord.A, DnsRecord.NS, DnsRecord.RRSIG, DnsRecord.NSEC, 1234);
        assertTrue(DnsRecord.bitmapHas(bitmap, DnsRecord.NS));
        assertTrue(DnsRecord.bitmapHas(bitmap, 1234));
        assertFalse(DnsRecord.bitmapHas(bitmap, DnsRecord.DS));
        assertFalse(DnsRecord.bitmapHas(bitmap, DnsRecord.SOA));
    }
}
