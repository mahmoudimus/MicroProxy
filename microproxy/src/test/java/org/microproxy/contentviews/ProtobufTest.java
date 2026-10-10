package org.microproxy.contentviews;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ProtobufTest {

    static byte[] hex(String hex) {
        return HexFormat.of().parseHex(hex.replace(" ", ""));
    }

    static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) out[i] = (byte) values[i];
        return out;
    }

    /** A vector: wire bytes and how they render. */
    record Vector(String name, byte[] proto, String yaml) {
        @Override
        public String toString() {
            return name;
        }
    }

    /** mitmproxy_rs's round-trip vectors (view_protobuf.rs), with the packed comment this view adds. */
    static List<Vector> vectors() {
        return List.of(
                new Vector("varint", bytes(0x08, 0x96, 0x01), "1: 150  # !sint: 75\n"),
                new Vector("varint_zigzag_negative", bytes(0x08, 0x0B), "1: 11  # !sint: -6\n"),
                new Vector("varint_int64_negative", hex("08feffffffffffffffff01"), "1: -2  # u64: 18446744073709551614\n"),
                new Vector("binary", bytes(0x32, 0x03, 0x01, 0x02, 0x03), "6: !binary '010203'  # packed: [1, 2, 3]\n"),
                new Vector("string", hex("0A0568656C6C6F"), "1: hello\n"),
                new Vector("nested", bytes(0x2A, 0x02, 0x08, 0x2A), "5:\n  1: 42  # !sint: 21\n"),
                new Vector("nested_twice", hex("2A042A02082A"), "5:\n  5:\n    1: 42  # !sint: 21\n"),
                new Vector("fixed64", hex("19000000000000F0BF"),
                        "3: !fixed64 -1.0  # u64: 13830554455654793216, i64: -4616189618054758400\n"),
                new Vector("fixed64_positive", hex("196E861BF0F9210940"), "3: !fixed64 3.14159  # u64: 4614256650576692846\n"),
                new Vector("fixed64_no_float", hex("19FFFFFFFFFFFFFFFF"), "3: !fixed64 -1  # u64: 18446744073709551615\n"),
                new Vector("fixed64_positive_no_float", hex("19010000000000F87F"), "3: !fixed64 9221120237041090561\n"),
                new Vector("fixed32", hex("15000080BF"), "2: !fixed32 -1.0  # u32: 3212836864, i32: -1082130432\n"),
                new Vector("fixed32_positive", hex("15D00F4940"), "2: !fixed32 3.14159  # u32: 1078530000\n"),
                new Vector("fixed32_no_float", hex("15FFFFFFFF"), "2: !fixed32 -1  # u32: 4294967295\n"),
                new Vector("fixed32_positive_no_float", hex("150100C07F"), "2: !fixed32 2143289345\n"),
                // From the protobuf docs: repeated int32 f = 6 [packed=true] with 3, 270 and 86942.
                new Vector("repeated_packed", hex("3206038E029EA705"), "6: !binary 038e029ea705  # packed: [3, 270, 86942]\n"),
                new Vector("repeated_varint", hex("080108020803"), "1:\n- 1  # !sint: -1\n- 2  # !sint: 1\n- 3  # !sint: -2\n"));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void rendersAsMitmproxyDoes(Vector v) throws DecodeException {
        assertEquals(v.yaml(), Protobuf.render(v.proto()));
    }

    @ParameterizedTest
    @MethodSource("vectors")
    void reencodesToTheSameBytes(Vector v) throws DecodeException {
        ProtoMessage m = Protobuf.decode(v.proto());
        assertArrayEquals(v.proto(), Protobuf.encode(m));
        assertArrayEquals(v.proto(), Protobuf.encode(m.toPlain()));
    }

    @Test
    void invalidProtobufIsADecodeException() {
        DecodeException e = assertThrows(DecodeException.class, () -> Protobuf.decode(bytes(0xFF, 0xFF)));
        assertTrue(e.getMessage().startsWith("invalid protobuf"), e.getMessage());
        assertThrows(DecodeException.class, () -> Protobuf.decode(bytes(0x0a, 0x05, 0x41)));
        assertThrows(DecodeException.class, () -> Protobuf.decode(bytes(0x07)));
        assertThrows(DecodeException.class, () -> Protobuf.decode(bytes(0x00, 0x01)));
        assertThrows(DecodeException.class, () -> Protobuf.decode(bytes(0x0c)));
        assertThrows(DecodeException.class, () -> Protobuf.decode(bytes(0x0b, 0x08, 0x01)));
        assertThrows(DecodeException.class, () -> Protobuf.decode(hex("08ffffffffffffffffff7f")));
    }

    @Test
    void emptyMessage() throws DecodeException {
        assertEquals("{}  # empty protobuf message", Protobuf.render(new byte[0]));
    }

    /** mitmproxy_rs's test_no_crash: a message from a gRPC testing server. */
    @Test
    void nestedMessagesInARepeatedField() throws DecodeException {
        byte[] data = ("\n\u0013gRPC testing server\u0012\u0007\n\u0005Index\u0012\u0007\n\u0005Empty\u0012\u000c\n\nDummyUnary"
                + "\u0012\u000f\n\rSpecificError\u0012\r\n\u000bRandomError\u0012\u000e\n\u000cHeadersUnary"
                + "\u0012\u0011\n\u000fNoResponseUnary").getBytes(StandardCharsets.ISO_8859_1);
        assertEquals("1: gRPC testing server\n2:\n- 1: Index\n- 1: Empty\n- 1: DummyUnary\n- 1: SpecificError\n"
                + "- 1: RandomError\n- 1: HeadersUnary\n- 1: NoResponseUnary\n", Protobuf.render(data));
        assertArrayEquals(data, Protobuf.encode(Protobuf.decode(data)));
    }

    /** mitmproxy's old protobuf test data: a group (wire types 3 and 4). */
    @Test
    void groups() throws DecodeException {
        byte[] data = hex(CapturedData.PROTOBUF03);
        ProtoMessage m = Protobuf.decode(data);
        ProtoValue.Group g = assertInstanceOf(ProtoValue.Group.class, m.first(2).orElseThrow());
        assertEquals(new ProtoValue.Varint(3840), g.message().first(3).orElseThrow());
        assertEquals("2: !group\n  3: 3840  # !sint: 1920\n  4: 2160  # !sint: 1080\n", m.render());
        assertArrayEquals(data, Protobuf.encode(m));
        assertArrayEquals(data, Protobuf.encode(m.toPlain()));
    }

    /** mitmproxy's old protobuf and gRPC test data, captured from real traffic. */
    @ParameterizedTest
    @MethodSource("captured")
    void capturedMessagesRoundTrip(String hex) throws DecodeException {
        byte[] data = hex(hex);
        ProtoMessage m = Protobuf.decode(data);
        assertArrayEquals(data, Protobuf.encode(m));
        assertArrayEquals(data, Protobuf.encode(m.toPlain()));
        assertTrue(m.render().endsWith("\n"));
    }

    static List<String> captured() {
        return List.of(CapturedData.PROTOBUF01, CapturedData.DESCRIPTOR_SET, CapturedData.PROTOBUF03,
                CapturedData.GRPC_MSG3);
    }

    @Test
    void capturedMessageRendering() throws DecodeException {
        assertEquals("1: 3bbc333c-e61c-433b-819a-0b9a8cc103b8\n", Protobuf.render(hex(CapturedData.PROTOBUF01)));
        String geocode = Protobuf.render(hex(CapturedData.GRPC_MSG3));
        assertTrue(geocode.startsWith("1:\n  1: !binary '15'\n  2: 1650 Pennsylvania Avenue NW, Washington, DC 20502, USA\n"),
                geocode);
        assertTrue(geocode.contains("      1: !fixed64 38.896898  # u64: 4630671069038832773\n"), geocode);
    }

    @Test
    void negativeInt32AndInt64TakeTenBytes() throws DecodeException {
        Map<Object, Object> fields = new LinkedHashMap<>();
        fields.put(1, -1L);
        fields.put(2, (long) Integer.MIN_VALUE);
        byte[] data = Protobuf.encode(fields);
        assertEquals("08ffffffffffffffffff01" + "1080808080f8ffffffff01", HexFormat.of().formatHex(data));
        ProtoMessage m = Protobuf.decode(data);
        assertEquals("1: -1  # u64: 18446744073709551615\n2: -2147483648  # u64: 18446744071562067968\n", m.render());
        assertEquals(fields, m.toPlain());
    }

    @Test
    void zigzagAmbiguityIsShownNotDecided() throws DecodeException {
        // 3 is int32 3 or sint32 -2: the plain value stays 3, the comment names the other reading.
        assertEquals("1: 3  # !sint: -2\n", Protobuf.render(bytes(0x08, 0x03)));
        assertEquals(3L, Protobuf.decode(bytes(0x08, 0x03)).toPlain().get(1));
        assertEquals(-2L, Protobuf.zigzagDecode(3));
        assertEquals(3L, Protobuf.zigzagEncode(-2));
        assertEquals(Integer.MIN_VALUE, Protobuf.zigzagDecode32(-1));
        assertEquals(-1, Protobuf.zigzagEncode32(Integer.MIN_VALUE));
        assertEquals(Long.MIN_VALUE, Protobuf.zigzagDecode(-1L));
    }

    @Test
    void textBytesAndNestedHeuristics() throws DecodeException {
        // Printable UTF-8 (beyond ASCII too) is text.
        assertInstanceOf(ProtoValue.Text.class, first(field(1, "héllo wörld\n".getBytes(StandardCharsets.UTF_8))));
        // Empty values are empty strings.
        assertEquals(new ProtoValue.Text(""), first(field(1, new byte[0])));
        // A valid message is a message.
        assertInstanceOf(ProtoValue.Message.class, first(field(1, bytes(0x08, 0x01, 0x12, 0x01, 0x41))));
        // Invalid UTF-8 that is no message is bytes.
        assertInstanceOf(ProtoValue.Bytes.class, first(field(1, bytes(0xff, 0xfe, 0x00))));
        // Control characters make text bytes.
        assertInstanceOf(ProtoValue.Bytes.class, first(field(1, bytes(0x07, 0x07))));
        // A redundant varint byte is not something an encoder writes: bytes, not a message.
        assertInstanceOf(ProtoValue.Bytes.class, first(field(1, bytes(0x08, 0x81, 0x00))));
        // One wire type per field number in a nested message.
        assertInstanceOf(ProtoValue.Bytes.class, first(field(1, bytes(0x08, 0x01, 0x0d, 1, 2, 3, 4))));
        // All values of a field are guessed together: one is no message, so neither is.
        byte[] two = concat(field(1, "abc".getBytes(StandardCharsets.UTF_8)), field(1, bytes(0x08, 0x01)));
        ProtoMessage m = Protobuf.decode(two);
        assertInstanceOf(ProtoValue.Bytes.class, m.values(1).get(0));
        assertInstanceOf(ProtoValue.Bytes.class, m.values(1).get(1));
        assertArrayEquals(two, Protobuf.encode(m));
    }

    @Test
    void nestedPackedAndStringsTogether() throws DecodeException {
        Map<Object, Object> inner = new LinkedHashMap<>();
        inner.put(1, "name");
        inner.put(2, Protobuf.packVarints(List.of(1, 300, 70000)));
        Map<Object, Object> outer = new LinkedHashMap<>();
        outer.put(1, 7L);
        outer.put(2, inner);
        outer.put(3, List.of("a", "b"));
        outer.put(4, new ProtoValue.Fixed32(Float.floatToIntBits(1.5f)));
        byte[] data = Protobuf.encode(outer);
        ProtoMessage m = Protobuf.decode(data);
        assertEquals("""
                1: 7  # !sint: -4
                2:
                  1: name
                  2: !binary 01ac02f0a204  # packed: [1, 300, 70000]
                3:
                - a
                - b
                4: !fixed32 1.5  # u32: 1069547520
                """, m.render());
        assertArrayEquals(data, Protobuf.encode(m.toPlain()));
        assertEquals(List.of(1L, 300L, 70000L), Protobuf.unpackVarints(hex("01ac02f0a204")));
    }

    @Test
    void depthIsBounded() throws DecodeException {
        byte[] data = bytes(0x08, 0x01);
        for (int i = 0; i < 200; i++) data = field(1, data);
        ProtoMessage m = Protobuf.decode(data);
        int depth = 0;
        ProtoValue v = m.first(1).orElseThrow();
        while (v instanceof ProtoValue.Message nested) {
            depth++;
            v = nested.message().first(1).orElseThrow();
        }
        assertEquals(Protobuf.DEFAULT_MAX_DEPTH, depth);
        assertInstanceOf(ProtoValue.Bytes.class, v);
        assertArrayEquals(data, Protobuf.encode(m));
        // Groups nest only so deep.
        byte[] groups = new byte[2 * 100];
        for (int i = 0; i < 100; i++) {
            groups[i] = 0x0b;
            groups[199 - i] = 0x0c;
        }
        assertThrows(DecodeException.class, () -> Protobuf.decode(groups));
    }

    @Test
    void encodingErrorsAreIllegalArguments() {
        Map<Object, Object> self = new LinkedHashMap<>();
        self.put(1, self);
        assertThrows(IllegalArgumentException.class, () -> Protobuf.encode(self));
        assertThrows(IllegalArgumentException.class, () -> Protobuf.encode(Map.of("name", 1)));
        assertThrows(IllegalArgumentException.class, () -> Protobuf.encode(Map.of(0, 1)));
        assertThrows(IllegalArgumentException.class, () -> Protobuf.encode(Map.of(1, new Object())));
        assertThrows(IllegalArgumentException.class, () -> Protobuf.encode(Map.of(1, List.of(List.of(1)))));
    }

    @Test
    void fixedWidthValuesKeepTheirWireType() throws DecodeException {
        Map<Object, Object> fields = new LinkedHashMap<>();
        fields.put(1, 2.5);
        fields.put(2, 2.5f);
        byte[] data = Protobuf.encode(fields);
        Map<Object, Object> plain = Protobuf.decode(data).toPlain();
        assertEquals(new ProtoValue.Fixed64(Double.doubleToLongBits(2.5)), plain.get(1));
        assertEquals(new ProtoValue.Fixed32(Float.floatToIntBits(2.5f)), plain.get(2));
        assertArrayEquals(data, Protobuf.encode(plain));
    }

    static ProtoValue first(byte[] message) throws DecodeException {
        return Protobuf.decode(message).first(1).orElseThrow();
    }

    /** A length-delimited field. */
    static byte[] field(int number, byte[] value) {
        Map<Object, Object> m = new LinkedHashMap<>();
        m.put(number, value);
        return Protobuf.encode(m);
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }
}
