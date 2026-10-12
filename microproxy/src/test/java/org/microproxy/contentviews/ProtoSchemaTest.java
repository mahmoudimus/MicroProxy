package org.microproxy.contentviews;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.contentviews.ProtobufTest.hex;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.http.HttpHeaders;

class ProtoSchemaTest {

    static byte[] tinyDescriptorSet() throws IOException {
        try (InputStream in = ProtoSchemaTest.class.getResourceAsStream("tiny.desc")) {
            return in.readAllBytes();
        }
    }

    static ProtoSchema tiny() throws IOException, DecodeException {
        return ProtoSchema.parse(tinyDescriptorSet());
    }

    /** The checked-in descriptor set is what {@link TinySchema} encodes, byte for byte. */
    @Test
    void checkedInDescriptorSetIsReproducible() throws IOException {
        assertArrayEquals(TinySchema.bytes(), tinyDescriptorSet());
    }

    @Test
    void readsMessagesEnumsAndMethods() throws Exception {
        ProtoSchema schema = tiny();
        ProtoSchema.MessageType order = schema.message("shop.Order").orElseThrow();
        assertEquals(11, order.fields().size());
        assertEquals(ProtoSchema.Type.SINT32, order.field("delta").type());
        assertEquals("shop.Order.Item", order.field(3).typeName());
        assertTrue(order.field("codes").packed(), "proto3 packs repeated scalars");
        assertFalse(order.field("items").packed());
        assertTrue(schema.message(".shop.Order.LabelsEntry").orElseThrow().mapEntry());
        assertEquals("SHIPPED", schema.enumType("shop.Order.Status").orElseThrow().values().get(2));
        ProtoSchema.Method watch = schema.method("/shop.Shop/Watch?x=1").orElseThrow();
        assertTrue(watch.serverStreaming());
        assertFalse(watch.clientStreaming());
        assertEquals("shop.GetOrderRequest", schema.messageFor("/shop.Shop/GetOrder", true).orElseThrow().fullName());
        assertEquals("shop.Order", schema.messageFor("/shop.Shop/GetOrder", false).orElseThrow().fullName());
        assertTrue(schema.messageFor("/shop.Shop/Missing", false).isEmpty());
        // The well-known types are there too.
        assertTrue(schema.message("google.rpc.Status").isPresent());
    }

    static Map<Object, Object> sampleOrder() {
        Map<Object, Object> item = new LinkedHashMap<>();
        item.put("sku", "A-1");
        item.put("quantity", 3L);
        item.put("price", 2.5);
        Map<Object, Object> labels = new LinkedHashMap<>();
        labels.put("gift", "yes");
        labels.put("rush", "no");
        Map<Object, Object> order = new LinkedHashMap<>();
        order.put("id", 42L);
        order.put("customer", "Ada");
        order.put("items", List.of(item));
        order.put("status", "SHIPPED");
        order.put("delta", -3L);
        order.put("codes", List.of(1L, -1L, 300L));
        order.put("labels", labels);
        order.put("total", 7.5);
        order.put("paid", true);
        order.put("checksum", 4000000000L);
        order.put("blob", new byte[] {1, 2});
        return order;
    }

    @Test
    void decodesAndEncodesWithNames() throws Exception {
        ProtoSchema schema = tiny();
        Map<Object, Object> order = sampleOrder();
        byte[] data = Protobuf.encode(order, schema, "shop.Order");
        ProtoMessage m = Protobuf.decode(data, schema, "shop.Order");
        assertEquals("""
                id: 42
                customer: Ada
                items:
                - sku: A-1
                  quantity: 3
                  price: 2.5
                status: SHIPPED
                delta: -3
                codes:
                - 1
                - -1
                - 300
                labels:
                  gift: 'yes'
                  rush: 'no'
                total: 7.5
                paid: true
                checksum: 4000000000
                blob: !binary '0102'
                """, m.render());
        Map<Object, Object> plain = m.toPlain();
        assertEquals("SHIPPED", plain.get("status"));
        assertEquals(-3L, plain.get("delta"));
        assertEquals(List.of(1L, -1L, 300L), plain.get("codes"));
        assertEquals(Map.of("gift", "yes", "rush", "no"), plain.get("labels"));
        assertArrayEquals(data, Protobuf.encode(plain, schema, "shop.Order"));
        // Packed on the wire: one length-delimited field 6.
        assertInstanceOf(ProtoValue.Packed.class, m.fields().stream().filter(f -> f.number() == 6).findFirst()
                .orElseThrow().value());
        assertArrayEquals(data, Protobuf.encode(m));
        // Without the schema, the same bytes decode with numbers.
        assertTrue(Protobuf.render(data).startsWith("1: 42  # !sint: 21\n2: Ada\n3:\n  1: A-1\n"));
    }

    @Test
    void unknownAndMismatchedFieldsFallBackToGuessing() throws Exception {
        ProtoSchema schema = tiny();
        Map<Object, Object> fields = new LinkedHashMap<>();
        fields.put(1, 7L);
        fields.put(2, 5L); // customer is a string; a varint does not fit
        fields.put(99, "extra");
        byte[] data = Protobuf.encode(fields);
        assertEquals("id: 7\n2: 5  # !sint: -3\n99: extra\n", Protobuf.decode(data, schema, "shop.Order").render());
        assertThrows(IllegalArgumentException.class, () -> Protobuf.decode(data, schema, "shop.Nope"));
        assertThrows(IllegalArgumentException.class,
                () -> Protobuf.encode(Map.of("status", "LOST"), schema, "shop.Order"));
    }

    @Test
    void grpcViewUsesTheMethodsTypes() throws Exception {
        ContentViews views = ContentViews.defaults().withSchema(tiny());
        byte[] request = Grpc.join(List.of(Protobuf.encode(Map.of(1, 42L))));
        byte[] response = Grpc.join(List.of(Protobuf.encode(Map.of("id", 42L, "status", "PLACED"), views.schema(),
                "shop.Order")));
        HttpHeaders headers = new HttpHeaders().set("content-type", "application/grpc");
        ContentView.Metadata req = new ContentView.Metadata("application/grpc", headers, null, "/shop.Shop/GetOrder", true);
        assertEquals("id: 42\n", views.render(request, req).orElseThrow().text());
        ContentView.Metadata res = new ContentView.Metadata("application/grpc", headers, null, "/shop.Shop/GetOrder", false);
        String text = views.render(response, res).orElseThrow().text();
        assertTrue(text.equals("id: 42\nstatus: PLACED\n") || text.equals("status: PLACED\nid: 42\n"), text);
        // An unknown method decodes without names.
        assertEquals("1: 42  # !sint: 21\n", views.render(request, req.withPath("/shop.Shop/Other")).orElseThrow().text());
    }

    @Test
    void protobufViewTakesTheTypeFromTheContentType() throws Exception {
        ContentViews views = ContentViews.defaults().withSchema(tiny());
        byte[] data = Protobuf.encode(Map.of(1, 42L));
        assertEquals("id: 42\n", views.render(data,
                ContentView.Metadata.of("application/x-protobuf; messageType=shop.GetOrderRequest")).orElseThrow().text());
        assertEquals("1: 42  # !sint: 21\n", views.render(data, ContentView.Metadata.of("application/x-protobuf"))
                .orElseThrow().text());
    }

    /** mitmproxy's captured descriptor set, as protoc wrote it (proto2, no package). */
    @Test
    void protocWrittenDescriptorSet() throws Exception {
        ProtoSchema schema = ProtoSchema.parse(hex(CapturedData.DESCRIPTOR_SET));
        ProtoSchema.MessageType person = schema.message("Person").orElseThrow();
        assertEquals(List.of("name", "id", "email", "phone"), person.fields().stream().map(ProtoSchema.Field::name).toList());
        assertEquals("Person.PhoneNumber", person.field("phone").typeName());
        assertEquals(ProtoSchema.Type.ENUM, schema.message("Person.PhoneNumber").orElseThrow().field("type").type());

        Map<Object, Object> phone = new LinkedHashMap<>();
        phone.put("number", "555-0100");
        phone.put("type", "WORK");
        Map<Object, Object> p = new LinkedHashMap<>();
        p.put("name", "Ada");
        p.put("id", 1L);
        p.put("email", "ada@example.com");
        p.put("phone", List.of(phone));
        byte[] data = Protobuf.encode(p, schema, "Person");
        assertEquals("name: Ada\nid: 1\nemail: ada@example.com\nphone:\n- number: 555-0100\n  type: WORK\n",
                Protobuf.decode(data, schema, "Person").render());
        // Without the schema, "email" happens to parse as a message; text wins, as in mitmproxy_rs.
        assertTrue(Protobuf.render(data).contains("3: ada@example.com\n"));
    }

    @Test
    void loadAndErrors(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("tiny.desc");
        Files.write(file, tinyDescriptorSet());
        assertTrue(ProtoSchema.load(file).message("shop.Order").isPresent());
        Files.write(file, new byte[] {(byte) 0xff});
        assertThrows(IOException.class, () -> ProtoSchema.load(file));
        assertEquals(ProtoSchema.empty().messages().keySet(), ProtoSchema.parse(new byte[0]).messages().keySet());
    }
}
