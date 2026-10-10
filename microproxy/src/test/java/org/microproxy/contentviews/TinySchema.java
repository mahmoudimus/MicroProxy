package org.microproxy.contentviews;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds the checked-in {@code tiny.desc}, a {@code FileDescriptorSet} encoded with {@link
 * Protobuf#encode(Map)} rather than protoc. It describes:
 *
 * <pre>
 * syntax = "proto3";
 * package shop;
 *
 * message Order {
 *   message Item { string sku = 1; uint32 quantity = 2; float price = 3; }
 *   enum Status { UNKNOWN = 0; PLACED = 1; SHIPPED = 2; }
 *   int64 id = 1;
 *   string customer = 2;
 *   repeated Item items = 3;
 *   Status status = 4;
 *   sint32 delta = 5;
 *   repeated int32 codes = 6;
 *   map&lt;string, string&gt; labels = 7;
 *   double total = 8;
 *   bool paid = 9;
 *   fixed32 checksum = 10;
 *   bytes blob = 11;
 * }
 * message GetOrderRequest { int64 id = 1; }
 * service Shop {
 *   rpc GetOrder(GetOrderRequest) returns (Order);
 *   rpc Watch(GetOrderRequest) returns (stream Order);
 * }
 * </pre>
 */
final class TinySchema {

    private TinySchema() {}

    // FieldDescriptorProto.Label and .Type numbers.
    private static final int OPTIONAL = 1;
    private static final int REPEATED = 3;
    private static final int DOUBLE = 1;
    private static final int FLOAT = 2;
    private static final int INT64 = 3;
    private static final int INT32 = 5;
    private static final int FIXED32 = 7;
    private static final int BOOL = 8;
    private static final int STRING = 9;
    private static final int MESSAGE = 11;
    private static final int BYTES = 12;
    private static final int UINT32 = 13;
    private static final int ENUM = 14;
    private static final int SINT32 = 17;

    static byte[] bytes() {
        Map<Object, Object> item = message("Item",
                field("sku", 1, OPTIONAL, STRING, null),
                field("quantity", 2, OPTIONAL, UINT32, null),
                field("price", 3, OPTIONAL, FLOAT, null));
        Map<Object, Object> labelsEntry = message("LabelsEntry",
                field("key", 1, OPTIONAL, STRING, null),
                field("value", 2, OPTIONAL, STRING, null));
        labelsEntry.put(7, map(7, true)); // MessageOptions.map_entry
        Map<Object, Object> status = map(1, "Status");
        status.put(2, List.of(map(1, "UNKNOWN", 2, 0L), map(1, "PLACED", 2, 1L), map(1, "SHIPPED", 2, 2L)));
        Map<Object, Object> order = message("Order",
                field("id", 1, OPTIONAL, INT64, null),
                field("customer", 2, OPTIONAL, STRING, null),
                field("items", 3, REPEATED, MESSAGE, ".shop.Order.Item"),
                field("status", 4, OPTIONAL, ENUM, ".shop.Order.Status"),
                field("delta", 5, OPTIONAL, SINT32, null),
                field("codes", 6, REPEATED, INT32, null),
                field("labels", 7, REPEATED, MESSAGE, ".shop.Order.LabelsEntry"),
                field("total", 8, OPTIONAL, DOUBLE, null),
                field("paid", 9, OPTIONAL, BOOL, null),
                field("checksum", 10, OPTIONAL, FIXED32, null),
                field("blob", 11, OPTIONAL, BYTES, null));
        order.put(3, List.of(item, labelsEntry)); // nested_type
        order.put(4, List.of(status)); // enum_type
        Map<Object, Object> request = message("GetOrderRequest", field("id", 1, OPTIONAL, INT64, null));
        Map<Object, Object> service = map(1, "Shop");
        service.put(2, List.of(
                map(1, "GetOrder", 2, ".shop.GetOrderRequest", 3, ".shop.Order"),
                map(1, "Watch", 2, ".shop.GetOrderRequest", 3, ".shop.Order", 6, true)));
        Map<Object, Object> file = map(1, "shop.proto", 2, "shop");
        file.put(4, List.of(order, request));
        file.put(6, List.of(service));
        file.put(12, "proto3");
        return Protobuf.encode(map(1, List.of(file)));
    }

    private static Map<Object, Object> message(String name, Map<?, ?>... fields) {
        Map<Object, Object> m = map(1, name);
        m.put(2, List.of(fields));
        return m;
    }

    private static Map<Object, Object> field(String name, int number, int label, int type, String typeName) {
        Map<Object, Object> f = map(1, name, 3, (long) number, 4, (long) label, 5, (long) type);
        if (typeName != null) f.put(6, typeName);
        return f;
    }

    private static Map<Object, Object> map(Object... keysAndValues) {
        Map<Object, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) m.put(keysAndValues[i], keysAndValues[i + 1]);
        return m;
    }
}
