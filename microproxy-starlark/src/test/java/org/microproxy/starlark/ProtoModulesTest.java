package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.contentviews.DecodeException;
import org.microproxy.contentviews.Grpc;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;

/** The {@code protobuf} and {@code grpc} modules. */
class ProtoModulesTest {

    private HttpServer origin;
    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (origin != null) origin.stop(0);
    }

    private static void check(String... lines) throws Exception {
        StringBuilder src = new StringBuilder("def checks():\n");
        for (String line : lines) src.append("    ").append(line).append('\n');
        StarlarkScript.compile(src.toString(), "proto.star", StarlarkScript.Limits.DEFAULT)
                .withProtoSchema(tiny()).call("checks", Mutability.create("test"));
    }

    static ProtoSchema tiny() throws IOException, DecodeException {
        try (InputStream in = ProtoModulesTest.class.getResourceAsStream("/org/microproxy/contentviews/tiny.desc")) {
            return ProtoSchema.parse(in.readAllBytes());
        }
    }

    @Test
    void decodeAndEncodeWithoutASchema() throws Exception {
        check(
                "m = protobuf.decode(b'\\x08\\x96\\x01\\x12\\x05hello\\x2a\\x02\\x08\\x2a')",
                "if m != {1: 150, 2: 'hello', 5: {1: 42}}: fail('decode', m)",
                "m[2] = 'goodbye'",
                "m[5][1] = -1",
                "data = protobuf.encode(m)",
                "if protobuf.decode(data) != {1: 150, 2: 'goodbye', 5: {1: -1}}: fail('round trip', protobuf.decode(data))",
                "if protobuf.encode({1: -1}) != b'\\x08\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x01': fail('negative')",
                "if protobuf.decode(b'\\x08\\x01\\x08\\x02') != {1: [1, 2]}: fail('repeated')",
                "if protobuf.encode({1: [1, 2], 2: True, 3: b'\\xff'}) != b'\\x08\\x01\\x08\\x02\\x10\\x01\\x1a\\x01\\xff': fail('lists')",
                "if protobuf.decode(b'') != {}: fail('empty')",
                "if protobuf.render(b'\\x08\\x96\\x01') != '1: 150  # !sint: 75\\n': fail('render')");
    }

    @Test
    void fixedWidthValuesAndGroups() throws Exception {
        check(
                "m = protobuf.decode(b'\\x15\\x00\\x00\\xc0\\x3f\\x19\\x00\\x00\\x00\\x00\\x00\\x00\\xf0\\xbf')",
                "if m[2].bits != 32 or m[2].float != 1.5 or m[2].value != 1069547520: fail('fixed32', m[2])",
                "if m[3].bits != 64 or m[3].float != -1.0 or m[3].signed >= 0: fail('fixed64', m[3])",
                "if m[2] != protobuf.fixed32(1.5) or m[3] != protobuf.fixed64(-1.0): fail('constructors')",
                "if protobuf.encode(m) != b'\\x15\\x00\\x00\\xc0\\x3f\\x19\\x00\\x00\\x00\\x00\\x00\\x00\\xf0\\xbf': fail('fixed round trip')",
                "if protobuf.fixed32(-1).value != 4294967295: fail('fixed32(-1)')",
                "if repr(protobuf.fixed32(7)) != 'protobuf.fixed32(7)': fail(repr(protobuf.fixed32(7)))",
                "g = protobuf.decode(b'\\x13\\x18\\x80\\x1e\\x20\\xf0\\x10\\x14')[2]",
                "if g.fields != {3: 3840, 4: 2160}: fail('group', g)",
                "if protobuf.encode({2: g}) != b'\\x13\\x18\\x80\\x1e\\x20\\xf0\\x10\\x14': fail('group round trip')",
                "if protobuf.encode({1: protobuf.group({2: 1})}) != b'\\x0b\\x10\\x01\\x0c': fail('group()')");
    }

    @Test
    void helpers() throws Exception {
        check(
                "if protobuf.unpack(protobuf.pack([3, 270, 86942])) != [3, 270, 86942]: fail('pack')",
                "if protobuf.pack([3, 270, 86942]) != b'\\x03\\x8e\\x02\\x9e\\xa7\\x05': fail('pack bytes')",
                "if protobuf.zigzag_decode(3) != -2 or protobuf.zigzag_encode(-2) != 3: fail('zigzag')",
                "if protobuf.zigzag_encode(-9223372036854775808) != 18446744073709551615: fail('zigzag max')",
                "if grpc.code_name(3) != 'INVALID_ARGUMENT' or grpc.code_name(99) != None: fail('code_name')");
    }

    @Test
    void errorsAreScriptErrors() throws Exception {
        for (String bad : List.of("protobuf.decode(b'\\xff\\xff')", "protobuf.encode({'name': 1})",
                "protobuf.encode({1: {}.get})", "protobuf.fixed32(1 << 40)", "protobuf.decode('text')",
                "grpc.messages(b'\\x00\\x00\\x00\\x00\\x09')", "grpc.status('!!')",
                "protobuf.decode(b'', type='shop.Missing')", "grpc.frame([b'x'], encoding='snappy')")) {
            EvalException e = assertThrows(EvalException.class, () -> check(bad), bad);
            assertTrue(!e.getMessage().isEmpty());
        }
        EvalException e = assertThrows(EvalException.class, () -> check("protobuf.decode(b'\\xff\\xff')"));
        assertTrue(e.getMessage().contains("protobuf.decode: invalid protobuf"), e.getMessage());
    }

    @Test
    void grpcFramingAndStatus() throws Exception {
        check(
                "body = grpc.frame([protobuf.encode({1: 'a'}), protobuf.encode({1: 'b'})])",
                "if body != b'\\x00\\x00\\x00\\x00\\x03\\x0a\\x01a\\x00\\x00\\x00\\x00\\x03\\x0a\\x01b': fail('frame', body)",
                "if grpc.messages(body) != [b'\\x0a\\x01a', b'\\x0a\\x01b']: fail('messages')",
                "if grpc.decode(body) != [{1: 'a'}, {1: 'b'}]: fail('decode')",
                "zipped = grpc.encode([{1: 'a'}], encoding='gzip')",
                "if zipped[0] != 1 or grpc.decode(zipped, encoding='gzip') != [{1: 'a'}]: fail('gzip')",
                "details = grpc.status_details(5, 'missing', details=[{'type_url': 'type.googleapis.com/google.rpc.ErrorInfo',"
                        + " 'value': {1: 'NOT_FOUND'}}])",
                "st = grpc.status(details)",
                "if st['code'] != 5 or st['name'] != 'NOT_FOUND' or st['message'] != 'missing': fail('status', st)",
                "if protobuf.decode(st['details'][0]['value']) != {1: 'NOT_FOUND'}: fail('detail', st)",
                "if st['details'][0]['type_url'] != 'type.googleapis.com/google.rpc.ErrorInfo': fail('type_url')");
        String details = new Grpc.Status(5, "missing", List.of()).toTrailer();
        check("if grpc.status('" + details + "')['message'] != 'missing': fail('from Java')");
    }

    @Test
    void namedFieldsWithASchema() throws Exception {
        check(
                "order = {'id': 42, 'customer': 'Ada', 'status': 'SHIPPED', 'delta': -3, 'codes': [1, 2],"
                        + " 'labels': {'gift': 'yes'}, 'total': 7.5, 'items': [{'sku': 'A-1', 'quantity': 2}]}",
                "data = protobuf.encode(order, type='shop.Order')",
                "back = protobuf.decode(data, type='shop.Order')",
                "if back['status'] != 'SHIPPED' or back['delta'] != -3 or back['codes'] != [1, 2]: fail(back)",
                "if back['labels'] != {'gift': 'yes'} or back['items'][0]['sku'] != 'A-1': fail(back)",
                "if back['total'] != 7.5: fail(back)",
                "if protobuf.encode(back, type='shop.Order') != data: fail('round trip')",
                "if protobuf.decode(data)[1] != 42: fail('without the type, numbers')",
                "body = grpc.encode([order], type='shop.Order')",
                "if grpc.decode(body, type='shop.Order')[0]['customer'] != 'Ada': fail('grpc with a type')",
                "if 'id: 42' not in protobuf.render(data, type='shop.Order'): fail('render')");
        ProtoSchema schema = tiny();
        ScriptedProxy proxy = ScriptedProxy.builder("def f():\n    return protobuf.decode(b'\\x08\\x05', type='shop.Order')\n",
                "schema.star").protoSchema(schema).build();
        assertEquals(schema, proxy.script().protoSchema());
        assertEquals("{\"id\": 5}", proxy.script().call("f", Mutability.create("t")).toString());
    }

    @Test
    void typedScriptsSeeTheModules() throws Exception {
        StarlarkScript s = StarlarkScript.compile("""
                def bump(n: int) -> int:
                    m = protobuf.decode(protobuf.encode({1: n}))
                    f: ProtoFixed = protobuf.fixed32(2)
                    return m[1] + f.value

                def rewrite(res: Response) -> None:
                    m = protobuf.decode(res.body)
                    m[1] = m[1] + 1
                    res.body = protobuf.encode(m)
                """, "typed.star", StarlarkScript.Limits.DEFAULT);
        assertEquals(StarlarkInt.of(3), s.call("bump", Mutability.create("t"), StarlarkInt.of(1)));
        ScriptResponse res = new ScriptResponse(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                new byte[] {8, 1}), false);
        s.call("rewrite", Mutability.create("t"), res);
        assertArrayEquals(new byte[] {8, 2}, ((StarlarkBytes) res.getValue("body")).toByteArray());

        ScriptException e = assertThrows(ScriptException.class, () -> StarlarkScript.compile("""
                def f() -> str:
                    return protobuf.encode({1: 1})
                """, "typed.star", StarlarkScript.Limits.DEFAULT));
        assertTrue(e.getMessage().contains("bytes"), e.getMessage());
        e = assertThrows(ScriptException.class, () -> StarlarkScript.compile("""
                def g() -> int:
                    return protobuf.fixed32(1)
                """, "typed.star", StarlarkScript.Limits.DEFAULT));
        assertTrue(e.getMessage().contains("ProtoFixed"), e.getMessage());
    }

    /** The README's example. */
    static final String GRPC_REWRITE = """
            def buffer_response(req, res, ctx):
                return res.headers.get("content-type", "").startswith("application/grpc")

            def on_response(req, res, ctx):
                if res.body == None:
                    return None
                encoding = res.headers.get("grpc-encoding")
                messages = grpc.decode(res.body, encoding=encoding)
                for m in messages:
                    m[1] = m[1].upper()
                    m[2] = m[2] + 41
                res.body = grpc.encode(messages, encoding=encoding)
                return None
            """;

    /** A script that rewrites a gRPC response's messages, through the proxy: the README's example. */
    @Test
    void onResponseRewritesGrpcMessages() throws Exception {
        byte[] body = Grpc.join(List.of(Protobuf.encode(Map.of(1, "hello", 2, 1L))), "gzip");
        origin = origin(exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/grpc");
            exchange.getResponseHeaders().set("grpc-encoding", "gzip");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        ScriptedProxy script = ScriptedProxy.builder(ScriptedReadmeTest.inReadme(GRPC_REWRITE), "grpc.star").build();
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).start();
        HttpResponse<byte[]> response = client(proxy).send(HttpRequest.newBuilder(URI.create(url(origin, "/pkg.Svc/Get")))
                        .timeout(Duration.ofSeconds(20)).POST(HttpRequest.BodyPublishers.ofByteArray(Grpc.join(List.of())))
                        .build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());
        List<byte[]> messages = Grpc.messages(response.body(), "gzip");
        assertEquals(Map.of(1, "HELLO", 2, 42L), Protobuf.decode(messages.getFirst()).toPlain());
    }
}
