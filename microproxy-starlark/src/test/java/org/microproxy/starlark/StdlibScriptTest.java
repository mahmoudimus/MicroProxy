package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.starlark.stdlib.Stdlib;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;

/** Scripts that {@code load()} the standard library ported from starlarky. */
class StdlibScriptTest {

    private static StarlarkScript compile(String source) throws ScriptException {
        return StarlarkScript.compile(source, "stdlib.star", StarlarkScript.Limits.DEFAULT);
    }

    private static Object call(String source, String function) throws Exception {
        try (Mutability mu = Mutability.create("test")) {
            return compile(source).call(function, mu);
        }
    }

    private static String loadError(String source) {
        return assertThrows(ScriptException.class, () -> compile(source)).getMessage();
    }

    @Test
    void proxyScriptUsesUrllibAndHashlib() throws Exception {
        HttpServer origin = origin(echo());
        HttpProxyServer proxy = null;
        try {
            ScriptedProxy script = ScriptedProxy.builder("""
                    load("@stdlib//urllib/parse", "parse")
                    load("@stdlib//hashlib", "hashlib")

                    def on_request(req, ctx):
                        query = parse.parse_qs(req.query)
                        if "token" not in query:
                            return response(401, "no token")
                        token = query["token"][0]
                        req.headers["X-Token-Sha256"] = hashlib.sha256(bytes(token)).hexdigest()
                        req.headers["X-Quoted"] = parse.quote(token, safe="")
                    """, "stdlib.star").build();
            proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).start();
            HttpResponse<String> ok = get(client(proxy), url(origin, "/api?token=a%2Fb%20c&x=1"));
            assertEquals(200, ok.statusCode());
            assertEquals(List.of(sha256("a/b c")), echoedHeader(ok.body(), "x-token-sha256"));
            assertEquals(List.of("a%2Fb%20c"), echoedHeader(ok.body(), "x-quoted"));
            assertEquals(401, get(client(proxy), url(origin, "/api")).statusCode());
        } finally {
            if (proxy != null) proxy.abort();
            origin.stop(0);
        }
    }

    private static String sha256(String s) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    @Test
    void typedScriptsLoadModules() throws Exception {
        String source = """
                load("@stdlib//hashlib", "hashlib")
                load("@stdlib//base64", "base64")

                def digest(text: str) -> str:
                    return base64.b64encode(hashlib.sha256(bytes(text)).digest()).decode("ascii")

                def check() -> str:
                    return digest("abc")
                """;
        assertEquals("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=", call(source, "check"));
        // static type checking still applies to the script's own code
        String error = loadError("""
                load("@stdlib//hashlib", "hashlib")

                def digest(text: str) -> int:
                    return hashlib.sha256(bytes(text)).hexdigest()

                def bad() -> int:
                    return digest(1)
                """);
        assertTrue(error.contains("parameter 'text' got value of type 'int', want 'str'"), error);
    }

    @Test
    void loadedNamesShadowPredeclaredBuiltins() throws Exception {
        // @stdlib//json has Python's dumps; the predeclared json does not
        assertEquals("{\"a\":2,\"b\":1}", call("""
                load("@stdlib//json", "json")
                def f():
                    return json.dumps({"b": 1, "a": 2})
                """, "f"));
        // or keep both, under another name
        assertEquals("[1] [1]", call("""
                load("@stdlib//json", py_json="json")
                def f():
                    return py_json.dumps([1]) + " " + json.encode([1])
                """, "f"));
    }

    @Test
    void onlyScriptsThatLoadGetPythonStrings() throws Exception {
        // a script without load() keeps Starlark's semantics exactly
        String error = assertThrows(EvalException.class, () -> call("""
                def f():
                    return "%5d|" % 3
                """, "f")).getMessage();
        assertTrue(error.contains("unsupported format character"), error);
        assertEquals("    3|", call("""
                load("@stdlib//string", "string")
                def f():
                    return "%5d|" % 3
                """, "f"));
    }

    @Test
    void badLoadsAreClearErrors() {
        assertTrue(loadError("load('helpers.star', 'x')").contains("scripts load only the standard library"));
        assertTrue(loadError("load('@stdlib//nope', 'x')").contains("cannot load '@stdlib//nope': no such module"));
        assertTrue(loadError("load('@other//x', 'x')").contains("unknown namespace @other"));
        assertTrue(loadError("load('@stdlib//../vendor/six', 'x')").contains("bad module path"));
        assertTrue(loadError("load('@stdlib//json', 'nope')").contains("does not contain symbol 'nope'"));
    }

    @Test
    void modulesAreLoadedOnceAndFrozen() throws Exception {
        assertSame(Stdlib.loadAll(List.of("@stdlib//re")).get("@stdlib//re"),
                Stdlib.loadAll(List.of("@stdlib//re")).get("@stdlib//re"));
        String error = assertThrows(EvalException.class, () -> call("""
                load("@stdlib//hashlib", "hashlib")
                H = hashlib.sha256()
                def f():
                    H.update(b"x")
                """, "f")).getMessage();
        assertTrue(error.contains("frozen"), error);
    }

    @Test
    void catastrophicRegexStopsAtTheCallDeadline() throws Exception {
        StarlarkScript script = StarlarkScript.compile("""
                load("@stdlib//re", "re")
                def f():
                    return re.match(r"(?:.*a){12}b", "a" * 60)
                """, "re.star", new StarlarkScript.Limits(10_000_000, Duration.ofMillis(300)));
        long started = System.nanoTime();
        try (Mutability mu = Mutability.create("test")) {
            String error = assertThrows(EvalException.class, () -> script.call("f", mu)).getMessage();
            assertTrue(error.contains("ran past the deadline"), error);
        }
        assertTrue(System.nanoTime() - started < Duration.ofSeconds(5).toNanos());
    }
}
