package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;

/** Read-only globals injected with {@link ScriptedProxy.Builder#constants}. */
class ScriptConstantsTest {

    private static Map<String, Object> sample() {
        Map<String, Object> constants = new LinkedHashMap<>();
        constants.put("HOST", "example.com");
        constants.put("LIMIT", 3);
        constants.put("BIG", BigInteger.TWO.pow(70));
        constants.put("LONG", 5_000_000_000L);
        constants.put("ON", true);
        constants.put("HOSTS", List.of("a.example", "b.example"));
        constants.put("LIMITS", Map.of("a.example", 1));
        constants.put("NESTED", Map.of("users", List.of(Map.of("name", "alice", "admin", true))));
        return constants;
    }

    private static StarlarkScript compile(String source, Map<String, ?> constants) throws ScriptException {
        return StarlarkScript.compile(source, "constants.star", StarlarkScript.Limits.DEFAULT, constants);
    }

    @Test
    void valuesReachTheScript() throws Exception {
        HttpServer origin = origin(echo());
        HttpProxyServer proxy = null;
        try {
            ScriptedProxy script = ScriptedProxy.builder("""
                    def on_request(req, ctx):
                        return response(200, json.encode([HOST, LIMIT, BIG, LONG, ON, HOSTS, LIMITS, NESTED]))
                    """, "constants.star").constants(sample()).build();
            proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).start();
            assertEquals("[\"example.com\",3,1180591620717411303424,5000000000,true,[\"a.example\",\"b.example\"],"
                            + "{\"a.example\":1},{\"users\":[{\"admin\":true,\"name\":\"alice\"}]}]",
                    get(client(proxy), url(origin, "/")).body());
        } finally {
            if (proxy != null) proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void theTypeCheckerKnowsTheirTypes() throws Exception {
        compile("""
                def hosts() -> list[str]:
                    return HOSTS

                def limit(host: str) -> int:
                    n: int = LIMITS.get(host, LIMIT)
                    return n

                def enabled() -> bool:
                    return ON
                """, sample());
        String error = assertThrows(ScriptException.class, () -> compile("""
                def port() -> int:
                    return HOST
                """, sample())).getMessage();
        assertTrue(error.contains("declares return type 'int' but may return 'str'"), error);
    }

    @Test
    void theyCannotBeChanged() throws Exception {
        StarlarkScript script = compile("""
                def append():
                    HOSTS.append("evil.example")

                def put():
                    LIMITS["evil.example"] = 100

                def nested():
                    NESTED["users"][0]["admin"] = False
                """, sample());
        try (Mutability mu = Mutability.create("test")) {
            for (String f : List.of("append", "put", "nested")) {
                EvalException e = assertThrows(EvalException.class, () -> script.call(f, mu));
                assertTrue(e.getMessage().contains("frozen") || e.getMessage().contains("immutable"), e.getMessage());
            }
        }
        String error = assertThrows(ScriptException.class, () -> compile("HOST = 'other.example'\n", sample()))
                .getMessage();
        assertTrue(error.contains("HOST is a script constant"), error);
    }

    @Test
    void javaCollectionsAreCopied() throws Exception {
        List<String> hosts = new ArrayList<>(List.of("a.example"));
        StarlarkScript script = compile("def hosts():\n    return len(HOSTS)\n", Map.of("HOSTS", hosts));
        hosts.add("b.example");
        try (Mutability mu = Mutability.create("test")) {
            assertEquals(StarlarkInt.of(1), script.call("hosts", mu));
        }
    }

    @Test
    void badNamesAndValuesAreRejected() {
        for (String name : List.of("len", "json", "response", "Request", "Failure", "True", "None", "list", "Any",
                "1abc", "a-b", "", "def", "lambda")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> ScriptedProxy.builder("", "x.star").constants(Map.of(name, "v")), name);
            assertTrue(e.getMessage().contains("would hide the built-in") || e.getMessage().contains("not a valid identifier"),
                    e.getMessage());
        }
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ScriptedProxy.builder("", "x.star").constants(Map.of("RATE", 1.5)));
        assertTrue(e.getMessage().contains("RATE is a java.lang.Double; constants are strings, ints, bools"), e.getMessage());
        e = assertThrows(IllegalArgumentException.class,
                () -> ScriptedProxy.builder("", "x.star").constants(Map.of("HOSTS", List.of("a", new Object()))));
        assertTrue(e.getMessage().contains("HOSTS[1] is a java.lang.Object"), e.getMessage());
        Map<String, Object> withNull = new HashMap<>();
        withNull.put("MISSING", null);
        e = assertThrows(IllegalArgumentException.class, () -> ScriptedProxy.builder("", "x.star").constants(withNull));
        assertTrue(e.getMessage().contains("MISSING is a null"), e.getMessage());
        e = assertThrows(IllegalArgumentException.class,
                () -> ScriptedProxy.builder("", "x.star").constants(Map.of("BY_LIST", Map.of(List.of(1), "x"))));
        assertTrue(e.getMessage().contains("BY_LIST key is a"), e.getMessage());
    }

    @Test
    void laterConstantsReplaceEarlierOnes() throws Exception {
        ScriptedProxy script = ScriptedProxy.builder("def name():\n    return NAME + '/' + OTHER\n", "x.star")
                .constants(Map.of("NAME", "first", "OTHER", "kept"))
                .constants(Map.of("NAME", "second"))
                .build();
        try (Mutability mu = Mutability.create("test")) {
            assertEquals("second/kept", script.script().call("name", mu));
        }
    }

    @Test
    void scriptsUsingAMissingConstantDoNotLoad() {
        String error = assertThrows(ScriptException.class, () -> compile("def f():\n    return TOKEN\n", Map.of()))
                .getMessage();
        assertTrue(error.contains("TOKEN"), error);
    }
}
