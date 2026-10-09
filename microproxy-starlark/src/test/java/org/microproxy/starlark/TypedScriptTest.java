package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;

class TypedScriptTest {

    private static StarlarkScript compile(String source) throws ScriptException {
        return StarlarkScript.compile(source, "typed.star", StarlarkScript.Limits.DEFAULT);
    }

    private static String loadError(String source) {
        return assertThrows(ScriptException.class, () -> compile(source)).getMessage();
    }

    @Test
    void annotatedHooksRunThroughTheProxy() throws Exception {
        HttpServer origin = origin(echo());
        HttpProxyServer proxy = null;
        try {
            ScriptedProxy script = ScriptedProxy.builder("""
                    BLOCKED: list[str] = ["/admin"]

                    def tag(req: Request) -> str:
                        return req.method + " " + req.path

                    def on_request(req: Request, ctx: Context) -> Response | None:
                        if req.path in BLOCKED:
                            return response(403, "blocked")
                        headers: Headers = req.headers
                        headers["X-Tag"] = tag(req)
                        return None

                    def on_response(req: Request, resp: Response, ctx: Context) -> None:
                        resp.headers["X-Status"] = str(resp.status)
                        if resp.text != None:
                            text = cast(str, resp.text)  # the checker does not narrow `str | None`
                            resp.text = text.replace("method", "METHOD")
                    """, "typed.star").build();
            proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(script).start();
            HttpResponse<String> ok = get(client(proxy), url(origin, "/hello"));
            assertEquals(List.of("GET /hello"), echoedHeader(ok.body(), "x-tag"));
            assertEquals("200", ok.headers().firstValue("x-status").orElseThrow());
            assertTrue(ok.body().startsWith("METHOD: GET"), ok.body());
            assertEquals(403, get(client(proxy), url(origin, "/admin")).statusCode());
        } finally {
            if (proxy != null) proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void misspeltFieldsFailWhenTheScriptLoads() {
        String error = loadError("""
                def on_request(req: Request, ctx: Context):
                    return req.hots
                """);
        assertTrue(error.contains("'req' of type 'Request' does not have field 'hots'"), error);
        error = loadError("""
                def on_request(req: Request, ctx: Context):
                    req.headers.gte("host")
                """);
        assertTrue(error.contains("does not have field 'gte'"), error);
    }

    @Test
    void wrongTypesFailWhenTheScriptLoads() {
        String error = loadError("""
                def on_request(req: Request, ctx: Context):
                    req.uri = 3
                """);
        assertTrue(error.contains("cannot assign type 'int' to 'req.uri' of type 'str'"), error);
        error = loadError("""
                def on_request(req: Request, ctx: Context) -> str:
                    return ctx.user
                """);
        assertTrue(error.contains("declares return type 'str' but may return 'str | None'"), error);
        error = loadError("""
                def status(resp: Response) -> str:
                    return resp.status
                """);
        assertTrue(error.contains("declares return type 'str' but may return 'int'"), error);
        error = loadError("""
                def on_response(req: Request, resp: Response, ctx: Context):
                    resp.text = resp.text.upper()
                """);
        assertTrue(error.contains("'resp.text' of type 'str | None' does not have field 'upper'"), error);
    }

    @Test
    void argumentsAreCheckedWhenCalled() throws Exception {
        StarlarkScript script = compile("""
                def bump(n: int) -> int:
                    return n + 1
                """);
        try (Mutability mu = Mutability.create("test")) {
            assertEquals(StarlarkInt.of(2), script.call("bump", mu, StarlarkInt.of(1)));
            EvalException e = assertThrows(EvalException.class, () -> script.call("bump", mu, "one"));
            assertTrue(e.getMessage().contains("parameter 'n' got value of type 'str', want 'int'"), e.getMessage());
        }
    }

    @Test
    void unannotatedCodeIsNotChecked() throws Exception {
        compile("""
                def on_request(req, ctx):
                    x = 1
                    x = "now a string"
                    req.headers["X"] = x
                """);
    }
}
