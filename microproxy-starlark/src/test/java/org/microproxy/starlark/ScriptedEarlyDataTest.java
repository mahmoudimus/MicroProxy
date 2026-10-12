package org.microproxy.starlark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;

/**
 * {@code ctx.early_data}: whether an HTTP/3 request arrived as 0-RTT early data, which a hook may
 * answer {@code 425} (Too Early) for its client to send again after the handshake.
 */
class ScriptedEarlyDataTest {

    private static FlowContext flow(boolean earlyData) {
        return new FlowContext(1, () -> new InetSocketAddress("127.0.0.1", 5000), () -> null, new ClientDetails()) {
            @Override
            public boolean isEarlyData() {
                return earlyData;
            }
        };
    }

    @Test
    void hooksSeeEarlyData() throws Exception {
        StarlarkScript script = StarlarkScript.compile("""
                def too_early(ctx: Context, method: str) -> int | None:
                    early: bool = ctx.early_data
                    if early and method not in ("GET", "HEAD"):
                        return 425
                    return None
                """, "early.star", StarlarkScript.Limits.DEFAULT);
        try (Mutability mu = Mutability.create("test")) {
            assertEquals(425, ((Number) toJava(script.call("too_early", mu, new ScriptContext(flow(true), mu), "POST")))
                    .intValue());
            assertEquals(Starlark.NONE,
                    script.call("too_early", mu, new ScriptContext(flow(true), mu), "GET"));
            assertEquals(Starlark.NONE,
                    script.call("too_early", mu, new ScriptContext(flow(false), mu), "POST"));
            assertEquals(false, new ScriptContext(null, null, -1, false, mu).getValue("early_data"),
                    "no flow, no early data");
        }
    }

    @Test
    void theReadmeExampleCompiles() throws Exception {
        String example = """
                def on_request(req, ctx):
                    if ctx.early_data and "/checkout" in req.uri:
                        return response(425, "too early\\n")
                """;
        StarlarkScript.compile(example, "readme.star", StarlarkScript.Limits.DEFAULT);
        String text = ScriptedReadmeTest.docsText();
        String indented = example.lines().map(l -> "  " + l).collect(Collectors.joining("\n"));
        assertTrue(text.contains(indented), "the docs do not show:\n" + indented);
    }

    private static Object toJava(Object starlark) {
        return starlark instanceof StarlarkInt i ? i.toIntUnchecked() : starlark;
    }
}
