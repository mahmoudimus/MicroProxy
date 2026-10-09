package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.starlark.ScriptedReadmeTest;

/** The {@code --script} option the Starlark module adds to the launcher. */
class LauncherScriptTest {

    @Test
    void helpListsExtensionOptions() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertNull(Launcher.start(new String[] {"--help"}, new PrintStream(out, true, StandardCharsets.UTF_8)));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("--script <file.star>"), out.toString(StandardCharsets.UTF_8));
    }

    @Test
    void scriptOptionDrivesTheProxy(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("proxy.star");
        Files.writeString(script, """
                def on_request(req, ctx):
                    return response(418, "scripted")
                """);
        HttpServer origin = origin(echo());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--script", script.toString()},
                new PrintStream(out, true, StandardCharsets.UTF_8));
        try {
            HttpResponse<String> response = get(client(proxy), url(origin, "/"));
            assertEquals(418, response.statusCode());
            assertEquals("scripted", response.body());
            assertTrue(out.toString(StandardCharsets.UTF_8).contains("Scripting with"));
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void scriptsWithAuthenticateAuthenticateClients(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("auth.star");
        Files.writeString(script, """
                def authenticate(req, ctx):
                    return req.headers.get("Proxy-Authorization") == "Bearer letmein"
                """);
        HttpServer origin = origin(echo());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--script", script.toString()},
                new PrintStream(out, true, StandardCharsets.UTF_8));
        try {
            assertEquals(407, get(client(proxy), url(origin, "/")).statusCode());
            String accepted = TestSupport.rawExchange(proxy.getListenAddress(), "GET " + url(origin, "/") + " HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\nProxy-Authorization: Bearer letmein\r\nConnection: close\r\n\r\n");
            assertTrue(accepted.startsWith("HTTP/1.1 200"), accepted);
            assertTrue(out.toString(StandardCharsets.UTF_8).contains("authenticate"), out.toString(StandardCharsets.UTF_8));
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void scriptVarsBecomeConstants(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("vars.star");
        Files.writeString(script, """
                def on_request(req, ctx):
                    return response(200, "%s %s %s" % (GREETING, NAME, SECRET))
                """);
        Path file = dir.resolve("vars.properties");
        Files.writeString(file, "NAME=from-file\nSECRET=s3cret value\n");
        HttpServer origin = origin(echo());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--script", script.toString(),
                "--script-var", "NAME=from-flag", "--script-var-file", file.toString(),
                "--script-var", "GREETING=a=b"}, new PrintStream(out, true, StandardCharsets.UTF_8));
        try {
            // Later options win: the file's NAME replaces the flag before it.
            assertEquals("a=b from-file s3cret value", get(client(proxy), url(origin, "/")).body());
            String console = out.toString(StandardCharsets.UTF_8);
            assertTrue(console.contains("Script constants: NAME, SECRET, GREETING"), console);
            assertFalse(console.contains("s3cret"), "values are not printed: " + console);
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void badScriptVarsStopStartup(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("vars.star");
        Files.writeString(script, "def on_request(req, ctx):\n    pass\n");
        for (String var : List.of("len=1", "1A=x", "NOVALUE")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Launcher.start(
                    new String[] {"--port", "0", "--script", script.toString(), "--script-var", var}, System.out));
            assertTrue(e.getMessage().contains("built-in") || e.getMessage().contains("identifier")
                    || e.getMessage().contains("NAME=VALUE"), e.getMessage());
        }
        Path file = dir.resolve("bad.properties");
        Files.writeString(file, "json=shadow\n");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Launcher.start(
                new String[] {"--port", "0", "--script", script.toString(), "--script-var-file", file.toString()},
                System.out));
        assertTrue(e.getMessage().contains("bad.properties") && e.getMessage().contains("json"), e.getMessage());
    }

    @Test
    void readmeBearerExampleFromTheCommandLine(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("auth.star");
        Files.writeString(script, ScriptedReadmeTest.inReadme(ScriptedReadmeTest.BEARER));
        // What the README's shell line writes.
        Path tokens = dir.resolve("tokens.properties");
        Files.writeString(tokens, "TOKENS=alice:" + ScriptedReadmeTest.sha256("alice's token") + "\n");
        HttpServer origin = origin(echo());
        HttpProxyServer proxy = Launcher.start(new String[] {"--port", "0", "--script", script.toString(),
                "--script-var-file", tokens.toString()}, new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
        try {
            String request = "GET " + url(origin, "/") + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
            String accepted = TestSupport.rawExchange(proxy.getListenAddress(),
                    request + "Proxy-Authorization: Bearer alice's token\r\n\r\n");
            assertTrue(accepted.startsWith("HTTP/1.1 200"), accepted);
            String rejected = TestSupport.rawExchange(proxy.getListenAddress(),
                    request + "Proxy-Authorization: Bearer someone else's\r\n\r\n");
            assertTrue(rejected.startsWith("HTTP/1.1 407") && rejected.contains("Bearer realm=\"proxy\""), rejected);
        } finally {
            proxy.abort();
            origin.stop(0);
        }
    }

    @Test
    void brokenScriptsStopStartup(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("bad.star");
        Files.writeString(script, "def on_request(\n");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Launcher.start(new String[] {"--port", "0", "--script", script.toString()}, System.out));
        assertTrue(e.getMessage().contains("bad.star"), e.getMessage());
    }
}
