package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
    void brokenScriptsStopStartup(@TempDir Path dir) throws Exception {
        Path script = dir.resolve("bad.star");
        Files.writeString(script, "def on_request(\n");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Launcher.start(new String[] {"--port", "0", "--script", script.toString()}, System.out));
        assertTrue(e.getMessage().contains("bad.star"), e.getMessage());
    }
}
