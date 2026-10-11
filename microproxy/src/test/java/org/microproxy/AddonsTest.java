package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.extras.AntiCache;
import org.microproxy.extras.BlockList;
import org.microproxy.extras.FlowFilter;
import org.microproxy.extras.MapLocal;
import org.microproxy.extras.MapRemote;
import org.microproxy.extras.ModifyBody;
import org.microproxy.extras.ModifyHeaders;
import org.microproxy.extras.StickyCookie;

/** The mitmproxy-style addons, each through a running proxy. */
class AddonsTest {

    private HttpServer origin;
    private HttpServer other;
    private HttpProxyServer proxy;
    private final AtomicInteger originHits = new AtomicInteger();

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(exchange -> {
            originHits.incrementAndGet();
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/page") || path.equals("/gzip")) {
                exchange.getRequestBody().readAllBytes();
                byte[] body = "<p>Example Domain, example text</p>".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                exchange.getResponseHeaders().set("Server", "origin");
                if (path.equals("/gzip")) {
                    body = HttpBodiesTest.gzip(body);
                    exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                }
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
                return;
            }
            if (path.startsWith("/login")) {
                exchange.getRequestBody().readAllBytes();
                exchange.getResponseHeaders().add("Set-Cookie", "session=abc123; Path=/; HttpOnly");
                exchange.getResponseHeaders().add("Set-Cookie", "scoped=1; Path=/api");
                exchange.getResponseHeaders().add("Set-Cookie", "gone=1; Max-Age=0");
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            exchange.getResponseHeaders().set("Server", "origin");
            echo().handle(exchange);
        });
        other = TestSupport.origin(exchange -> {
            exchange.getResponseHeaders().set("X-Other", "yes");
            echo().handle(exchange);
        });
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
        other.stop(0);
    }

    private HttpClient start(HttpFiltersSource... addons) {
        proxy = MicroProxy.bootstrap().withPort(0).withFiltersSource(HttpFiltersChain.of(addons)).start();
        return client(proxy);
    }

    private static String authority(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    // -------------------------------------------------------------------------------------------
    // map_remote
    // -------------------------------------------------------------------------------------------

    @Test
    void mapRemoteSendsRequestsToAnotherServer() {
        HttpClient client = start(MapRemote.of(
                "|http://" + authority(origin).replace(".", "\\.") + "/v1/(\\w+)|http://" + authority(other) + "/v2/\\1"));
        HttpResponse<String> mapped = get(client, url(origin, "/v1/items?x=1"));
        assertEquals("yes", mapped.headers().firstValue("X-Other").orElseThrow());
        assertEquals("/v2/items?x=1", echoedUri(mapped.body()));
        assertEquals(List.of(authority(other)), echoedHeader(mapped.body(), "Host"));
        // Not matched: goes where it was going.
        HttpResponse<String> unmapped = get(client, url(origin, "/v3/items"));
        assertTrue(unmapped.headers().firstValue("X-Other").isEmpty());
    }

    @Test
    void mapRemoteRulesTakeFiltersAndApplyInOrder() {
        HttpClient client = start(MapRemote.builder()
                .add("|~m POST|/form|/posted")
                .add("|/posted|/posted-again")
                .build());
        HttpResponse<String> post = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/form")))
                .POST(HttpRequest.BodyPublishers.ofString("a=1")).build());
        assertEquals("/posted-again", echoedUri(post.body()));
        assertEquals("/form", echoedUri(get(client, url(origin, "/form")).body()), "the filter keeps GETs out");
    }

    @Test
    void mapRemoteFiltersOnRequestBodiesBufferOnlyWhenTheHeadAllows() {
        HttpClient client = start(MapRemote.of("|~m POST & ~bq secret|/in|/hidden"));
        assertEquals("/hidden", echoedUri(send(client, HttpRequest.newBuilder(URI.create(url(origin, "/in")))
                .POST(HttpRequest.BodyPublishers.ofString("the secret word")).build()).body()));
        HttpResponse<String> plain = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/in")))
                .POST(HttpRequest.BodyPublishers.ofString("nothing here")).build());
        assertEquals("/in", echoedUri(plain.body()));
        assertEquals("nothing here", echoedBody(plain.body()));
    }

    // -------------------------------------------------------------------------------------------
    // map_local
    // -------------------------------------------------------------------------------------------

    @Test
    void mapLocalServesFilesAndDirectories(@TempDir Path dir) throws IOException {
        Path site = Files.createDirectories(dir.resolve("site"));
        Files.writeString(site.resolve("index.html"), "<h1>home</h1>");
        Files.createDirectories(site.resolve("css"));
        Files.writeString(site.resolve("css/app.css"), "body{}");
        Files.createDirectories(site.resolve("docs"));
        Files.writeString(site.resolve("docs/index.html"), "docs index");
        Files.writeString(site.resolve("my file.txt"), "spaced");
        Files.writeString(dir.resolve("secret.txt"), "outside");
        Path icon = Files.writeString(dir.resolve("favicon.ico"), "icon");
        Files.createSymbolicLink(site.resolve("escape.txt"), dir.resolve("secret.txt"));

        HttpClient client = start(MapLocal.of("|/static/|" + site, "|~m GET|favicon\\.ico$|" + icon));
        HttpResponse<String> index = get(client, url(origin, "/static/"));
        assertEquals("<h1>home</h1>", index.body());
        assertEquals("text/html", index.headers().firstValue("Content-Type").orElseThrow());
        HttpResponse<String> css = get(client, url(origin, "/static/css/app.css?v=3"));
        assertEquals("body{}", css.body());
        assertEquals("text/css", css.headers().firstValue("Content-Type").orElseThrow());
        assertEquals("docs index", get(client, url(origin, "/static/docs")).body());
        assertEquals("spaced", get(client, url(origin, "/static/my%20file.txt")).body());
        assertEquals("icon", get(client, url(origin, "/anything/favicon.ico")).body());
        assertEquals(0, originHits.get());

        assertEquals(404, get(client, url(origin, "/static/missing.js")).statusCode());
        // Traversal, encoded so the client does not normalize it away, and a link pointing out.
        assertEquals(404, get(client, url(origin, "/static/%2e%2e/secret.txt")).statusCode());
        assertEquals(404, get(client, url(origin, "/static/css/%2E%2E%2F..%2Fsecret.txt")).statusCode());
        assertEquals(404, get(client, url(origin, "/static/escape.txt")).statusCode());
        assertEquals(0, originHits.get());

        // Not matched: the server answers.
        assertEquals(200, get(client, url(origin, "/elsewhere")).statusCode());
        assertEquals(1, originHits.get());
    }

    @Test
    void mapLocalRejectsMissingPaths() {
        assertThrows(IllegalArgumentException.class, () -> MapLocal.of("|x|/no/such/path/anywhere"));
    }

    // -------------------------------------------------------------------------------------------
    // block_list
    // -------------------------------------------------------------------------------------------

    @Test
    void blockListAnswersOrDrops() throws IOException {
        HttpClient client = start(BlockList.of("|~u /ads/|403", "|!/allowed & ~u /drop/|444"));
        HttpResponse<String> blocked = get(client, url(origin, "/ads/banner.js"));
        assertEquals(403, blocked.statusCode());
        assertEquals("", blocked.body());
        assertEquals(0, originHits.get());

        // 444: the connection closes without any response.
        String raw = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET " + url(origin, "/drop/x") + " HTTP/1.1\r\nHost: " + authority(origin) + "\r\n\r\n");
        assertEquals("", raw);
        assertEquals(0, originHits.get());
        assertEquals(200, get(client, url(origin, "/drop/allowed")).statusCode());
    }

    @Test
    void blockListSpecsAreValidated() {
        assertThrows(IllegalArgumentException.class, () -> BlockList.of("|~d x"));
        assertThrows(IllegalArgumentException.class, () -> BlockList.of("|~d x|abc"));
        assertThrows(IllegalArgumentException.class, () -> BlockList.of("|~d x|42"));
        assertThrows(IllegalArgumentException.class, () -> BlockList.of("|~zz|404"));
    }

    // -------------------------------------------------------------------------------------------
    // anticache
    // -------------------------------------------------------------------------------------------

    @Test
    void antiCacheRemovesConditionalHeaders() {
        HttpClient client = start(AntiCache.create());
        HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/c")))
                .header("If-None-Match", "\"abc\"").header("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT")
                .header("X-Kept", "1").build());
        assertTrue(echoedHeader(response.body(), "If-None-Match").isEmpty());
        assertTrue(echoedHeader(response.body(), "If-Modified-Since").isEmpty());
        assertEquals(List.of("1"), echoedHeader(response.body(), "X-Kept"));
    }

    // -------------------------------------------------------------------------------------------
    // modify_headers
    // -------------------------------------------------------------------------------------------

    @Test
    void modifyHeadersSetsAndRemoves(@TempDir Path dir) throws IOException {
        Path token = Files.writeString(dir.resolve("token"), "from-file");
        HttpClient client = start(ModifyHeaders.of(
                "|~q|User-Agent|MicroProxy\\x21",
                "|~s|Server|",
                "|~q & ~u /token|Authorization|@" + token,
                "|X-Both|yes"));
        HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/token")))
                .header("User-Agent", "curl/8").build());
        assertEquals(List.of("MicroProxy!"), echoedHeader(response.body(), "User-Agent"));
        assertEquals(List.of("from-file"), echoedHeader(response.body(), "Authorization"));
        assertEquals(List.of("yes"), echoedHeader(response.body(), "X-Both"), "requests get it");
        assertEquals("yes", response.headers().firstValue("X-Both").orElseThrow(), "and responses");
        assertTrue(response.headers().firstValue("Server").isEmpty());
        assertTrue(echoedHeader(get(client, url(origin, "/plain")).body(), "Authorization").isEmpty());
    }

    // -------------------------------------------------------------------------------------------
    // modify_body
    // -------------------------------------------------------------------------------------------

    @Test
    void modifyBodyEditsResponsesIncludingEncodedOnes() throws IOException {
        HttpClient client = start(ModifyBody.of("|~s & ~t html|Example (\\w+)|Rewritten $1"));
        assertEquals("<p>Rewritten $1, example text</p>", get(client, url(origin, "/page")).body(),
                "the replacement is literal");
        HttpResponse<byte[]> gzipped = sendWith(client, HttpRequest.newBuilder(URI.create(url(origin, "/gzip"))).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals("gzip", gzipped.headers().firstValue("Content-Encoding").orElseThrow());
        String text = new String(new GZIPInputStream(new ByteArrayInputStream(gzipped.body())).readAllBytes(),
                StandardCharsets.UTF_8);
        assertEquals("<p>Rewritten $1, example text</p>", text);
    }

    @Test
    void modifyBodyEditsRequestsAndLeavesOtherFlowsAlone() {
        HttpClient client = start(ModifyBody.of("|~q & ~m POST|\"debug\":\\s*false|\"debug\":true",
                "|~bs nothing-like-this|.|X"));
        HttpResponse<String> response = send(client, HttpRequest.newBuilder(URI.create(url(origin, "/api")))
                .POST(HttpRequest.BodyPublishers.ofString("{\"debug\": false}")).build());
        assertEquals("{\"debug\":true}", echoedBody(response.body()));
        // The second rule's filter does not match this response: unchanged.
        assertEquals("<p>Example Domain, example text</p>", get(client, url(origin, "/page")).body());
    }

    private static <T> HttpResponse<T> sendWith(HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        try {
            return client.send(request, handler);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // -------------------------------------------------------------------------------------------
    // stickycookie
    // -------------------------------------------------------------------------------------------

    @Test
    void stickyCookiesCarryOverToOtherClients() {
        StickyCookie sticky = StickyCookie.of("~d 127.0.0.1");
        HttpClient first = start(sticky);
        assertEquals(204, get(first, url(origin, "/login")).statusCode());
        // Another client, without a cookie jar of its own.
        HttpClient second = client(proxy);
        HttpResponse<String> api = get(second, url(origin, "/api/me"));
        String cookie = String.join("; ", echoedHeader(api.body(), "Cookie"));
        assertTrue(cookie.contains("session=abc123"), cookie);
        assertTrue(cookie.contains("scoped=1"), cookie);
        assertFalse(cookie.contains("gone"), cookie);
        String root = String.join("; ", echoedHeader(get(second, url(origin, "/home")).body(), "Cookie"));
        assertEquals("session=abc123", root, "a /api cookie stays on /api");
        assertTrue(cookie.indexOf("scoped") < cookie.indexOf("session"), "longer paths first");
    }

    @Test
    void addonsComposeWithFilterExpressions() {
        HttpClient client = start(
                BlockList.of("|~u /blocked|404"),
                MapRemote.of("|~d 127\\.0\\.0\\.1 & ~u /moved|/moved|/arrived"),
                ModifyHeaders.of("|~q|X-Chain|1"));
        assertEquals(404, get(client, url(origin, "/blocked")).statusCode());
        HttpResponse<String> moved = get(client, url(origin, "/moved"));
        assertEquals("/arrived", echoedUri(moved.body()));
        assertEquals(List.of("1"), echoedHeader(moved.body(), "X-Chain"));
        assertTrue(FlowFilter.parse("~u /moved").matches(FlowFilter.flow(
                new org.microproxy.http.DefaultHttpRequest(org.microproxy.http.HttpVersion.HTTP_1_1,
                        org.microproxy.http.HttpMethod.GET, "/moved"), "http://x/moved", null)));
    }
}
