package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.socks;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedBody;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.send;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * SOCKS4a and SOCKS5 chained proxies: GET, POST and CONNECT through them, SOCKS5 with and without
 * authentication, and MITM over SOCKS.
 *
 * <p>LittleProxy: Socks4ChainedProxyTest, Socks5ChainedProxyTest (via BaseChainedSocksProxyTest and
 * BaseProxyTest), Socks5ChainedProxyAuthenticationTest.
 */
class SocksChainedProxyTest {

    private static CertificateAuthority originCa;
    private static HttpServer origin;
    private static HttpsServer secureOrigin;

    private final ChainTestSupport.Proxies proxies = new ChainTestSupport.Proxies();
    private SocksServer socksServer;

    @BeforeAll
    static void startOrigins() {
        originCa = CertificateAuthority.generate("SOCKS Origin CA");
        origin = TestSupport.origin(echo());
        secureOrigin = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
    }

    @AfterAll
    static void stopOrigins() {
        origin.stop(0);
        secureOrigin.stop(0);
    }

    @AfterEach
    void tearDown() throws Exception {
        proxies.close();
        if (socksServer != null) socksServer.close();
        for (Socket r : refusing) r.close();
    }

    /** Reserved until the test ends, so a server started meanwhile cannot be given the same port. */
    private final List<Socket> refusing = new ArrayList<>();

    /** A loopback port that refuses connections, reserved until the test ends. */
    private int closedPort() {
        Socket s = TestSupport.refusingPort();
        refusing.add(s);
        return s.getLocalPort();
    }

    private HttpProxyServer viaSocks(ChainedProxyType type, String user, String password) throws Exception {
        socksServer = new SocksServer(user, password);
        return proxies.start(MicroProxy.bootstrap().withProxyAlias("downstream")
                .withChainProxyManager(always(socks(socksServer.address(), type, user, password))));
    }

    private static String target(HttpServer server) {
        return "127.0.0.1:" + server.getAddress().getPort();
    }

    @ParameterizedTest
    @EnumSource(value = ChainedProxyType.class, names = {"SOCKS4", "SOCKS5"})
    void getAndPostWithoutAuthentication(ChainedProxyType type) throws Exception {
        HttpProxyServer down = viaSocks(type, null, null);
        HttpResponse<String> get = TestSupport.get(client(down), url(origin, "/g"));
        assertEquals(200, get.statusCode());
        // SOCKS is transparent: the origin gets origin-form and only the downstream's Via.
        assertEquals("/g", echoedUri(get.body()));
        assertEquals(List.of("1.1 downstream"), echoedHeader(get.body(), "via"));

        HttpResponse<String> post = send(client(down), HttpRequest.newBuilder(URI.create(url(origin, "/p")))
                .POST(HttpRequest.BodyPublishers.ofString("socks body")).build());
        assertEquals(200, post.statusCode());
        assertEquals("socks body", echoedBody(post.body()));
        assertEquals("/p", echoedUri(post.body()));
        if (type == ChainedProxyType.SOCKS5) {
            assertEquals(List.of(0), socksServer.offeredMethods.subList(0, 1));
        }
        // The JDK client may reuse its connection to the proxy, but each server connection goes through SOCKS.
        assertEquals(target(origin), socksServer.targets.get(0));
    }

    @ParameterizedTest
    @EnumSource(value = ChainedProxyType.class, names = {"SOCKS4", "SOCKS5"})
    void connectThroughSocks(ChainedProxyType type) throws Exception {
        HttpProxyServer down = viaSocks(type, null, null);
        HttpResponse<String> response = TestSupport.get(client(down, originCa.clientContext()), url(secureOrigin, "/s"));
        assertEquals(200, response.statusCode());
        assertEquals("/s", echoedUri(response.body()));
        assertEquals(List.of(target(secureOrigin)), socksServer.targets);
    }

    @Test
    void socks5AuthenticationOffersBothMethodsAndSendsCredentials() throws Exception {
        HttpProxyServer down = viaSocks(ChainedProxyType.SOCKS5, "alice", "secret");
        assertEquals(200, TestSupport.get(client(down), url(origin, "/a")).statusCode());
        assertEquals(200, TestSupport.get(client(down, originCa.clientContext()), url(secureOrigin, "/a")).statusCode());
        // No-auth and user/password are both offered; the server picked user/password and accepted.
        assertEquals(List.of(0, 2), socksServer.offeredMethods.subList(0, 2));
        assertEquals(List.of(target(origin), target(secureOrigin)), socksServer.targets);
    }

    @Test
    void socks5WrongPasswordIsBadGatewayForConnect() throws Exception {
        socksServer = new SocksServer("alice", "secret");
        HttpProxyServer down = proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(socks(socksServer.address(), ChainedProxyType.SOCKS5, "alice", "wrong"))));
        assertEquals(502, ChainTestSupport.connectStatus(down.getListenAddress(), target(secureOrigin)));
        assertEquals(List.of(), socksServer.targets);
    }

    @Test
    void socks4RejectedUserIsBadGateway() throws Exception {
        socksServer = new SocksServer("bob", null);
        HttpProxyServer down = proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(socks(socksServer.address(), ChainedProxyType.SOCKS4, "mallory", null))));
        assertEquals(502, TestSupport.get(client(down), url(origin, "/")).statusCode());
        assertEquals(502, ChainTestSupport.connectStatus(down.getListenAddress(), target(secureOrigin)));
        assertEquals(List.of(), socksServer.targets);
    }

    @Test
    void unreachableSocksProxyIsBadGateway() throws Exception {
        int deadPort = closedPort();
        HttpProxyServer down = proxies.start(MicroProxy.bootstrap().withChainProxyManager(always(
                socks(new InetSocketAddress(TestSupport.LOOPBACK, deadPort), ChainedProxyType.SOCKS5, null, null))));
        assertEquals(502, TestSupport.get(client(down), url(origin, "/")).statusCode());
    }

    @ParameterizedTest
    @EnumSource(value = ChainedProxyType.class, names = {"SOCKS4", "SOCKS5"})
    void mitmOverSocks(ChainedProxyType type) throws Exception {
        CertificateAuthority proxyCa = CertificateAuthority.generate("SOCKS MITM CA");
        socksServer = new SocksServer(null, null);
        HttpProxyServer down = proxies.start(MicroProxy.bootstrap()
                .withChainProxyManager(always(socks(socksServer.address(), type, null, null)))
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
        HttpResponse<String> response = send(client(down, proxyCa.clientContext()),
                HttpRequest.newBuilder(URI.create(url(secureOrigin, "/m"))).POST(HttpRequest.BodyPublishers.ofString("m")).build());
        assertEquals(200, response.statusCode());
        assertEquals("m", echoedBody(response.body()));
        assertEquals(List.of(target(secureOrigin)), socksServer.targets);
    }
}
