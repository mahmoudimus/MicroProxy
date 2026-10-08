package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.client;
import static org.microproxy.TestSupport.echo;
import static org.microproxy.TestSupport.echoedHeader;
import static org.microproxy.TestSupport.echoedUri;
import static org.microproxy.TestSupport.get;
import static org.microproxy.TestSupport.origin;
import static org.microproxy.TestSupport.url;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

class ChainedProxyTest {

    private HttpServer origin;
    private final List<HttpProxyServer> proxies = new ArrayList<>();
    private final List<String> upstreamSaw = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() {
        origin = origin(echo());
    }

    @AfterEach
    void tearDown() {
        proxies.forEach(HttpProxyServer::abort);
        origin.stop(0);
    }

    private HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
        HttpProxyServer p = bootstrap.withPort(0).start();
        proxies.add(p);
        return p;
    }

    /** An upstream HTTP proxy that records the requests it receives. */
    private HttpProxyServer upstream(HttpProxyServerBootstrap bootstrap) {
        return start(bootstrap.withProxyAlias("upstream").withFiltersSource(new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(org.microproxy.http.HttpRequest req, FlowContext ctx) {
                upstreamSaw.add(req.method() + " " + req.uri());
                return null;
            }
        }));
    }

    static ChainedProxy http(InetSocketAddress address) {
        return () -> address;
    }

    private HttpProxyServer downstream(ChainedProxy... chain) {
        return start(MicroProxy.bootstrap().withProxyAlias("downstream")
                .withChainProxyManager((req, queue, details) -> queue.addAll(List.of(chain))));
    }

    @Test
    void requestsAreForwardedInAbsoluteFormToHttpUpstream() {
        HttpProxyServer up = upstream(MicroProxy.bootstrap());
        HttpProxyServer down = downstream(http(up.getListenAddress()));
        HttpResponse<String> response = get(client(down), url(origin, "/chained"));
        assertEquals(200, response.statusCode());
        assertEquals(List.of("GET " + url(origin, "/chained")), upstreamSaw);
        assertEquals("/chained", echoedUri(response.body()));
        assertEquals(List.of("1.1 downstream", "1.1 upstream"), echoedHeader(response.body(), "via"));
    }

    @Test
    void upstreamCredentialsAreSentForPlainAndConnect() throws Exception {
        HttpProxyServer up = upstream(MicroProxy.bootstrap()
                .withProxyAuthenticator((u, p) -> u.equals("chain") && p.equals("secret")));
        ChainedProxy authenticated = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return up.getListenAddress();
            }

            @Override
            public String getUsername() {
                return "chain";
            }

            @Override
            public String getPassword() {
                return "secret";
            }
        };
        HttpProxyServer down = downstream(authenticated);
        assertEquals(200, get(client(down), url(origin, "/auth")).statusCode());

        CertificateAuthority ca = CertificateAuthority.generate("Chain Test CA");
        HttpsServer secure = TestSupport.httpsOrigin(ca.serverContext("127.0.0.1"), echo());
        try {
            assertEquals(200, get(client(down, ca.clientContext()), url(secure, "/tls")).statusCode());
            assertTrue(upstreamSaw.contains("CONNECT 127.0.0.1:" + secure.getAddress().getPort()));
        } finally {
            secure.stop(0);
        }
    }

    @Test
    void failingProxyFallsBackToTheNextOne() throws Exception {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0)) {
            deadPort = s.getLocalPort();
        }
        AtomicInteger failures = new AtomicInteger();
        ChainedProxy dead = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return new InetSocketAddress(TestSupport.LOOPBACK, deadPort);
            }

            @Override
            public void connectionFailed(Throwable cause) {
                failures.incrementAndGet();
            }
        };
        HttpProxyServer up = upstream(MicroProxy.bootstrap());
        HttpProxyServer down = downstream(dead, http(up.getListenAddress()));
        assertEquals(200, get(client(down), url(origin, "/fallback")).statusCode());
        assertEquals(1, failures.get());
        assertEquals(1, upstreamSaw.size());
    }

    @Test
    void fallbackToDirectConnectionStripsTheHost() throws Exception {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0)) {
            deadPort = s.getLocalPort();
        }
        HttpProxyServer down = downstream(http(new InetSocketAddress(TestSupport.LOOPBACK, deadPort)),
                ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        HttpResponse<String> response = get(client(down), url(origin, "/direct"));
        assertEquals(200, response.statusCode());
        assertEquals("/direct", echoedUri(response.body()));
    }

    @Test
    void emptyChainMeansBadGateway() {
        HttpProxyServer down = downstream();
        assertEquals(502, get(client(down), url(origin, "/")).statusCode());
    }

    @Test
    void encryptedConnectionToChainedProxy() {
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        HttpProxyServer up = upstream(MicroProxy.bootstrap().withSslContextSource(tls));
        ChainedProxy encrypted = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return up.getListenAddress();
            }

            @Override
            public boolean requiresEncryption() {
                return true;
            }

            @Override
            public SSLContext getSslContext() {
                return tls.getSslContext();
            }
        };
        HttpProxyServer down = downstream(encrypted);
        assertEquals(200, get(client(down), url(origin, "/encrypted")).statusCode());
        assertEquals(1, upstreamSaw.size());
    }

    @Test
    void mitmThroughChainedProxyTunnelsToOrigin() {
        CertificateAuthority originCa = CertificateAuthority.generate("Origin CA");
        CertificateAuthority proxyCa = CertificateAuthority.generate("Proxy CA");
        HttpsServer secure = TestSupport.httpsOrigin(originCa.serverContext("127.0.0.1"), echo());
        try {
            HttpProxyServer up = upstream(MicroProxy.bootstrap());
            HttpProxyServer down = start(MicroProxy.bootstrap()
                    .withChainProxyManager((req, q, d) -> q.add(http(up.getListenAddress())))
                    .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext())));
            HttpResponse<String> response = get(client(down, proxyCa.clientContext()), url(secure, "/m"));
            assertEquals(200, response.statusCode());
            assertEquals("/m", echoedUri(response.body()));
            assertEquals(List.of("CONNECT 127.0.0.1:" + secure.getAddress().getPort()), upstreamSaw);
        } finally {
            secure.stop(0);
        }
    }

    private ChainedProxy socks(SocksServer server, ChainedProxyType type, String user, String password) {
        return new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return server.address();
            }

            @Override
            public ChainedProxyType getChainedProxyType() {
                return type;
            }

            @Override
            public String getUsername() {
                return user;
            }

            @Override
            public String getPassword() {
                return password;
            }
        };
    }

    @Test
    void socks4ChainedProxy() throws Exception {
        try (SocksServer socks = new SocksServer("bob", null)) {
            HttpProxyServer down = downstream(socks(socks, ChainedProxyType.SOCKS4, "bob", null));
            HttpResponse<String> response = get(client(down), url(origin, "/s4"));
            assertEquals(200, response.statusCode());
            assertEquals("/s4", echoedUri(response.body()), "SOCKS is transparent: origin-form expected");
            assertEquals(List.of("127.0.0.1:" + origin.getAddress().getPort()), socks.targets);
        }
    }

    @Test
    void socks5ChainedProxyWithAuthentication() throws Exception {
        try (SocksServer socks = new SocksServer("alice", "pw")) {
            HttpProxyServer down = downstream(socks(socks, ChainedProxyType.SOCKS5, "alice", "pw"));
            assertEquals(200, get(client(down), url(origin, "/s5")).statusCode());
            assertEquals(1, socks.targets.size());
        }
        try (SocksServer socks = new SocksServer("alice", "pw")) {
            HttpProxyServer down = downstream(socks(socks, ChainedProxyType.SOCKS5, "alice", "wrong"));
            assertEquals(502, get(client(down), url(origin, "/s5")).statusCode());
        }
    }
}
