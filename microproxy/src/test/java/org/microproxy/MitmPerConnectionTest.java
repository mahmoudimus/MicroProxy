package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpRequest;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SslContexts;

/**
 * MITM decisions made per client connection: a CA per user, a client certificate per user towards
 * an origin that requires one, and pooled server connections that never cross users.
 */
class MitmPerConnectionTest {

    private final CertificateAuthority originCa = CertificateAuthority.generate("Per-Connection Origin CA");
    private final CertificateAuthority usersCa = CertificateAuthority.generate("Per-Connection Users CA");
    private final CertificateAuthority aliceCa = CertificateAuthority.generate("Alice's Proxy CA");
    private final CertificateAuthority bobCa = CertificateAuthority.generate("Bob's Proxy CA");
    /** Subjects of the client certificates the origin was shown, one per request. */
    private final List<String> presented = new CopyOnWriteArrayList<>();
    private final AtomicInteger serverConnections = new AtomicInteger();
    private HttpsServer origin;
    private String target;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() throws Exception {
        origin = HttpsServer.create(new InetSocketAddress(TestSupport.LOOPBACK, 0), 0);
        origin.setHttpsConfigurator(new HttpsConfigurator(withKey(originCa, "127.0.0.1", usersTrust())) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters ssl = getSSLContext().getDefaultSSLParameters();
                ssl.setWantClientAuth(true);
                params.setSSLParameters(ssl);
            }
        });
        origin.createContext("/", exchange -> {
            SSLSession session = ((HttpsExchange) exchange).getSSLSession();
            String subject;
            try {
                subject = ((X509Certificate) session.getPeerCertificates()[0]).getSubjectX500Principal().getName();
                subject = subject.substring(subject.indexOf("CN=") + 3).split(",")[0];
            } catch (SSLException e) {
                subject = "none";
            }
            presented.add(subject);
            TestSupport.fixed(200, "hello " + subject).handle(exchange);
        });
        origin.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        origin.start();
        target = "127.0.0.1:" + origin.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
    }

    /** A proxy where alice, bob and carol log in with password {@code pw}. */
    private HttpProxyServerBootstrap bootstrap(MitmManager mitm) {
        return MicroProxy.bootstrap().withPort(0)
                .withProxyAuthenticator((user, password) -> List.of("alice", "bob", "carol").contains(user)
                        && "pw".equals(password))
                .withManInTheMiddle(mitm)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
                        serverConnections.incrementAndGet();
                    }
                });
    }

    /** Opens an intercepted session as {@code user}, trusting {@code trust}, and GETs {@code path}. */
    private RawProxyClient.Response getAs(String user, SSLContext trust, String path) throws IOException {
        try (Socket s = RawProxyClient.open(proxy.getListenAddress())) {
            String credentials = Base64.getEncoder().encodeToString((user + ":pw").getBytes(StandardCharsets.UTF_8));
            assertEquals(200, RawProxyClient.connect(s, target, "Proxy-Authorization: Basic " + credentials).status());
            SSLSocket tls = RawProxyClient.tls(s, trust, "127.0.0.1", origin.getAddress().getPort());
            return RawProxyClient.exchange(tls, "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        }
    }

    @Test
    void eachUserIsServedCertificatesFromTheirOwnCa() throws Exception {
        Map<String, MitmManager> managers = Map.of(
                "alice", new CertificateAuthorityMitmManager(aliceCa, originCa.clientContext()),
                "bob", new CertificateAuthorityMitmManager(bobCa, originCa.clientContext()));
        AtomicInteger choices = new AtomicInteger();
        proxy = bootstrap(MitmManager.perConnection(flow -> {
            choices.incrementAndGet();
            return managers.get(flow.getClientDetails().getUserName());
        })).start();

        assertEquals(200, getAs("alice", aliceCa.clientContext(), "/a").status());
        assertEquals(200, getAs("bob", bobCa.clientContext(), "/b").status());
        // Each user's client trusts only that user's CA, so the other CA's certificate is refused.
        assertThrows(IOException.class, () -> getAs("alice", bobCa.clientContext(), "/a"));
        assertThrows(IOException.class, () -> getAs("bob", aliceCa.clientContext(), "/b"));
        assertEquals(4, choices.get(), "chosen once per client connection");
    }

    @Test
    void aDeclinedConnectionIsTunnelled() throws Exception {
        proxy = bootstrap(MitmManager.perConnection(flow -> "carol".equals(flow.getClientDetails().getUserName())
                ? null : new CertificateAuthorityMitmManager(aliceCa, originCa.clientContext()))).start();
        // Carol's client talks to the origin itself: it sees the origin's certificate, not a proxy CA's.
        RawProxyClient.Response r = getAs("carol", originCa.clientContext(), "/tunnel");
        assertEquals(200, r.status());
        assertEquals("hello none", r.body());
    }

    @Test
    void theClientCertificateIsChosenPerUser() throws Exception {
        Map<String, SSLContext> upstream = Map.of("alice", userContext("alice"), "bob", userContext("bob"));
        List<FlowContext> flows = new CopyOnWriteArrayList<>();
        proxy = bootstrap(new CertificateAuthorityMitmManager(aliceCa) {
            @Override
            public SSLContext serverSslContext(String peerHost, int peerPort, FlowContext flow) {
                flows.add(flow);
                return upstream.get(flow.getClientDetails().getUserName());
            }
        }).withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).withPoolPerRequestInMitm(true)
                .start();

        for (String user : List.of("alice", "bob", "alice")) {
            assertEquals("hello " + user, getAs(user, aliceCa.clientContext(), "/" + user).body());
        }
        assertEquals(List.of("alice", "bob", "alice"), presented);
        // A manager deciding per client keeps its server connections out of the pool.
        assertEquals(3, serverConnections.get());
        assertEquals(0, proxy.getServerConnectionPoolMetrics().totalConnections());
        FullFlowContext first = assertInstanceOf(FullFlowContext.class, flows.getFirst());
        assertEquals(target, first.getServerHostAndPort());
        assertNotNull(first.getClientAddress());
    }

    @Test
    void pooledConnectionsAreSharedOnlyByClientsWithTheSameManager() throws Exception {
        Map<String, MitmManager> managers = Map.of(
                "alice", new CertificateAuthorityMitmManager(aliceCa, userContext("alice")),
                "bob", new CertificateAuthorityMitmManager(aliceCa, userContext("bob")));
        proxy = bootstrap(MitmManager.perConnection(flow -> managers.get(flow.getClientDetails().getUserName())))
                .withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true).withPoolPerRequestInMitm(true)
                .start();

        List<String> users = List.of("alice", "bob", "alice", "bob");
        for (int i = 0; i < users.size(); i++) {
            String user = users.get(i);
            assertEquals("hello " + user, getAs(user, aliceCa.clientContext(), "/" + i).body());
            int idle = Math.min(i + 1, 2);
            await(() -> proxy.getServerConnectionPoolMetrics().idleConnections() == idle);
        }
        assertEquals(users, presented, "no user's request went out on another user's connection");
        assertEquals(2, serverConnections.get(), "each user's connection was reused by that user");
    }

    @Test
    void managersWithoutFlowContextKeepWorkingAndPooling() throws Exception {
        CertificateAuthorityMitmManager delegate = new CertificateAuthorityMitmManager(aliceCa, userContext("alice"));
        AtomicInteger configured = new AtomicInteger();
        MitmManager legacy = new MitmManager() {
            @Override
            public SSLContext serverSslContext(String peerHost, int peerPort) {
                return delegate.serverSslContext(peerHost, peerPort);
            }

            @Override
            public SSLContext clientSslContextFor(HttpRequest connectRequest, SSLSession serverSslSession) {
                return delegate.clientSslContextFor(connectRequest, serverSslSession);
            }

            @Override
            public void configureServerSocket(SSLSocket socket) {
                configured.incrementAndGet();
            }
        };
        proxy = bootstrap(legacy).withSharedServerConnectionPool(true).withPoolSharedMitmConnections(true)
                .withPoolPerRequestInMitm(true).start();

        for (String user : List.of("alice", "bob")) {
            assertEquals(200, getAs(user, aliceCa.clientContext(), "/" + user).status());
            await(() -> proxy.getServerConnectionPoolMetrics().idleConnections() == 1);
        }
        assertEquals(1, configured.get());
        assertEquals(1, serverConnections.get(), "one manager for everyone: the connection is shared as before");
    }

    /** Waits up to five seconds for {@code condition}. */
    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            assertTrue(System.nanoTime() < deadline, "timed out waiting");
            Thread.sleep(10);
        }
    }

    /** A context with a client certificate for {@code user} from the users' CA, trusting the origin. */
    private SSLContext userContext(String user) throws Exception {
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("anchor", originCa.getCertificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(anchors);
        return withKey(usersCa, user, tmf.getTrustManagers());
    }

    /**
     * Accepts client certificates signed by the users' CA. The CA issues server certificates, which
     * the JDK's own trust managers would refuse as client certificates.
     */
    private TrustManager[] usersTrust() {
        return new TrustManager[] {new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                try {
                    chain[0].verify(usersCa.getCertificate().getPublicKey());
                } catch (GeneralSecurityException e) {
                    throw new CertificateException(e);
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("not a client");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[] {usersCa.getCertificate()};
            }
        }};
    }

    /** A context presenting a certificate for {@code name} issued by {@code issuer}. */
    private static SSLContext withKey(CertificateAuthority issuer, String name, TrustManager[] trust)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = generator.generateKeyPair();
        X509Certificate leaf = issuer.issue(keys.getPublic(), List.of(name));
        return SslContexts.withKey(keys.getPrivate(), new X509Certificate[] {leaf, issuer.getCertificate()}, trust);
    }
}
