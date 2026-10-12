package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.tls.CertificateAuthority;

/** The test fixtures themselves. */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class TestSupportTest {

    /**
     * A proxy may keep idle TLS connections to several HTTPS origins, one per port it was asked to
     * reach. The JDK server would wait on each under a monitor, pinning a virtual thread's carrier:
     * with as many as there are carriers, no virtual thread would run, and a test would hang until
     * its timeout.
     */
    @Test
    void idleConnectionsToHttpsOriginsLeaveVirtualThreadsRunning() throws Exception {
        CertificateAuthority ca = CertificateAuthority.generate("Fixture CA");
        int carriers = Runtime.getRuntime().availableProcessors() + 1;
        List<HttpsServer> servers = new ArrayList<>();
        List<SSLSocket> sockets = new ArrayList<>();
        try {
            for (int i = 0; i < carriers; i++) {
                HttpsServer server = TestSupport.httpsOrigin(ca.serverContext("127.0.0.1"), TestSupport.fixed(200, "ok"));
                servers.add(server);
                SSLSocket socket = (SSLSocket) ca.clientContext().getSocketFactory()
                        .createSocket(TestSupport.LOOPBACK, server.getAddress().getPort());
                socket.startHandshake(); // and no request
                sockets.add(socket);
            }
            CountDownLatch ran = new CountDownLatch(1);
            Thread.ofVirtual().start(ran::countDown);
            assertTrue(ran.await(10, TimeUnit.SECONDS), "a virtual thread ran");
        } finally {
            for (SSLSocket s : sockets) s.close();
            for (HttpsServer s : servers) s.stop(0);
        }
    }
}
