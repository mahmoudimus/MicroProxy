package org.microproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.SSLContext;

/** Helpers for tests of chained proxies, TLS chains, SOCKS and the PROXY protocol. */
final class ChainTestSupport {

    private ChainTestSupport() {}

    /** Starts proxies on ephemeral ports and aborts them all on close. */
    static final class Proxies implements AutoCloseable {
        private final List<HttpProxyServer> started = new ArrayList<>();

        HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
            HttpProxyServer proxy = bootstrap.withPort(0).start();
            started.add(proxy);
            return proxy;
        }

        @Override
        public void close() {
            started.forEach(HttpProxyServer::abort);
        }
    }

    /** Records "METHOD uri" for every request a proxy receives from its client. */
    static final class RequestLog extends ActivityTrackerAdapter {
        final List<String> received = new CopyOnWriteArrayList<>();

        @Override
        public void requestReceivedFromClient(FlowContext flowContext, org.microproxy.http.HttpRequest request) {
            received.add(request.method() + " " + request.uri());
        }
    }

    /** A chain that is the same fixed list of proxies for every request. */
    static ChainedProxyManager always(ChainedProxy... chain) {
        return (request, queue, details) -> queue.addAll(List.of(chain));
    }

    /** A plain HTTP chained proxy. */
    static ChainedProxy http(InetSocketAddress address) {
        return () -> address;
    }

    /** An HTTP chained proxy reached over TLS with {@code context} (which may hold a client certificate). */
    static ChainedProxy encrypted(InetSocketAddress address, SSLContext context) {
        return new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return address;
            }

            @Override
            public boolean requiresEncryption() {
                return true;
            }

            @Override
            public SSLContext getSslContext() {
                return context;
            }
        };
    }

    /** An HTTP chained proxy with Basic credentials. */
    static ChainedProxy authenticated(InetSocketAddress address, String user, String password) {
        return new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return address;
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

    /** A SOCKS chained proxy. */
    static ChainedProxy socks(InetSocketAddress address, ChainedProxyType type, String user, String password) {
        return new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return address;
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

    /** Opens a raw connection to {@code proxy} with a bounded read timeout. */
    static Socket open(InetSocketAddress proxy) throws IOException {
        Socket s = new Socket(proxy.getAddress(), proxy.getPort());
        s.setSoTimeout(20_000);
        return s;
    }

    /**
     * Sends {@code CONNECT target} on {@code socket} and returns the response head. On success the
     * socket is left positioned at the start of the tunnel.
     */
    static String connect(Socket socket, String target) throws IOException {
        TestSupport.write(socket.getOutputStream(),
                "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n");
        return TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
    }

    /** The status code of a response head such as {@code HTTP/1.1 200 OK}. */
    static int status(String head) {
        if (!head.startsWith("HTTP/")) {
            throw new AssertionError("not an HTTP response: '" + head + "'");
        }
        return Integer.parseInt(head.substring(9, 12));
    }

    /** Status code of a {@code CONNECT target} sent through {@code proxy} on a fresh connection. */
    static int connectStatus(InetSocketAddress proxy, String target) throws IOException {
        try (Socket s = open(proxy)) {
            return status(connect(s, target));
        }
    }

    /**
     * A minimal HTTP CONNECT proxy that records the first bytes of each connection (up to the end of
     * the first head), answers 200 and then relays bytes to the requested target.
     */
    static final class RecordingConnectProxy implements AutoCloseable {
        final List<String> firstHeads = new CopyOnWriteArrayList<>();
        private final TestSupport.RawServer server;

        RecordingConnectProxy() {
            server = TestSupport.rawServer(client -> {
                String head = TestSupport.readUntil(client.getInputStream(), "\r\n\r\n");
                firstHeads.add(head);
                String[] requestLine = head.substring(0, head.indexOf("\r\n")).split(" ");
                if (!requestLine[0].equals("CONNECT")) {
                    TestSupport.write(client.getOutputStream(), "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                    return;
                }
                String target = requestLine[1];
                int colon = target.lastIndexOf(':');
                try (Socket upstream = new Socket(target.substring(0, colon), Integer.parseInt(target.substring(colon + 1)))) {
                    TestSupport.write(client.getOutputStream(), "HTTP/1.1 200 Connection Established\r\n\r\n");
                    InputStream fromClient = client.getInputStream();
                    Thread t = Thread.ofVirtual().start(() -> pipe(fromClient, upstream));
                    pipe(upstream.getInputStream(), client);
                    t.join();
                }
            });
        }

        InetSocketAddress address() {
            return server.address();
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }

    private static void pipe(InputStream in, Socket to) {
        try {
            OutputStream out = to.getOutputStream();
            in.transferTo(out);
            to.shutdownOutput();
        } catch (IOException ignored) {
            // one side closed
        }
    }

}
