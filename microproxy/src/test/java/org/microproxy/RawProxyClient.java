package org.microproxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Hand-written HTTP over sockets, for cases the JDK client cannot express, such as CONNECT with a
 * {@code Proxy-Authorization} header (which it strips by default) or talking to a proxy over TLS.
 */
final class RawProxyClient {

    private RawProxyClient() {}

    /** A parsed response: status, headers (lower-cased names) and body. */
    record Response(int status, Map<String, String> headers, String body) {
        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    static Socket open(InetSocketAddress address) throws IOException {
        Socket s = new Socket(address.getAddress(), address.getPort());
        s.setSoTimeout(10_000);
        return s;
    }

    /** Sends {@code CONNECT hostPort} with the given extra header lines and reads the reply head. */
    static Response connect(Socket proxy, String hostPort, String... headerLines) throws IOException {
        StringBuilder sb = new StringBuilder("CONNECT ").append(hostPort).append(" HTTP/1.1\r\nHost: ")
                .append(hostPort).append("\r\n");
        for (String h : headerLines) sb.append(h).append("\r\n");
        TestSupport.write(proxy.getOutputStream(), sb.append("\r\n").toString());
        return read(proxy.getInputStream(), true);
    }

    /** Layers TLS (as client) over an established tunnel or a connection to a TLS proxy. */
    static SSLSocket tls(Socket plain, SSLContext context, String host, int port) throws IOException {
        SSLSocket s = (SSLSocket) context.getSocketFactory().createSocket(plain, host, port, true);
        s.setUseClientMode(true);
        s.startHandshake();
        return s;
    }

    /** Writes {@code request} and reads one response. */
    static Response exchange(Socket s, String request) throws IOException {
        TestSupport.write(s.getOutputStream(), request);
        return read(s.getInputStream(), false);
    }

    /**
     * Reads one response; its body is delimited by {@code Content-Length} or chunked encoding, or
     * absent when {@code headOnly} (e.g. a successful CONNECT).
     */
    static Response read(InputStream in, boolean headOnly) throws IOException {
        String head = TestSupport.readUntil(in, "\r\n\r\n");
        if (!head.endsWith("\r\n\r\n")) throw new IOException("connection closed in the response head: " + head);
        String[] lines = head.split("\r\n");
        int status = Integer.parseInt(lines[0].split(" ")[1]);
        Map<String, String> headers = new TreeMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).strip().toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).strip());
            }
        }
        if (headOnly && status / 100 == 2) return new Response(status, headers, "");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (headers.containsKey("content-length")) {
            body.write(in.readNBytes(Integer.parseInt(headers.get("content-length"))));
        } else if ("chunked".equalsIgnoreCase(headers.get("transfer-encoding"))) {
            while (true) {
                int size = Integer.parseInt(TestSupport.readUntil(in, "\r\n").strip().split(";")[0], 16);
                if (size == 0) {
                    TestSupport.readUntil(in, "\r\n");
                    break;
                }
                body.write(in.readNBytes(size));
                TestSupport.readUntil(in, "\r\n");
            }
        }
        return new Response(status, headers, body.toString(StandardCharsets.UTF_8));
    }
}
