package org.microproxy.starlark;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import org.microproxy.TestSupport;

/**
 * Hand-written HTTP over a socket to the proxy, for what the JDK client will not send (such as
 * {@code Proxy-Authorization} with a scheme of our choosing) or several requests on one connection.
 */
final class RawHttp implements AutoCloseable {

    /** A response: status, headers (lower-cased names) and body. */
    record Response(int status, Map<String, String> headers, String body) {
        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    final Socket socket;

    RawHttp(InetSocketAddress proxy) throws IOException {
        socket = new Socket(proxy.getAddress(), proxy.getPort());
        socket.setSoTimeout(10_000);
    }

    /** Sends {@code method target} with {@code headerLines} and reads the response. */
    Response send(String method, String target, String... headerLines) throws IOException {
        StringBuilder sb = new StringBuilder(method).append(' ').append(target).append(" HTTP/1.1\r\n");
        String host = target.startsWith("http://") ? target.substring(7).replaceFirst("/.*", "") : target;
        sb.append("Host: ").append(host).append("\r\n");
        for (String h : headerLines) sb.append(h).append("\r\n");
        TestSupport.write(socket.getOutputStream(), sb.append("\r\n").toString());
        return read(socket.getInputStream(), method.equals("CONNECT"));
    }

    static Response read(InputStream in, boolean connect) throws IOException {
        String head = TestSupport.readUntil(in, "\r\n\r\n");
        if (!head.endsWith("\r\n\r\n")) throw new IOException("connection closed in the response head: " + head);
        String[] lines = head.split("\r\n");
        int status = Integer.parseInt(lines[0].split(" ")[1]);
        Map<String, String> headers = new TreeMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).strip().toLowerCase(Locale.ROOT),
                        lines[i].substring(colon + 1).strip());
            }
        }
        if (connect && status / 100 == 2) return new Response(status, headers, "");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (headers.containsKey("content-length")) {
            body.write(in.readNBytes(Integer.parseInt(headers.get("content-length"))));
        } else if ("chunked".equalsIgnoreCase(headers.get("transfer-encoding"))) {
            while (true) {
                String size = TestSupport.readUntil(in, "\r\n").strip();
                int n = Integer.parseInt(size, 16);
                if (n == 0) {
                    TestSupport.readUntil(in, "\r\n");
                    break;
                }
                body.write(in.readNBytes(n));
                in.readNBytes(2);
            }
        }
        return new Response(status, headers, body.toString(StandardCharsets.UTF_8));
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
