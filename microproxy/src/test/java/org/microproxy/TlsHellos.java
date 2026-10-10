package org.microproxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/** ClientHellos for tests: real ones from the JDK's TLS client, and hand-built ones. */
public final class TlsHellos {

    private TlsHellos() {}

    /**
     * The TLS records a JDK client sends first, with {@code sni} (or none when null) and {@code
     * alpn} (or no ALPN extension when empty). The client's handshake is abandoned afterwards.
     */
    public static byte[] fromJdkClient(String sni, String... alpn) throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (ServerSocket listener = new ServerSocket(0, 1, loopback)) {
            Thread client = Thread.ofVirtual().start(() -> {
                try (SSLSocket s = (SSLSocket) SSLContext.getDefault().getSocketFactory()
                        .createSocket(loopback, listener.getLocalPort())) {
                    SSLParameters params = s.getSSLParameters();
                    if (sni != null) params.setServerNames(List.of(new SNIHostName(sni)));
                    if (alpn.length > 0) params.setApplicationProtocols(alpn);
                    s.setSSLParameters(params);
                    s.setSoTimeout(10_000);
                    s.startHandshake();
                } catch (Exception expected) {
                    // the "server" hangs up after the ClientHello
                }
            });
            try (Socket accepted = listener.accept()) {
                accepted.setSoTimeout(10_000);
                byte[] records = readRecords(accepted.getInputStream());
                accepted.close();
                client.join();
                return records;
            }
        }
    }

    /** Reads whole TLS records until the first handshake message is complete. */
    private static byte[] readRecords(InputStream in) throws IOException {
        ByteArrayOutputStream records = new ByteArrayOutputStream();
        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        while (true) {
            byte[] header = in.readNBytes(5);
            if (header.length < 5) throw new IOException("closed before a ClientHello");
            int length = (header[3] & 0xff) << 8 | (header[4] & 0xff);
            byte[] body = in.readNBytes(length);
            records.write(header);
            records.write(body);
            handshake.write(body);
            byte[] h = handshake.toByteArray();
            if (h.length >= 4 && h.length >= ((h[1] & 0xff) << 16 | (h[2] & 0xff) << 8 | (h[3] & 0xff)) + 4) {
                return records.toByteArray();
            }
        }
    }

    /** The handshake message carried by {@code records}, without record headers. */
    public static byte[] message(byte[] records) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int at = 0; at + 5 <= records.length; ) {
            int length = (records[at + 3] & 0xff) << 8 | (records[at + 4] & 0xff);
            out.write(records, at + 5, length);
            at += 5 + length;
        }
        return out.toByteArray();
    }

    /** {@code message} re-split into TLS handshake records of at most {@code size} bytes. */
    public static byte[] records(byte[] message, int size) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int at = 0; at < message.length; at += size) {
            int n = Math.min(size, message.length - at);
            out.write(0x16);
            out.write(0x03);
            out.write(0x01);
            out.write(n >> 8);
            out.write(n);
            out.write(message, at, n);
        }
        return out.toByteArray();
    }

    /**
     * A hand-built ClientHello message (handshake header included) with these server names (none
     * when empty), ALPN protocols (no extension when null) and supported versions (no extension
     * when empty).
     */
    public static byte[] build(List<String> serverNames, List<String> alpn, int... versions) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x03);
        body.write(0x03);
        body.writeBytes(new byte[32]);
        body.write(0);
        u16(body, 6);
        u16(body, 0x1301);
        u16(body, 0xc02f);
        u16(body, 0x0a0a);
        body.write(1);
        body.write(0);
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        if (!serverNames.isEmpty()) {
            ByteArrayOutputStream list = new ByteArrayOutputStream();
            for (String name : serverNames) {
                byte[] b = name.getBytes(StandardCharsets.ISO_8859_1);
                list.write(0);
                u16(list, b.length);
                list.writeBytes(b);
            }
            extension(extensions, 0, withU16Length(list.toByteArray()));
        }
        if (alpn != null) {
            ByteArrayOutputStream list = new ByteArrayOutputStream();
            for (String protocol : alpn) {
                byte[] b = protocol.getBytes(StandardCharsets.ISO_8859_1);
                list.write(b.length);
                list.writeBytes(b);
            }
            extension(extensions, 16, withU16Length(list.toByteArray()));
        }
        if (versions.length > 0) {
            ByteArrayOutputStream list = new ByteArrayOutputStream();
            list.write(versions.length * 2);
            for (int v : versions) u16(list, v);
            extension(extensions, 43, list.toByteArray());
        }
        byte[] ext = extensions.toByteArray();
        u16(body, ext.length);
        body.writeBytes(ext);
        byte[] b = body.toByteArray();
        byte[] message = new byte[b.length + 4];
        message[0] = 1;
        message[1] = (byte) (b.length >> 16);
        message[2] = (byte) (b.length >> 8);
        message[3] = (byte) b.length;
        System.arraycopy(b, 0, message, 4, b.length);
        return message;
    }

    private static void extension(ByteArrayOutputStream out, int type, byte[] body) {
        u16(out, type);
        u16(out, body.length);
        out.writeBytes(body);
    }

    private static byte[] withU16Length(byte[] b) {
        byte[] out = Arrays.copyOf(new byte[] {(byte) (b.length >> 8), (byte) b.length}, b.length + 2);
        System.arraycopy(b, 0, out, 2, b.length);
        return out;
    }

    private static void u16(ByteArrayOutputStream out, int v) {
        out.write(v >> 8);
        out.write(v);
    }
}
