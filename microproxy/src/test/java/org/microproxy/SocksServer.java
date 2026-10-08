package org.microproxy;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** A minimal SOCKS4a/SOCKS5 server for tests. Records the targets it connected to. */
final class SocksServer implements AutoCloseable {

    final List<String> targets = new CopyOnWriteArrayList<>();
    private final ServerSocket serverSocket;
    private final String user;
    private final String password;

    SocksServer(String user, String password) throws IOException {
        this.user = user;
        this.password = password;
        serverSocket = new ServerSocket(0, 50, TestSupport.LOOPBACK);
        Thread.ofVirtual().start(() -> {
            while (!serverSocket.isClosed()) {
                try {
                    Socket s = serverSocket.accept();
                    Thread.ofVirtual().start(() -> handle(s));
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    InetSocketAddress address() {
        return new InetSocketAddress(TestSupport.LOOPBACK, serverSocket.getLocalPort());
    }

    private void handle(Socket client) {
        try (client) {
            DataInputStream in = new DataInputStream(client.getInputStream());
            OutputStream out = client.getOutputStream();
            int version = in.readUnsignedByte();
            String host;
            int port;
            if (version == 4) {
                in.readUnsignedByte(); // command
                port = in.readUnsignedShort();
                byte[] ip = in.readNBytes(4);
                String userId = readNullTerminated(in);
                host = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0
                        ? readNullTerminated(in) : InetAddress.getByAddress(ip).getHostAddress();
                if (user != null && !user.equals(userId)) {
                    out.write(new byte[] {0, 91, 0, 0, 0, 0, 0, 0});
                    return;
                }
                out.write(new byte[] {0, 90, 0, 0, 0, 0, 0, 0});
            } else {
                int methods = in.readUnsignedByte();
                byte[] offered = in.readNBytes(methods);
                boolean wantsAuth = user != null;
                byte chosen = wantsAuth ? (byte) 2 : (byte) 0;
                boolean ok = false;
                for (byte m : offered) ok |= m == chosen;
                if (!ok) {
                    out.write(new byte[] {5, (byte) 0xff});
                    return;
                }
                out.write(new byte[] {5, chosen});
                if (wantsAuth) {
                    in.readUnsignedByte();
                    String u = new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.UTF_8);
                    String p = new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.UTF_8);
                    boolean good = user.equals(u) && password.equals(p);
                    out.write(new byte[] {1, (byte) (good ? 0 : 1)});
                    if (!good) return;
                }
                in.readUnsignedByte();
                in.readUnsignedByte();
                in.readUnsignedByte();
                int type = in.readUnsignedByte();
                host = switch (type) {
                    case 1 -> InetAddress.getByAddress(in.readNBytes(4)).getHostAddress();
                    case 3 -> new String(in.readNBytes(in.readUnsignedByte()), StandardCharsets.ISO_8859_1);
                    default -> InetAddress.getByAddress(in.readNBytes(16)).getHostAddress();
                };
                port = in.readUnsignedShort();
                out.write(new byte[] {5, 0, 0, 1, 0, 0, 0, 0, 0, 0});
            }
            out.flush();
            targets.add(host + ":" + port);
            try (Socket upstream = new Socket(host, port)) {
                Thread t = Thread.ofVirtual().start(() -> pipe(in, upstreamOut(upstream), upstream));
                pipe(upstream.getInputStream(), out, client);
                t.join();
            }
        } catch (Exception ignored) {
            // test server
        }
    }

    private static OutputStream upstreamOut(Socket s) {
        try {
            return s.getOutputStream();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static void pipe(InputStream in, OutputStream out, Socket dest) {
        try {
            in.transferTo(out);
            dest.shutdownOutput();
        } catch (IOException ignored) {
            // done
        }
    }

    private static String readNullTerminated(DataInputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.readUnsignedByte()) != 0) sb.append((char) b);
        return sb.toString();
    }

    @Override
    public void close() throws IOException {
        serverSocket.close();
    }
}
