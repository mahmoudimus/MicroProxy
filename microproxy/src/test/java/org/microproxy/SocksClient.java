package org.microproxy;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * A SOCKS client for tests that sends each message of the handshake on its own, so a test can
 * stop anywhere and look at what the server answered.
 */
public final class SocksClient implements AutoCloseable {

    public static final int NO_AUTHENTICATION = 0x00;
    public static final int USERNAME_PASSWORD = 0x02;
    public static final int NO_ACCEPTABLE = 0xFF;
    public static final int CONNECT = 1;
    public static final int BIND = 2;
    public static final int UDP_ASSOCIATE = 3;
    public static final int IPV4 = 1;
    public static final int DOMAIN = 3;
    public static final int IPV6 = 4;

    public final Socket socket;
    public final DataInputStream in;
    public final OutputStream out;

    public SocksClient(InetSocketAddress proxy) throws IOException {
        socket = new Socket(proxy.getAddress(), proxy.getPort());
        socket.setSoTimeout(20_000);
        in = new DataInputStream(socket.getInputStream());
        out = socket.getOutputStream();
    }

    public SocksClient(HttpProxyServer proxy) throws IOException {
        this(proxy.getListenAddress());
    }

    /** Sends the SOCKS5 greeting offering {@code methods}; returns the method the server chose. */
    public int greet(int... methods) throws IOException {
        byte[] greeting = new byte[2 + methods.length];
        greeting[0] = 5;
        greeting[1] = (byte) methods.length;
        for (int i = 0; i < methods.length; i++) greeting[2 + i] = (byte) methods[i];
        write(greeting);
        int version = in.readUnsignedByte();
        if (version != 5) throw new IOException("not a SOCKS5 answer: version " + version);
        return in.readUnsignedByte();
    }

    /** Sends RFC 1929 credentials; returns the status (0 = accepted). */
    public int authenticate(String user, String password) throws IOException {
        byte[] u = user.getBytes(StandardCharsets.UTF_8);
        byte[] p = password.getBytes(StandardCharsets.UTF_8);
        byte[] message = new byte[3 + u.length + p.length];
        message[0] = 1;
        message[1] = (byte) u.length;
        System.arraycopy(u, 0, message, 2, u.length);
        message[2 + u.length] = (byte) p.length;
        System.arraycopy(p, 0, message, 3 + u.length, p.length);
        write(message);
        int version = in.readUnsignedByte();
        if (version != 1) throw new IOException("not a username/password answer: version " + version);
        return in.readUnsignedByte();
    }

    /** Greets offering no authentication only, then asks to connect to {@code host:port}. */
    public int open(String host, int port) throws IOException {
        int method = greet(NO_AUTHENTICATION);
        if (method != NO_AUTHENTICATION) throw new IOException("method " + method + " chosen");
        return connect(host, port);
    }

    /** Asks to {@code CONNECT} to {@code host}: an IP literal as such, else as a domain name. */
    public int connect(String host, int port) throws IOException {
        if (host.matches("[0-9.]+")) return request(CONNECT, IPV4, InetAddress.getByName(host).getAddress(), port);
        if (host.contains(":")) return request(CONNECT, IPV6, InetAddress.getByName(host).getAddress(), port);
        return request(CONNECT, DOMAIN, domain(host), port);
    }

    /** {@code host} as a SOCKS5 domain name field: its length, then its bytes. */
    public static byte[] domain(String host) {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        byte[] field = new byte[1 + name.length];
        field[0] = (byte) name.length;
        System.arraycopy(name, 0, field, 1, name.length);
        return field;
    }

    /** Sends a SOCKS5 request; returns the reply code (0 = succeeded), or -1 if the server closed instead. */
    public int request(int command, int addressType, byte[] address, int port) throws IOException {
        byte[] request = new byte[4 + address.length + 2];
        request[0] = 5;
        request[1] = (byte) command;
        request[3] = (byte) addressType;
        System.arraycopy(address, 0, request, 4, address.length);
        request[4 + address.length] = (byte) (port >> 8);
        request[5 + address.length] = (byte) port;
        write(request);
        return reply();
    }

    /** Reads a SOCKS5 reply, bound address included; returns its code, or -1 at end of stream. */
    public int reply() throws IOException {
        int version = in.read();
        if (version < 0) return -1;
        if (version != 5) throw new IOException("not a SOCKS5 reply: version " + version);
        int code = in.readUnsignedByte();
        in.readUnsignedByte();
        int type = in.readUnsignedByte();
        int length = switch (type) {
            case IPV4 -> 4;
            case IPV6 -> 16;
            case DOMAIN -> in.readUnsignedByte();
            default -> throw new IOException("bad address type " + type);
        };
        in.readFully(new byte[length + 2]);
        return code;
    }

    /** Sends a SOCKS4a {@code CONNECT} (SOCKS4 for an IPv4 literal); returns the reply code (90 = granted), or -1. */
    public int socks4(int command, String host, int port, String userId) throws IOException {
        boolean literal = host.matches("[0-9.]+");
        byte[] user = userId.getBytes(StandardCharsets.ISO_8859_1);
        byte[] name = literal ? new byte[0] : host.getBytes(StandardCharsets.ISO_8859_1);
        byte[] request = new byte[8 + user.length + 1 + (literal ? 0 : name.length + 1)];
        request[0] = 4;
        request[1] = (byte) command;
        request[2] = (byte) (port >> 8);
        request[3] = (byte) port;
        byte[] ip = literal ? InetAddress.getByName(host).getAddress() : new byte[] {0, 0, 0, 1};
        System.arraycopy(ip, 0, request, 4, 4);
        System.arraycopy(user, 0, request, 8, user.length);
        System.arraycopy(name, 0, request, 9 + user.length, name.length);
        write(request);
        int version = in.read();
        if (version < 0) return -1;
        int code = in.readUnsignedByte();
        in.readFully(new byte[6]);
        return code;
    }

    public void write(byte[] bytes) throws IOException {
        out.write(bytes);
        out.flush();
    }

    public void write(String s) throws IOException {
        write(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    /** Whether the server closed the connection: the next read sees its end (or a reset). */
    public boolean closedByServer() {
        try {
            return in.read() < 0;
        } catch (IOException e) {
            return true;
        }
    }

    /** Reads {@code n} bytes as ISO-8859-1. */
    public String read(int n) throws IOException {
        byte[] b = new byte[n];
        in.readFully(b);
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    public InputStream input() {
        return in;
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
