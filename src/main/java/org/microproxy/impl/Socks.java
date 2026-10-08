package org.microproxy.impl;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;

/** Client side of the SOCKS4a and SOCKS5 CONNECT handshakes. */
final class Socks {

    private Socks() {}

    /** SOCKS4a CONNECT, letting the SOCKS server resolve {@code host}. */
    static void connect4(InputStream in, OutputStream out, String host, int port, String user)
            throws IOException {
        byte[] userBytes = (user == null ? "" : user).getBytes(StandardCharsets.ISO_8859_1);
        byte[] hostBytes = host.getBytes(StandardCharsets.ISO_8859_1);
        byte[] req = new byte[8 + userBytes.length + 1 + hostBytes.length + 1];
        req[0] = 4;
        req[1] = 1;
        req[2] = (byte) (port >> 8);
        req[3] = (byte) port;
        // 0.0.0.1 tells a SOCKS4a server that a host name follows the user id.
        req[7] = 1;
        System.arraycopy(userBytes, 0, req, 8, userBytes.length);
        System.arraycopy(hostBytes, 0, req, 9 + userBytes.length, hostBytes.length);
        out.write(req);
        out.flush();
        byte[] reply = new byte[8];
        new DataInputStream(in).readFully(reply);
        if (reply[1] != 90) {
            throw new ProtocolException("SOCKS4 connect rejected with code " + (reply[1] & 0xff));
        }
    }

    /** SOCKS5 CONNECT with optional username/password authentication (RFC 1928, RFC 1929). */
    static void connect5(
            InputStream in, OutputStream out, String host, int port, String user, String password)
            throws IOException {
        DataInputStream din = new DataInputStream(in);
        boolean withAuth = user != null && password != null;
        out.write(withAuth ? new byte[] {5, 2, 0, 2} : new byte[] {5, 1, 0});
        out.flush();
        byte[] choice = new byte[2];
        din.readFully(choice);
        if (choice[0] != 5) throw new ProtocolException("not a SOCKS5 server");
        if (choice[1] == 2 && withAuth) {
            byte[] u = user.getBytes(StandardCharsets.UTF_8);
            byte[] p = password.getBytes(StandardCharsets.UTF_8);
            if (u.length > 255 || p.length > 255) throw new ProtocolException("SOCKS5 credentials too long");
            byte[] auth = new byte[3 + u.length + p.length];
            auth[0] = 1;
            auth[1] = (byte) u.length;
            System.arraycopy(u, 0, auth, 2, u.length);
            auth[2 + u.length] = (byte) p.length;
            System.arraycopy(p, 0, auth, 3 + u.length, p.length);
            out.write(auth);
            out.flush();
            byte[] status = new byte[2];
            din.readFully(status);
            if (status[1] != 0) throw new ProtocolException("SOCKS5 authentication failed");
        } else if (choice[1] != 0) {
            throw new ProtocolException("SOCKS5 server accepted no offered auth method");
        }
        byte[] hostBytes = host.getBytes(StandardCharsets.ISO_8859_1);
        if (hostBytes.length > 255) throw new ProtocolException("host name too long for SOCKS5");
        byte[] req = new byte[7 + hostBytes.length];
        req[0] = 5;
        req[1] = 1;
        req[3] = 3;
        req[4] = (byte) hostBytes.length;
        System.arraycopy(hostBytes, 0, req, 5, hostBytes.length);
        req[5 + hostBytes.length] = (byte) (port >> 8);
        req[6 + hostBytes.length] = (byte) port;
        out.write(req);
        out.flush();
        byte[] head = new byte[4];
        din.readFully(head);
        if (head[1] != 0) {
            throw new ProtocolException("SOCKS5 connect rejected with code " + (head[1] & 0xff));
        }
        int addrLen = switch (head[3]) {
            case 1 -> 4;
            case 4 -> 16;
            case 3 -> din.readUnsignedByte();
            default -> throw new ProtocolException("bad SOCKS5 address type");
        };
        din.readFully(new byte[addrLen + 2]);
    }
}
