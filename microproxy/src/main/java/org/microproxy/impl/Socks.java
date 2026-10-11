package org.microproxy.impl;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;

/** Client side of the SOCKS4a and SOCKS5 CONNECT handshakes, and the protocols' numbers. */
final class Socks {

    // SOCKS5 (RFC 1928) and its username/password authentication (RFC 1929).
    static final int VERSION_5 = 5;
    static final int METHOD_NO_AUTHENTICATION = 0x00;
    static final int METHOD_USERNAME_PASSWORD = 0x02;
    static final int METHOD_NO_ACCEPTABLE = 0xFF;
    /** The version of the username/password sub-negotiation. */
    static final int AUTH_VERSION = 0x01;
    static final int AUTH_SUCCESS = 0x00;
    static final int AUTH_FAILURE = 0x01;
    static final int COMMAND_CONNECT = 0x01;
    static final int ADDRESS_IPV4 = 0x01;
    static final int ADDRESS_DOMAIN = 0x03;
    static final int ADDRESS_IPV6 = 0x04;
    static final int REPLY_SUCCEEDED = 0x00;
    static final int REPLY_GENERAL_FAILURE = 0x01;
    static final int REPLY_NOT_ALLOWED = 0x02;
    static final int REPLY_NETWORK_UNREACHABLE = 0x03;
    static final int REPLY_HOST_UNREACHABLE = 0x04;
    static final int REPLY_CONNECTION_REFUSED = 0x05;
    static final int REPLY_TTL_EXPIRED = 0x06;
    static final int REPLY_COMMAND_NOT_SUPPORTED = 0x07;
    static final int REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

    // SOCKS4 and its 4a extension.
    static final int VERSION_4 = 4;
    /** The version byte of a SOCKS4 reply. */
    static final int REPLY_VERSION_4 = 0;
    static final int REPLY_4_GRANTED = 90;
    static final int REPLY_4_REJECTED = 91;

    private Socks() {}

    /** SOCKS4a CONNECT, letting the SOCKS server resolve {@code host}. */
    static void connect4(InputStream in, OutputStream out, String host, int port, String user)
            throws IOException {
        byte[] userBytes = (user == null ? "" : user).getBytes(StandardCharsets.ISO_8859_1);
        byte[] hostBytes = host.getBytes(StandardCharsets.ISO_8859_1);
        byte[] req = new byte[8 + userBytes.length + 1 + hostBytes.length + 1];
        req[0] = VERSION_4;
        req[1] = COMMAND_CONNECT;
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
        if (reply[1] != REPLY_4_GRANTED) {
            throw new ProtocolException("SOCKS4 connect rejected with code " + (reply[1] & 0xff));
        }
    }

    /** SOCKS5 CONNECT with optional username/password authentication (RFC 1928, RFC 1929). */
    static void connect5(
            InputStream in, OutputStream out, String host, int port, String user, String password)
            throws IOException {
        DataInputStream din = new DataInputStream(in);
        boolean withAuth = user != null && password != null;
        out.write(withAuth
                ? new byte[] {VERSION_5, 2, METHOD_NO_AUTHENTICATION, METHOD_USERNAME_PASSWORD}
                : new byte[] {VERSION_5, 1, METHOD_NO_AUTHENTICATION});
        out.flush();
        byte[] choice = new byte[2];
        din.readFully(choice);
        if (choice[0] != VERSION_5) throw new ProtocolException("not a SOCKS5 server");
        if (choice[1] == METHOD_USERNAME_PASSWORD && withAuth) {
            byte[] u = user.getBytes(StandardCharsets.UTF_8);
            byte[] p = password.getBytes(StandardCharsets.UTF_8);
            if (u.length > 255 || p.length > 255) throw new ProtocolException("SOCKS5 credentials too long");
            byte[] auth = new byte[3 + u.length + p.length];
            auth[0] = AUTH_VERSION;
            auth[1] = (byte) u.length;
            System.arraycopy(u, 0, auth, 2, u.length);
            auth[2 + u.length] = (byte) p.length;
            System.arraycopy(p, 0, auth, 3 + u.length, p.length);
            out.write(auth);
            out.flush();
            byte[] status = new byte[2];
            din.readFully(status);
            if (status[1] != AUTH_SUCCESS) throw new ProtocolException("SOCKS5 authentication failed");
        } else if (choice[1] != METHOD_NO_AUTHENTICATION) {
            throw new ProtocolException("SOCKS5 server accepted no offered auth method");
        }
        byte[] hostBytes = host.getBytes(StandardCharsets.ISO_8859_1);
        if (hostBytes.length > 255) throw new ProtocolException("host name too long for SOCKS5");
        byte[] req = new byte[7 + hostBytes.length];
        req[0] = VERSION_5;
        req[1] = COMMAND_CONNECT;
        req[3] = ADDRESS_DOMAIN;
        req[4] = (byte) hostBytes.length;
        System.arraycopy(hostBytes, 0, req, 5, hostBytes.length);
        req[5 + hostBytes.length] = (byte) (port >> 8);
        req[6 + hostBytes.length] = (byte) port;
        out.write(req);
        out.flush();
        byte[] head = new byte[4];
        din.readFully(head);
        if (head[1] != REPLY_SUCCEEDED) {
            throw new ProtocolException("SOCKS5 connect rejected with code " + (head[1] & 0xff));
        }
        int addrLen = switch (head[3]) {
            case ADDRESS_IPV4 -> 4;
            case ADDRESS_IPV6 -> 16;
            case ADDRESS_DOMAIN -> din.readUnsignedByte();
            default -> throw new ProtocolException("bad SOCKS5 address type");
        };
        din.readFully(new byte[addrLen + 2]);
    }
}
