package org.microproxy.impl;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import org.microproxy.http.HttpResponseStatus;

/** Reads PROXY protocol v1/v2 headers and writes v1 headers (HAProxy PROXY protocol spec). */
final class ProxyProtocol {

    private static final byte[] V2_SIGNATURE = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };

    /** The addresses carried by a PROXY header; addresses are null for LOCAL/UNKNOWN. */
    // @value-candidate: becomes a value class in the valhalla build profile
    record Header(InetSocketAddress source, InetSocketAddress destination) {}

    private ProxyProtocol() {}

    static Header read(ByteReader in) throws IOException {
        int first = in.read();
        if (first == 'P') {
            String line = in.readLine(106, HttpResponseStatus.BAD_REQUEST);
            if (line == null || !line.startsWith("ROXY ")) throw new ProtocolException("bad PROXY v1 header");
            return parseV1(line.substring(5));
        }
        if (first == 0x0D) {
            byte[] rest = new byte[15];
            in.readFully(rest, 0, 15);
            for (int i = 1; i < 12; i++) {
                if (rest[i - 1] != V2_SIGNATURE[i]) throw new ProtocolException("bad PROXY v2 signature");
            }
            int verCmd = rest[11] & 0xff;
            int family = rest[12] & 0xff;
            int len = ((rest[13] & 0xff) << 8) | (rest[14] & 0xff);
            byte[] body = new byte[len];
            in.readFully(body, 0, len);
            if ((verCmd >> 4) != 2) throw new ProtocolException("bad PROXY v2 version");
            if ((verCmd & 0x0f) == 0) return new Header(null, null); // LOCAL
            return switch (family >> 4) {
                case 1 -> addresses(body, 4);
                case 2 -> addresses(body, 16);
                default -> new Header(null, null);
            };
        }
        throw new ProtocolException("missing PROXY protocol header");
    }

    private static Header parseV1(String rest) throws IOException {
        String[] parts = rest.split(" ");
        if (parts.length >= 1 && parts[0].equals("UNKNOWN")) return new Header(null, null);
        if (parts.length != 5 || !(parts[0].equals("TCP4") || parts[0].equals("TCP6"))) {
            throw new ProtocolException("bad PROXY v1 header");
        }
        try {
            InetAddress src = literal(parts[1]);
            InetAddress dst = literal(parts[2]);
            return new Header(
                    new InetSocketAddress(src, port(parts[3])), new InetSocketAddress(dst, port(parts[4])));
        } catch (IllegalArgumentException e) {
            throw new ProtocolException("bad PROXY v1 header");
        }
    }

    private static Header addresses(byte[] body, int addrLen) throws IOException {
        if (body.length < addrLen * 2 + 4) throw new ProtocolException("short PROXY v2 address block");
        byte[] src = java.util.Arrays.copyOfRange(body, 0, addrLen);
        byte[] dst = java.util.Arrays.copyOfRange(body, addrLen, addrLen * 2);
        int sport = ((body[addrLen * 2] & 0xff) << 8) | (body[addrLen * 2 + 1] & 0xff);
        int dport = ((body[addrLen * 2 + 2] & 0xff) << 8) | (body[addrLen * 2 + 3] & 0xff);
        return new Header(
                new InetSocketAddress(InetAddress.getByAddress(src), sport),
                new InetSocketAddress(InetAddress.getByAddress(dst), dport));
    }

    private static InetAddress literal(String text) throws IOException {
        // Only accept literals: never trigger a DNS lookup on untrusted input.
        if (!Tls.isIpLiteral(text)) throw new IllegalArgumentException(text);
        return InetAddress.getByName(text);
    }

    private static int port(String text) {
        int p = Integer.parseInt(text);
        if (p < 0 || p > 65535) throw new IllegalArgumentException(text);
        return p;
    }

    /** Encodes a v1 header for a TCP connection from {@code source} to {@code destination}. */
    static byte[] encodeV1(InetSocketAddress source, InetSocketAddress destination) {
        if (source == null || destination == null
                || source.getAddress() == null || destination.getAddress() == null) {
            return "PROXY UNKNOWN\r\n".getBytes(StandardCharsets.US_ASCII);
        }
        InetAddress src = source.getAddress();
        InetAddress dst = destination.getAddress();
        boolean v6 = src instanceof Inet6Address || dst instanceof Inet6Address;
        String line = "PROXY " + (v6 ? "TCP6 " : "TCP4 ")
                + text(src, v6) + " " + text(dst, v6) + " "
                + source.getPort() + " " + destination.getPort() + "\r\n";
        return line.getBytes(StandardCharsets.US_ASCII);
    }

    private static String text(InetAddress address, boolean v6) {
        if (v6 && !(address instanceof Inet6Address)) {
            return "::ffff:" + address.getHostAddress();
        }
        String s = address.getHostAddress();
        int scope = s.indexOf('%');
        return scope >= 0 ? s.substring(0, scope) : s;
    }
}
