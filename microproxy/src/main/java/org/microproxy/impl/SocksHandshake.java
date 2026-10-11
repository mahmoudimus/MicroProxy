// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// - mitmproxy/proxy/layers/modes.py: Socks5Proxy, the server side of the SOCKS5 handshake.
// Changes: blocking reads with bounded fields; the authenticator decides whether a client without
// credentials may proceed; SOCKS4 and 4a requests; replies that tell why a connection failed.
package org.microproxy.impl;

import static org.microproxy.impl.Socks.ADDRESS_DOMAIN;
import static org.microproxy.impl.Socks.ADDRESS_IPV4;
import static org.microproxy.impl.Socks.ADDRESS_IPV6;
import static org.microproxy.impl.Socks.AUTH_FAILURE;
import static org.microproxy.impl.Socks.AUTH_SUCCESS;
import static org.microproxy.impl.Socks.AUTH_VERSION;
import static org.microproxy.impl.Socks.COMMAND_CONNECT;
import static org.microproxy.impl.Socks.METHOD_NO_ACCEPTABLE;
import static org.microproxy.impl.Socks.METHOD_NO_AUTHENTICATION;
import static org.microproxy.impl.Socks.METHOD_USERNAME_PASSWORD;
import static org.microproxy.impl.Socks.VERSION_4;
import static org.microproxy.impl.Socks.VERSION_5;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.microproxy.ProxyFailure;

/**
 * The server side of a SOCKS handshake: SOCKS5 (RFC 1928) with no authentication or username and
 * password (RFC 1929), and SOCKS4 with its 4a extension (host names). Only {@code CONNECT} is
 * served. The handshake ends with the destination, before any reply to the request: the proxy
 * connects first, and then answers with {@link #reply}.
 */
final class SocksHandshake {

    /** The longest SOCKS4 user id or 4a host name accepted, as SOCKS5 bounds its fields. */
    static final int MAX_FIELD = 255;

    private SocksHandshake() {}

    /** Reads the client's bytes: buffers at least {@code n} of them, within the handshake's deadline. */
    @FunctionalInterface
    interface Input {
        /**
         * Buffers at least {@code n} bytes of the client's, without consuming them.
         *
         * @return false if the client closed the connection first
         */
        boolean ensure(int n) throws IOException;
    }

    /** Writes bytes to the client. */
    @FunctionalInterface
    interface Output {
        void write(byte[] bytes) throws IOException;
    }

    /** Asks the proxy's authenticator about a client while it authenticates. */
    interface Authenticator {
        /** Whether the proxy authenticates its clients at all. */
        boolean required();

        /** Whether a client that has no credentials to give may proceed (asked only when {@link #required}). */
        boolean acceptsWithout();

        /** Whether the username and password a SOCKS5 client gave are accepted (asked only when {@link #required}). */
        boolean accepts(String user, String password);
    }

    /**
     * Where the client asked to go, and how it authenticated.
     *
     * @param version {@link Socks#VERSION_5}, or {@link Socks#VERSION_4} for SOCKS4 and 4a
     * @param host a host name or an IP address literal (IPv6 without brackets)
     * @param port the destination port, 1 to 65535
     * @param user the SOCKS5 username, or null without username/password authentication
     * @param password the SOCKS5 password, or null
     */
    record Destination(int version, String host, int port, String user, String password) {
        /** {@return the destination as {@code host:port}, with IPv6 literals in brackets} */
        String hostAndPort() {
            return new HostAndPort(host, port).toString();
        }
    }

    /** Why a handshake was refused. */
    enum Refusal {
        /** The client's authentication was refused, or it offered none the proxy accepts. */
        AUTHENTICATION,
        /** The client asked for a command other than CONNECT. */
        COMMAND,
        /** Anything else: an address the proxy cannot use. */
        OTHER
    }

    /** The handshake was refused, and the client told so if the protocol has a way. */
    static final class Refused extends ProtocolException {
        /** Why. */
        final Refusal refusal;
        /** The SOCKS5 code of the reply the client was sent, or -1 for none. */
        final int reply;

        Refused(String message, Refusal refusal, int reply) {
            super(message);
            this.refusal = refusal;
            this.reply = reply;
        }
    }

    /**
     * Runs the handshake up to the client's request, whose first byte (the version) has been
     * received and not consumed.
     *
     * @return the destination, which the proxy answers with {@link #reply} once it knows the outcome
     * @throws Refused if the proxy refused the client (and told it so where the protocol can)
     * @throws ProtocolException if the client broke the protocol
     * @throws EOFException if the client closed the connection within the handshake
     */
    static Destination accept(ByteReader in, Input input, Output out, Authenticator auth) throws IOException {
        int version = peek(in, input);
        return switch (version) {
            case VERSION_5 -> accept5(in, input, out, auth);
            case VERSION_4 -> accept4(in, input, out, auth);
            default -> throw new ProtocolException("not a SOCKS client (first byte 0x"
                    + Integer.toHexString(version) + ")");
        };
    }

    private static Destination accept5(ByteReader in, Input input, Output out, Authenticator auth) throws IOException {
        // Greeting: VER NMETHODS METHODS...
        need(input, 2);
        in.read();
        int count = in.read();
        need(input, count);
        boolean noAuthentication = false;
        boolean usernamePassword = false;
        for (int i = 0; i < count; i++) {
            int method = in.read();
            noAuthentication |= method == METHOD_NO_AUTHENTICATION;
            usernamePassword |= method == METHOD_USERNAME_PASSWORD;
        }
        int method;
        if (!auth.required()) {
            method = noAuthentication ? METHOD_NO_AUTHENTICATION : METHOD_NO_ACCEPTABLE;
        } else if (usernamePassword) {
            method = METHOD_USERNAME_PASSWORD;
        } else {
            method = noAuthentication && auth.acceptsWithout() ? METHOD_NO_AUTHENTICATION : METHOD_NO_ACCEPTABLE;
        }
        out.write(new byte[] {VERSION_5, (byte) method});
        if (method == METHOD_NO_ACCEPTABLE) {
            throw new Refused(auth.required()
                    ? "the client offers no SOCKS5 authentication the proxy accepts"
                    : "the client does not offer SOCKS5 without authentication", Refusal.AUTHENTICATION, -1);
        }

        String user = null;
        String password = null;
        if (method == METHOD_USERNAME_PASSWORD) {
            // RFC 1929: VER ULEN UNAME PLEN PASSWD, each field at most 255 bytes by its length byte.
            need(input, 2);
            int subVersion = in.read();
            if (subVersion != AUTH_VERSION) {
                throw new ProtocolException("unknown SOCKS5 username/password version " + subVersion);
            }
            user = string(in, input, in.read());
            need(input, 1);
            password = string(in, input, in.read());
            boolean accepted = auth.accepts(user, password);
            out.write(new byte[] {AUTH_VERSION, (byte) (accepted ? AUTH_SUCCESS : AUTH_FAILURE)});
            if (!accepted) throw new Refused("SOCKS5 credentials rejected for user " + user, Refusal.AUTHENTICATION, -1);
        }

        // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        need(input, 4);
        int requestVersion = in.read();
        int command = in.read();
        in.read();
        int type = in.read();
        if (requestVersion != VERSION_5) {
            throw new ProtocolException("SOCKS5 request with version " + requestVersion);
        }
        if (command != COMMAND_CONNECT) {
            out.write(reply(VERSION_5, Socks.REPLY_COMMAND_NOT_SUPPORTED));
            throw new Refused("unsupported SOCKS5 command " + command + " (only CONNECT is)", Refusal.COMMAND,
                    Socks.REPLY_COMMAND_NOT_SUPPORTED);
        }
        String host = switch (type) {
            case ADDRESS_IPV4 -> address(in, input, 4);
            case ADDRESS_IPV6 -> address(in, input, 16);
            case ADDRESS_DOMAIN -> {
                need(input, 1);
                int length = in.read();
                yield string(in, input, length);
            }
            default -> {
                out.write(reply(VERSION_5, Socks.REPLY_ADDRESS_TYPE_NOT_SUPPORTED));
                throw new Refused("unsupported SOCKS5 address type " + type, Refusal.OTHER,
                        Socks.REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
            }
        };
        int port = port(in, input);
        String invalid = invalid(host, port);
        if (invalid != null) {
            out.write(reply(VERSION_5, Socks.REPLY_GENERAL_FAILURE));
            throw new Refused(invalid, Refusal.OTHER, Socks.REPLY_GENERAL_FAILURE);
        }
        return new Destination(VERSION_5, host, port, user, password);
    }

    private static Destination accept4(ByteReader in, Input input, Output out, Authenticator auth) throws IOException {
        // VN CD DSTPORT DSTIP USERID NULL [HOST NULL]
        need(input, 2);
        in.read();
        int command = in.read();
        int port = port(in, input);
        need(input, 4);
        byte[] ip = new byte[4];
        in.readFully(ip, 0, 4);
        // The user id is a name, not a credential: it is read and not trusted.
        nullTerminated(in, input);
        // 0.0.0.x (x not 0): SOCKS4a, a host name follows.
        boolean named = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
        String host = named ? nullTerminated(in, input) : InetAddress.getByAddress(ip).getHostAddress();
        if (command != COMMAND_CONNECT) {
            out.write(reply(VERSION_4, Socks.REPLY_COMMAND_NOT_SUPPORTED));
            throw new Refused("unsupported SOCKS4 command " + command + " (only CONNECT is)", Refusal.COMMAND,
                    Socks.REPLY_COMMAND_NOT_SUPPORTED);
        }
        if (auth.required() && !auth.acceptsWithout()) {
            out.write(reply(VERSION_4, Socks.REPLY_NOT_ALLOWED));
            throw new Refused("SOCKS4 has no credentials to give the proxy's authenticator", Refusal.AUTHENTICATION,
                    Socks.REPLY_NOT_ALLOWED);
        }
        String invalid = invalid(host, port);
        if (invalid != null) {
            out.write(reply(VERSION_4, Socks.REPLY_GENERAL_FAILURE));
            throw new Refused(invalid, Refusal.OTHER, Socks.REPLY_GENERAL_FAILURE);
        }
        return new Destination(VERSION_4, host, port, null, null);
    }

    /**
     * The reply to a request: {@code code} (a SOCKS5 reply code) with the bound address {@code
     * 0.0.0.0:0}, as mitmproxy sends it; SOCKS4 knows only granted and rejected.
     *
     * @param version the client's SOCKS version
     * @param code {@link Socks#REPLY_SUCCEEDED} or a failure's SOCKS5 code
     */
    static byte[] reply(int version, int code) {
        if (version == VERSION_4) {
            int status = code == Socks.REPLY_SUCCEEDED ? Socks.REPLY_4_GRANTED : Socks.REPLY_4_REJECTED;
            return new byte[] {Socks.REPLY_VERSION_4, (byte) status, 0, 0, 0, 0, 0, 0};
        }
        return new byte[] {VERSION_5, (byte) code, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0};
    }

    /** The SOCKS5 reply code for a request that failed with {@code failure}. */
    static int replyCode(ProxyFailure failure) {
        return switch (failure) {
            case ProxyFailure.UnresolvedHost f -> Socks.REPLY_HOST_UNREACHABLE;
            case ProxyFailure.ConnectFailed f -> connectReplyCode(f.cause());
            case ProxyFailure.ServerTimeout f -> Socks.REPLY_TTL_EXPIRED;
            case ProxyFailure.NoRoute f -> Socks.REPLY_NOT_ALLOWED;
            case ProxyFailure.TlsFailed f -> Socks.REPLY_GENERAL_FAILURE;
            case ProxyFailure.BadServerResponse f -> Socks.REPLY_GENERAL_FAILURE;
            case ProxyFailure.NoConnectionAvailable f -> Socks.REPLY_GENERAL_FAILURE;
            case ProxyFailure.BadRequest f -> Socks.REPLY_GENERAL_FAILURE;
            case ProxyFailure.RequestTooLarge f -> Socks.REPLY_GENERAL_FAILURE;
        };
    }

    /**
     * The SOCKS5 reply code for a request the proxy or a filter answered with {@code status}
     * rather than a failure: a refusal ({@code 403}, {@code 407}, ...) is not allowed, {@code 504}
     * a timeout, other server errors a general failure.
     */
    static int replyCode(int status) {
        if (status == 504) return Socks.REPLY_TTL_EXPIRED;
        return status >= 500 ? Socks.REPLY_GENERAL_FAILURE : Socks.REPLY_NOT_ALLOWED;
    }

    /** Tells a refused, unreachable or timed-out connection from others by the exception's kind and text. */
    private static int connectReplyCode(IOException cause) {
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (t instanceof SocketTimeoutException) return Socks.REPLY_TTL_EXPIRED;
            if (t instanceof NoRouteToHostException) return Socks.REPLY_HOST_UNREACHABLE;
            if (t instanceof ConnectException) {
                String message = String.valueOf(t.getMessage()).toLowerCase(Locale.ROOT);
                if (message.contains("refused")) return Socks.REPLY_CONNECTION_REFUSED;
                if (message.contains("network is unreachable")) return Socks.REPLY_NETWORK_UNREACHABLE;
                if (message.contains("unreachable")) return Socks.REPLY_HOST_UNREACHABLE;
                if (message.contains("timed out")) return Socks.REPLY_TTL_EXPIRED;
            }
        }
        return Socks.REPLY_GENERAL_FAILURE;
    }

    /** Why {@code host} and {@code port} are no destination, or null if they are one. */
    private static String invalid(String host, int port) {
        if (port == 0) return "SOCKS destination port 0";
        if (host.isEmpty()) return "empty SOCKS destination host";
        boolean literal = host.indexOf(':') >= 0;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            boolean ok = literal
                    ? Character.digit(c, 16) >= 0 || c == ':' || c == '.'
                    : (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                            || c == '.' || c == '-' || c == '_';
            if (!ok) return "invalid SOCKS destination host";
        }
        return null;
    }

    private static int peek(ByteReader in, Input input) throws IOException {
        need(input, 1);
        return in.peek();
    }

    private static void need(Input input, int n) throws IOException {
        if (!input.ensure(n)) throw new EOFException("the client closed the connection within the SOCKS handshake");
    }

    private static String address(ByteReader in, Input input, int length) throws IOException {
        need(input, length);
        byte[] bytes = new byte[length];
        in.readFully(bytes, 0, length);
        return InetAddress.getByAddress(bytes).getHostAddress();
    }

    private static int port(ByteReader in, Input input) throws IOException {
        need(input, 2);
        return in.read() << 8 | in.read();
    }

    /** A field of {@code length} bytes (at most 255, by its length byte), decoded as UTF-8. */
    private static String string(ByteReader in, Input input, int length) throws IOException {
        need(input, length);
        byte[] bytes = new byte[length];
        in.readFully(bytes, 0, length);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** A SOCKS4 field ended by a zero byte, of at most {@link #MAX_FIELD} bytes before it. */
    private static String nullTerminated(ByteReader in, Input input) throws IOException {
        byte[] bytes = new byte[MAX_FIELD];
        for (int length = 0; ; length++) {
            need(input, 1);
            int b = in.read();
            if (b == 0) return new String(bytes, 0, length, StandardCharsets.ISO_8859_1);
            if (length == MAX_FIELD) throw new ProtocolException("SOCKS4 field longer than " + MAX_FIELD + " bytes");
            bytes[length] = (byte) b;
        }
    }
}
