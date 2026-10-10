// Ported from mitmproxy (MIT License, see META-INF/LICENSE-mitmproxy.txt):
// - mitmproxy/proxy/layers/tls.py: handshake_record_contents, get_client_hello, parse_client_hello;
// - mitmproxy/net/tls.py: starts_like_tls_record;
// - mitmproxy/tls.py: ClientHello.sni and ClientHello.alpn_protocols;
// - mitmproxy/contrib/kaitaistruct/tls_client_hello.ksy: the layout of the message;
// - mitmproxy/net/check.py: is_valid_host, for the SNI.
// Changes: a bound on the message size, the supported_versions extension, and errors for messages
// that end early instead of reading past them.
package org.microproxy.impl;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.microproxy.ClientHello;

/**
 * Finds and parses a TLS {@code ClientHello} at the start of a connection: the handshake message
 * may span several TLS records (as large post-quantum key shares make it do), and the records may
 * arrive in pieces, so the caller reads more bytes until {@link #message} has them all.
 */
final class TlsClientHello {

    /** The largest ClientHello message the proxy buffers: real ones are a few KiB at most. */
    static final int MAX_MESSAGE_SIZE = 64 * 1024;

    /** The largest TLS plaintext record (RFC 8446 section 5.1). */
    private static final int MAX_RECORD_SIZE = 1 << 14;
    /** TLS record content type of handshake messages. */
    private static final int HANDSHAKE = 0x16;
    /** Handshake message type of a ClientHello. */
    private static final int CLIENT_HELLO = 0x01;
    private static final int EXT_SERVER_NAME = 0x0000;
    private static final int EXT_ALPN = 0x0010;
    private static final int EXT_SUPPORTED_VERSIONS = 0x002b;

    private TlsClientHello() {}

    /** The bytes are not the start of a ClientHello the proxy can read. */
    static final class Malformed extends Exception {
        Malformed(String message) {
            super(message);
        }
    }

    /** The ClientHello is larger than {@link #MAX_MESSAGE_SIZE}. */
    static final class TooLarge extends Exception {
        TooLarge(String message) {
            super(message);
        }
    }

    /**
     * Whether {@code data} could start a TLS record: a handshake record of SSL 3.0 to TLS 1.3
     * ({@code 0x16 0x03 0x00..0x03}). A client that sends fewer than three bytes first is taken not
     * to speak TLS; with fewer than three received, this tells only whether the bytes so far agree.
     *
     * @param len how many bytes of {@code data} have been received
     */
    static boolean startsLikeTlsRecord(byte[] data, int len) {
        return startsLikeTlsRecord(data, 0, len);
    }

    private static boolean startsLikeTlsRecord(byte[] data, int off, int len) {
        if (len < 1 || (data[off] & 0xff) != HANDSHAKE) return false;
        if (len < 2) return true;
        if (data[off + 1] != 0x03) return false;
        return len < 3 || (data[off + 2] & 0xff) <= 0x03;
    }

    /**
     * The ClientHello handshake message at the start of {@code data[0, len)}, gathered from the
     * TLS records that carry it, without their headers: its type, 3-byte length and body.
     *
     * @param need set to the number of bytes, from the start of {@code data}, that the next step
     *     needs when the message is not complete yet
     * @return the message, or {@code null} when more bytes are needed
     * @throws Malformed if the records do not carry a ClientHello
     * @throws TooLarge if the message is longer than {@code maxSize}
     */
    static byte[] message(byte[] data, int len, int maxSize, int[] need) throws Malformed, TooLarge {
        byte[] message = new byte[0];
        int size = 0;
        int offset = 0;
        while (true) {
            if (len < offset + 5) {
                need[0] = offset + 5;
                return null;
            }
            if (!startsLikeTlsRecord(data, offset, 3)) {
                throw new Malformed("expected a TLS handshake record");
            }
            int recordSize = u16(data, offset + 3);
            if (recordSize == 0) throw new Malformed("empty TLS record");
            if (size + recordSize > maxSize + 4 + MAX_RECORD_SIZE) {
                // Even the record that completes a message of the largest size would be smaller.
                throw new TooLarge("ClientHello records exceed " + maxSize + " bytes");
            }
            offset += 5;
            if (len < offset + recordSize) {
                need[0] = offset + recordSize;
                return null;
            }
            message = Arrays.copyOf(message, size + recordSize);
            System.arraycopy(data, offset, message, size, recordSize);
            size += recordSize;
            offset += recordSize;
            if (size >= 4) {
                if ((message[0] & 0xff) != CLIENT_HELLO) {
                    throw new Malformed("the first handshake message is not a ClientHello");
                }
                int messageSize = ((message[1] & 0xff) << 16 | u16(message, 2)) + 4;
                if (messageSize - 4 > maxSize) {
                    throw new TooLarge("ClientHello of " + (messageSize - 4) + " bytes exceeds " + maxSize);
                }
                if (size >= messageSize) {
                    return Arrays.copyOf(message, messageSize);
                }
            }
        }
    }

    /**
     * Parses a ClientHello handshake message, as {@link #message} returns it.
     *
     * @throws Malformed if the message is cut short or its fields overrun it
     */
    static ClientHello parse(byte[] message) throws Malformed {
        if (message.length < 4 || (message[0] & 0xff) != CLIENT_HELLO) {
            throw new Malformed("not a ClientHello message");
        }
        Cursor c = new Cursor(message, 4, message.length);
        int legacyVersion = c.u16();
        c.skip(32); // random
        c.skip(c.u8()); // session id
        int cipherBytes = c.u16();
        if (cipherBytes % 2 != 0) throw new Malformed("odd cipher suite list length");
        Cursor ciphers = c.slice(cipherBytes);
        List<Integer> cipherSuites = new ArrayList<>(cipherBytes / 2);
        while (ciphers.remaining() > 0) cipherSuites.add(ciphers.u16());
        c.skip(c.u8()); // compression methods

        String sni = null;
        List<String> alpn = List.of();
        List<Integer> versions = null;
        List<Integer> types = new ArrayList<>();
        if (c.remaining() > 0) {
            Cursor extensions = c.slice(c.u16());
            boolean sawAlpn = false;
            while (extensions.remaining() > 0) {
                int type = extensions.u16();
                Cursor body = extensions.slice(extensions.u16());
                types.add(type);
                if (type == EXT_SERVER_NAME && sni == null) {
                    sni = serverName(body);
                } else if (type == EXT_ALPN && !sawAlpn) {
                    sawAlpn = true;
                    alpn = alpn(body);
                } else if (type == EXT_SUPPORTED_VERSIONS && versions == null) {
                    versions = supportedVersions(body);
                }
            }
        }
        if (versions == null) versions = List.of(legacyVersion);
        return new ClientHello(sni, alpn, versions, cipherSuites, types, message);
    }

    /** The host name of a server_name extension holding exactly one, valid host name; else null. */
    private static String serverName(Cursor body) throws Malformed {
        Cursor names = body.slice(body.u16());
        List<String> hosts = new ArrayList<>(1);
        boolean onlyHostNames = true;
        while (names.remaining() > 0) {
            int nameType = names.u8();
            byte[] name = names.bytes(names.u16());
            onlyHostNames &= nameType == 0;
            hosts.add(new String(name, StandardCharsets.ISO_8859_1));
        }
        if (hosts.size() != 1 || !onlyHostNames || !isValidHost(hosts.getFirst())) return null;
        return hosts.getFirst();
    }

    private static List<String> alpn(Cursor body) throws Malformed {
        Cursor protocols = body.slice(body.u16());
        List<String> names = new ArrayList<>();
        while (protocols.remaining() > 0) {
            names.add(new String(protocols.bytes(protocols.u8()), StandardCharsets.ISO_8859_1));
        }
        return names;
    }

    private static List<Integer> supportedVersions(Cursor body) throws Malformed {
        int bytes = body.u8();
        if (bytes % 2 != 0) throw new Malformed("odd supported_versions length");
        Cursor list = body.slice(bytes);
        List<Integer> versions = new ArrayList<>(bytes / 2);
        while (list.remaining() > 0) versions.add(list.u16());
        return versions;
    }

    /**
     * A DNS name (labels of letters, digits, hyphens and underscores, at most 255 bytes, with an
     * optional final dot) or an IP address, as mitmproxy's {@code is_valid_host} accepts.
     */
    static boolean isValidHost(String host) {
        if (host.isEmpty() || host.length() > 255) return false;
        String name = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        boolean dns = !name.isEmpty();
        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63) {
                dns = false;
                break;
            }
            for (int i = 0; i < label.length() && dns; i++) {
                char ch = label.charAt(i);
                dns = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
                        || ch == '-' || ch == '_';
            }
            if (!dns) break;
        }
        if (dns) return true;
        // An IPv6 literal (an IPv4 one is a valid DNS name above).
        if (host.indexOf(':') < 0) return false;
        for (int i = 0; i < host.length(); i++) {
            char ch = host.charAt(i);
            if (Character.digit(ch, 16) < 0 && ch != ':' && ch != '.') return false;
        }
        return true;
    }

    private static int u16(byte[] b, int at) {
        return (b[at] & 0xff) << 8 | (b[at + 1] & 0xff);
    }

    /** Reads big-endian fields from {@code data[pos, end)}, failing rather than reading past the end. */
    private static final class Cursor {
        private final byte[] data;
        private int pos;
        private final int end;

        Cursor(byte[] data, int pos, int end) {
            this.data = data;
            this.pos = pos;
            this.end = end;
        }

        int remaining() {
            return end - pos;
        }

        private void need(int n) throws Malformed {
            if (n < 0 || n > end - pos) throw new Malformed("ClientHello ends early");
        }

        int u8() throws Malformed {
            need(1);
            return data[pos++] & 0xff;
        }

        int u16() throws Malformed {
            need(2);
            int v = TlsClientHello.u16(data, pos);
            pos += 2;
            return v;
        }

        void skip(int n) throws Malformed {
            need(n);
            pos += n;
        }

        byte[] bytes(int n) throws Malformed {
            need(n);
            byte[] b = Arrays.copyOfRange(data, pos, pos + n);
            pos += n;
            return b;
        }

        /** The next {@code n} bytes as a cursor of their own; this one moves past them. */
        Cursor slice(int n) throws Malformed {
            need(n);
            Cursor c = new Cursor(data, pos, pos + n);
            pos += n;
            return c;
        }
    }
}
