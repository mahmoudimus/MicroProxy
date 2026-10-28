// Ported from rustls src/msgs/handshake.rs, src/msgs/client_hello.rs and src/msgs/server_hello.rs
// (the extension payloads: ServerNamePayload, NamedGroups, SignatureSchemes, ProtocolNames,
// SupportedProtocolVersions, KeyShareEntry, PskKeyExchangeModes, PresharedKeyOffer,
// PresharedKeyIdentity and PresharedKeyBinder, the early_data payloads, and
// DuplicateExtensionChecker) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Encoders and decoders for the bodies of the extensions the handshake uses. */
final class Extensions {

    private Extensions() {}

    /** A {@code KeyShareEntry}: a group and its public key. */
    record KeyShare(int group, byte[] keyExchange) {}

    /** Fails with {@code illegal_parameter} if an extension type repeats (RFC 8446 section 4.2). */
    static void checkNoDuplicates(List<Extension> extensions, String message) throws QuicException {
        Set<Integer> seen = new HashSet<>();
        for (Extension e : extensions) {
            if (!seen.add(e.type())) {
                throw TlsAlert.illegalParameter(message + " repeats " + ExtensionType.name(e.type()));
            }
        }
    }

    // --- server_name (RFC 6066 section 3) ---

    static byte[] encodeServerName(String host) {
        Writer w = new Writer();
        int list = w.open(2);
        w.u8(0).vector16(host.getBytes(StandardCharsets.US_ASCII));
        w.close(list);
        return w.toByteArray();
    }

    /**
     * The host name in a ClientHello's {@code server_name}, normalized to lower case without a
     * trailing dot; or null if it names no DNS host (an IP literal, which RFC 6066 forbids, is
     * treated as no name).
     */
    static String decodeServerName(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        Reader list = r.sub16("server_name_list");
        r.expectEnd("server_name");
        if (!list.hasRemaining()) throw TlsAlert.decodeError("empty server_name_list");
        String host = null;
        boolean sawHostName = false;
        while (list.hasRemaining()) {
            int nameType = list.u8("name_type");
            byte[] name = list.vector16(1, "server name");
            if (nameType != 0) continue;
            if (sawHostName) throw TlsAlert.decodeError("server_name repeats host_name");
            sawHostName = true;
            host = normalizeHostName(name);
        }
        return host;
    }

    private static String normalizeHostName(byte[] name) throws QuicException {
        for (byte b : name) {
            if (b <= 0x20 || b >= 0x7f) throw TlsAlert.decodeError("server name is not a printable ASCII name");
        }
        String host = new String(name, StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || HostnameChecker.isIpLiteral(host)) return null;
        return host;
    }

    // --- lists of two-byte code points: supported_groups, signature_algorithms ---

    static byte[] encodeU16List(int[] values) {
        Writer w = new Writer();
        int list = w.open(2);
        for (int v : values) w.u16(v);
        w.close(list);
        return w.toByteArray();
    }

    static int[] decodeU16List(byte[] data, String what) throws QuicException {
        Reader r = new Reader(data);
        int[] values = r.u16List16(1, what);
        r.expectEnd(what);
        return values;
    }

    // --- application_layer_protocol_negotiation (RFC 7301) ---

    static byte[] encodeAlpn(List<byte[]> protocols) {
        Writer w = new Writer();
        int list = w.open(2);
        for (byte[] p : protocols) w.vector8(p);
        w.close(list);
        return w.toByteArray();
    }

    static List<byte[]> decodeAlpn(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        Reader list = r.sub16("protocol_name_list");
        r.expectEnd("application_layer_protocol_negotiation");
        List<byte[]> out = new ArrayList<>();
        while (list.hasRemaining()) {
            out.add(list.vector8(1, "protocol name"));
        }
        if (out.isEmpty()) throw TlsAlert.decodeError("empty protocol_name_list");
        return out;
    }

    // --- supported_versions (RFC 8446 section 4.2.1) ---

    static byte[] encodeSupportedVersionsClient(int... versions) {
        Writer w = new Writer();
        int list = w.open(1);
        for (int v : versions) w.u16(v);
        w.close(list);
        return w.toByteArray();
    }

    static int[] decodeSupportedVersionsClient(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        Reader list = r.sub8("supported_versions");
        r.expectEnd("supported_versions");
        if (list.remaining() < 2 || (list.remaining() & 1) != 0) {
            throw TlsAlert.decodeError("supported_versions has a bad length");
        }
        int[] out = new int[list.remaining() / 2];
        for (int i = 0; i < out.length; i++) out[i] = list.u16("supported_versions");
        return out;
    }

    static byte[] encodeSupportedVersionServer(int version) {
        return new Writer().u16(version).toByteArray();
    }

    static int decodeSupportedVersionServer(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        int version = r.u16("selected_version");
        r.expectEnd("supported_versions");
        return version;
    }

    // --- key_share (RFC 8446 section 4.2.8) ---

    static byte[] encodeKeyShareClient(List<KeyShare> shares) {
        Writer w = new Writer();
        int list = w.open(2);
        for (KeyShare s : shares) w.u16(s.group()).vector16(s.keyExchange());
        w.close(list);
        return w.toByteArray();
    }

    static List<KeyShare> decodeKeyShareClient(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        Reader list = r.sub16("client_shares");
        r.expectEnd("key_share");
        List<KeyShare> out = new ArrayList<>();
        while (list.hasRemaining()) {
            int group = list.u16("key share group");
            out.add(new KeyShare(group, list.vector16(1, "key_exchange")));
        }
        return out;
    }

    static byte[] encodeKeyShareServer(KeyShare share) {
        return new Writer().u16(share.group()).vector16(share.keyExchange()).toByteArray();
    }

    static KeyShare decodeKeyShareServer(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        KeyShare share = new KeyShare(r.u16("key share group"), r.vector16(1, "key_exchange"));
        r.expectEnd("key_share");
        return share;
    }

    static byte[] encodeKeyShareRetry(int group) {
        return new Writer().u16(group).toByteArray();
    }

    static int decodeKeyShareRetry(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        int group = r.u16("selected_group");
        r.expectEnd("key_share");
        return group;
    }

    // --- cookie (RFC 8446 section 4.2.2) ---

    static byte[] encodeCookie(byte[] cookie) {
        return new Writer().vector16(cookie).toByteArray();
    }

    static byte[] decodeCookie(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        byte[] cookie = r.vector16(0, "cookie");
        r.expectEnd("cookie");
        return cookie;
    }

    // --- psk_key_exchange_modes (RFC 8446 section 4.2.9) ---

    /** {@code psk_ke}: PSK-only key establishment, which this implementation never uses. */
    static final int PSK_KE = 0;
    /** {@code psk_dhe_ke}: PSK with (EC)DHE key establishment. */
    static final int PSK_DHE_KE = 1;

    static byte[] encodePskKeyExchangeModes(int... modes) {
        Writer w = new Writer();
        int list = w.open(1);
        for (int m : modes) w.u8(m);
        w.close(list);
        return w.toByteArray();
    }

    static byte[] decodePskKeyExchangeModes(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        byte[] modes = r.vector8(1, "ke_modes");
        r.expectEnd("psk_key_exchange_modes");
        return modes;
    }

    // --- pre_shared_key (RFC 8446 section 4.2.11) ---

    /** A {@code PskIdentity}: a ticket and its obfuscated age. */
    record PskIdentity(byte[] identity, long obfuscatedTicketAge) {}

    /**
     * A ClientHello's {@code OfferedPsks}.
     *
     * @param bindersLength the length of the encoded binders list, with its two-byte length: what
     *     the truncated ClientHello leaves out
     */
    record PskOffer(List<PskIdentity> identities, List<byte[]> binders, int bindersLength) {}

    static byte[] encodePskOffer(List<PskIdentity> identities, List<byte[]> binders) {
        Writer w = new Writer();
        int ids = w.open(2);
        for (PskIdentity id : identities) w.vector16(id.identity()).u32(id.obfuscatedTicketAge());
        w.close(ids);
        int list = w.open(2);
        for (byte[] b : binders) w.vector8(b);
        w.close(list);
        return w.toByteArray();
    }

    static PskOffer decodePskOffer(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        Reader ids = r.sub16("identities");
        List<PskIdentity> identities = new ArrayList<>();
        while (ids.hasRemaining()) {
            identities.add(new PskIdentity(ids.vector16(1, "identity"), ids.u32("obfuscated_ticket_age")));
        }
        int bindersLength = r.remaining();
        Reader list = r.sub16("binders");
        r.expectEnd("pre_shared_key");
        List<byte[]> binders = new ArrayList<>();
        while (list.hasRemaining()) {
            binders.add(list.vector8(32, "PskBinderEntry"));
        }
        if (identities.isEmpty() || binders.isEmpty()) throw TlsAlert.decodeError("empty pre_shared_key offer");
        return new PskOffer(identities, binders, bindersLength);
    }

    static byte[] encodePskSelected(int identity) {
        return new Writer().u16(identity).toByteArray();
    }

    static int decodePskSelected(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        int selected = r.u16("selected_identity");
        r.expectEnd("pre_shared_key");
        return selected;
    }

    // --- early_data (RFC 8446 section 4.2.10) ---

    static byte[] encodeMaxEarlyDataSize(long size) {
        return new Writer().u32(size).toByteArray();
    }

    /** A body that is one uint16, such as {@code record_size_limit}'s. */
    static int decodeU16(byte[] data, String what) throws QuicException {
        Reader r = new Reader(data);
        int v = r.u16(what);
        r.expectEnd(what);
        return v;
    }

    static long decodeMaxEarlyDataSize(byte[] data) throws QuicException {
        Reader r = new Reader(data);
        long size = r.u32("max_early_data_size");
        r.expectEnd("early_data");
        return size;
    }

    /** Fails with {@code decode_error} unless an extension body is empty, as acknowledgements are. */
    static void expectEmpty(byte[] data, int type) throws QuicException {
        if (data.length != 0) throw TlsAlert.decodeError(ExtensionType.name(type) + " should be empty");
    }
}
