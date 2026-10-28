// The parsing and selection follow Go src/crypto/tls/ech.go (parseECHConfigList, pickECHConfig)
// (BSD-3-Clause, Copyright 2024 The Go Authors), with the public_name check of RFC 9849 section
// 6.1.7.
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * One ECHConfig of version {@code 0xfe0d} (RFC 9849 section 4): the server's HPKE key and the
 * suites it accepts, the longest name it expects, the public name the outer ClientHello carries,
 * and the configuration's extensions.
 *
 * @param raw the whole ECHConfig as received, version and length included: HPKE's {@code info}
 *     is {@code "tls ech" || 0x00 || raw}
 * @param configId the {@code config_id} the outer extension names
 * @param kemId the HPKE KEM
 * @param publicKey the HPKE public key
 * @param cipherSuites the HPKE KDF and AEAD pairs, in the server's order
 * @param maximumNameLength the longest server name the server expects, for padding
 * @param publicName the client-facing server's name
 * @param extensions the configuration's extensions
 */
record EchConfig(byte[] raw, int configId, int kemId, byte[] publicKey, List<SymmetricSuite> cipherSuites,
        int maximumNameLength, String publicName, List<Extension> extensions) {

    /** The ECHConfig version of RFC 9849, also the extension's codepoint. */
    static final int VERSION = 0xfe0d;

    EchConfig {
        cipherSuites = List.copyOf(cipherSuites);
        extensions = List.copyOf(extensions);
    }

    /** An {@code HpkeSymmetricCipherSuite}: a KDF id and an AEAD id. */
    record SymmetricSuite(int kdfId, int aeadId) {}

    /** An ECHConfig extension; mandatory when the type's high bit is set (RFC 9849 section 4.2). */
    record Extension(int type, byte[] data) {
        boolean mandatory() {
            return (type & 0x8000) != 0;
        }
    }

    /** The configuration a client offers ECH with: the config, and the suite chosen from it. */
    record Selected(EchConfig config, int kdfId, Hpke.Aead aead) {}

    /**
     * Parses an ECHConfigList. Configurations of other versions are skipped by their length, as
     * RFC 9849 section 4 requires; anything malformed fails the whole list.
     *
     * @param list the list with its two-byte length prefix
     * @return the version {@code 0xfe0d} configurations, in order
     * @throws QuicException a {@code decode_error} if the list is malformed
     */
    static List<EchConfig> parseList(byte[] list) throws QuicException {
        Reader outer = new Reader(list);
        Reader r = outer.sub16("ECHConfigList");
        outer.expectEnd("ECHConfigList");
        if (!r.hasRemaining()) throw TlsAlert.decodeError("empty ECHConfigList");
        List<EchConfig> out = new ArrayList<>();
        while (r.hasRemaining()) {
            int start = list.length - r.remaining();
            int version = r.u16("ECHConfig version");
            byte[] contents = r.vector16(0, "ECHConfig contents");
            if (version != VERSION) continue;
            byte[] raw = java.util.Arrays.copyOfRange(list, start, start + 4 + contents.length);
            out.add(parseContents(raw, contents));
        }
        return out;
    }

    private static EchConfig parseContents(byte[] raw, byte[] contents) throws QuicException {
        Reader r = new Reader(contents);
        int configId = r.u8("ECHConfig config_id");
        int kemId = r.u16("ECHConfig kem_id");
        byte[] publicKey = r.vector16(1, "ECHConfig public_key");
        Reader suites = r.sub16("ECHConfig cipher_suites");
        if (!suites.hasRemaining() || suites.remaining() % 4 != 0) {
            throw TlsAlert.decodeError("ECHConfig cipher_suites of " + suites.remaining() + " bytes");
        }
        List<SymmetricSuite> cipherSuites = new ArrayList<>();
        while (suites.hasRemaining()) {
            cipherSuites.add(new SymmetricSuite(suites.u16("kdf_id"), suites.u16("aead_id")));
        }
        int maximumNameLength = r.u8("ECHConfig maximum_name_length");
        byte[] name = r.vector8(1, "ECHConfig public_name");
        Reader exts = r.sub16("ECHConfig extensions");
        List<Extension> extensions = new ArrayList<>();
        while (exts.hasRemaining()) {
            extensions.add(new Extension(exts.u16("ECHConfig extension type"), exts.vector16(0, "ECHConfig extension data")));
        }
        r.expectEnd("ECHConfig");
        return new EchConfig(raw, configId, kemId, publicKey, cipherSuites, maximumNameLength,
                new String(name, StandardCharsets.ISO_8859_1), extensions);
    }

    /**
     * The configuration to offer ECH with: the first of {@code list} that this client can use,
     * with the first of its suites that {@link Hpke} implements. A configuration is skipped if its
     * KEM or every suite is unsupported, its public key is not a KEM key, its public name is not a
     * valid host name (RFC 9849 section 6.1.7), or it has a mandatory extension (all are unknown
     * here) or an extension twice.
     *
     * @return the selection, or null if no configuration can be used
     * @throws QuicException a {@code decode_error} if the list is malformed
     */
    static Selected select(byte[] list) throws QuicException {
        for (EchConfig config : parseList(list)) {
            if (config.kemId != Hpke.KEM_X25519_HKDF_SHA256 || config.publicKey.length != Hpke.X25519_KEY_LENGTH) continue;
            if (!validPublicName(config.publicName)) continue;
            Set<Integer> seen = new HashSet<>();
            boolean usable = true;
            for (Extension e : config.extensions) usable &= !e.mandatory() && seen.add(e.type());
            if (!usable) continue;
            for (SymmetricSuite s : config.cipherSuites) {
                if (Hpke.supports(config.kemId, s.kdfId(), s.aeadId())) {
                    return new Selected(config, s.kdfId(), Hpke.Aead.forId(s.aeadId()));
                }
            }
        }
        return null;
    }

    /**
     * Whether {@code name} is a host name in preferred name syntax whose last label could not be
     * read as an IPv4 address (RFC 9849 section 6.1.7): dot-separated LDH labels of 1 to 63
     * octets, the last neither all digits nor {@code 0x} and hex digits.
     */
    static boolean validPublicName(String name) {
        if (name.isEmpty() || name.length() > 253 || name.startsWith(".") || name.endsWith(".")) return false;
        String[] labels = name.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) return false;
            if (label.startsWith("-") || label.endsWith("-")) return false;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean ldh = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
                if (!ldh) return false;
            }
        }
        String last = labels[labels.length - 1];
        if (last.chars().allMatch(c -> c >= '0' && c <= '9')) return false;
        if (last.length() >= 2 && last.charAt(0) == '0' && (last.charAt(1) == 'x' || last.charAt(1) == 'X')
                && last.substring(2).chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            return false;
        }
        return true;
    }
}
