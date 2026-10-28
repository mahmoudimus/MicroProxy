// The ClientHelloInner and its encoding follow BoringSSL ssl/encrypted_client_hello.cc
// (ssl_encrypt_client_hello: the padding, the AAD and the sealing) and ssl/extensions.cc
// (ssl_add_clienthello_tlsext_inner: which extensions the inner hello leaves out, which it
// compresses, and the compressed ones moved to the end) (ISC); the acceptance signals follow Go
// src/crypto/tls/handshake_client_tls13.go (BSD-3-Clause, Copyright 2018 The Go Authors).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.Hkdf;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The client side of one Encrypted Client Hello (RFC 9849) offer: the HPKE context for the
 * selected ECHConfig, the ClientHelloInner made from the profile's hello, and the
 * ClientHelloOuter that carries it encrypted.
 *
 * <p>The outer hello is the profile's hello for the configuration's public name, with the real
 * {@code encrypted_client_hello} in place of the profile's GREASE one, so it keeps the profile's
 * extensions, order, GREASE and key shares. The inner hello is derived from it as BoringSSL
 * derives Chrome's: the real server name, {@code encrypted_client_hello} of type inner, TLS 1.3
 * only in {@code supported_versions} and the cipher suites, no TLS 1.2-only extensions; every
 * other extension is the outer one's, and those are moved, in order, after the extensions that
 * differ, so the encoded inner hello replaces them with one {@code ech_outer_extensions}.
 */
final class EchClient {

    /** {@code ech_outer_extensions} (RFC 9849 section 5.1). */
    static final int ECH_OUTER_EXTENSIONS = 0xfd00;
    static final String ACCEPT_LABEL = "ech accept confirmation";
    static final String HRR_ACCEPT_LABEL = "hrr ech accept confirmation";
    /** The length of the acceptance signals (RFC 9849 section 7.2). */
    static final int CONFIRMATION_LENGTH = 8;

    /**
     * Extensions only TLS 1.2 uses, which the inner hello, offering TLS 1.3 alone, leaves out:
     * extended_master_secret, renegotiation_info, session_ticket, ec_point_formats, padding,
     * NPN and Channel ID.
     */
    private static final Set<Integer> TLS12_ONLY = Set.of(23, 0xff01, 35, 11, 21, 13172, 30032);

    private final EchConfig.Selected selected;
    private final String innerName;
    private final byte[] innerRandom;
    private final byte[] enc;
    private final Hpke.Context hpke;

    /** The inner hello and which of its extensions the encoding takes from the outer hello. */
    record Inner(ClientHello hello, Set<Integer> compressed) {}

    /**
     * Sets up HPKE for {@code selected}: {@code SetupBaseS(pkR, "tls ech" || 0x00 || ECHConfig)}.
     *
     * @param innerName the real server name, or null to send none in the inner hello
     */
    EchClient(EchConfig.Selected selected, String innerName, SecureRandom random) throws GeneralSecurityException {
        this.selected = selected;
        this.innerName = innerName;
        this.innerRandom = new byte[32];
        random.nextBytes(innerRandom);
        byte[] prefix = "tls ech\0".getBytes(StandardCharsets.US_ASCII);
        byte[] raw = selected.config().raw();
        byte[] info = Arrays.copyOf(prefix, prefix.length + raw.length);
        System.arraycopy(raw, 0, info, prefix.length, raw.length);
        Hpke.Sender sender = Hpke.setupBaseS(selected.config().publicKey(), info, selected.aead(), random);
        this.enc = sender.enc();
        this.hpke = sender.context();
    }

    /** {@return the configuration's public name, the outer hello's server name} */
    String publicName() {
        return selected.config().publicName();
    }

    /** {@return the inner hello's random} */
    byte[] innerRandom() {
        return innerRandom.clone();
    }

    EchConfig.Selected selected() {
        return selected;
    }

    /**
     * The ClientHelloInner for {@code outer}, the profile's hello for the public name (or, after
     * a HelloRetryRequest, the second outer hello before its ECH is sealed), without
     * {@code pre_shared_key}, which the caller adds last.
     */
    Inner inner(ClientHello outer) {
        List<Extension> differing = new ArrayList<>();
        List<Extension> shared = new ArrayList<>();
        boolean hasEch = false;
        for (Extension e : outer.extensions()) {
            int type = e.type();
            if (TLS12_ONLY.contains(type) || type == ExtensionType.PRE_SHARED_KEY) continue;
            switch (type) {
                case ExtensionType.SERVER_NAME -> {
                    if (innerName != null) differing.add(new Extension(type, Extensions.encodeServerName(innerName)));
                }
                case ProfileExtensions.ENCRYPTED_CLIENT_HELLO -> {
                    differing.add(new Extension(type, new byte[] {1}));
                    hasEch = true;
                }
                case ExtensionType.SUPPORTED_VERSIONS -> differing.add(new Extension(type, tls13Only(e.data())));
                case ExtensionType.EARLY_DATA -> differing.add(e);
                default -> shared.add(e);
            }
        }
        if (!hasEch) differing.add(new Extension(ProfileExtensions.ENCRYPTED_CLIENT_HELLO, new byte[] {1}));
        Set<Integer> compressed = new HashSet<>();
        for (Extension e : shared) compressed.add(e.type());
        List<Extension> extensions = new ArrayList<>(differing);
        extensions.addAll(shared);
        int[] suites = Arrays.stream(outer.cipherSuites())
                .filter(s -> Grease.isGrease(s) || CipherSuite.forCode(s) != null).toArray();
        return new Inner(new ClientHello(HandshakeMessage.LEGACY_VERSION, innerRandom.clone(), outer.sessionId(), suites,
                new byte[] {0}, extensions), Set.copyOf(compressed));
    }

    /** {@code supported_versions} with only TLS 1.3 and above, and GREASE, in order. */
    private static byte[] tls13Only(byte[] data) {
        Writer w = new Writer();
        int list = w.open(1);
        for (int i = 1; i + 1 < data.length; i += 2) {
            int v = ((data[i] & 0xff) << 8) | (data[i + 1] & 0xff);
            if (Grease.isGrease(v) || v >= HandshakeMessage.TLS13) w.u16(v);
        }
        w.close(list);
        return w.toByteArray();
    }

    /**
     * The ClientHelloOuter: {@code outer} with an {@code encrypted_client_hello} carrying {@code
     * innerMessage} encrypted, where the profile's GREASE one was (or before the last GREASE
     * extension if the profile has none).
     *
     * @param outer the outer hello so far; its {@code encrypted_client_hello}, if any, is replaced
     * @param inner the inner hello and the extensions it shares with {@code outer}
     * @param innerMessage the inner hello as sent, header and {@code pre_shared_key} included
     * @param first whether this is the first ClientHello: the second sends an empty {@code enc}
     *     and continues the HPKE context (RFC 9849 section 6.1.5)
     */
    ClientHello outer(ClientHello outer, Inner inner, byte[] innerMessage, boolean first)
            throws GeneralSecurityException, QuicException {
        byte[] encoded = encodeInner(inner, innerMessage);
        byte[] encOut = first ? enc : new byte[0];
        int payloadLength = encoded.length + Hpke.Aead.TAG_LENGTH;
        List<Extension> extensions = withEch(outer.extensions(), outerExtension(encOut, new byte[payloadLength]));
        ClientHello aadHello = outer.withExtensions(extensions);
        byte[] aadMessage = aadHello.encode();
        byte[] aad = Arrays.copyOfRange(aadMessage, 4, aadMessage.length);
        byte[] payload = hpke.seal(aad, encoded);
        return outer.withExtensions(withEch(outer.extensions(), outerExtension(encOut, payload)));
    }

    /** {@code extensions} with {@code ech} in place of the {@code encrypted_client_hello} there. */
    private static List<Extension> withEch(List<Extension> extensions, byte[] ech) {
        List<Extension> out = new ArrayList<>(extensions);
        for (int i = 0; i < out.size(); i++) {
            if (out.get(i).type() == ProfileExtensions.ENCRYPTED_CLIENT_HELLO) {
                out.set(i, new Extension(ProfileExtensions.ENCRYPTED_CLIENT_HELLO, ech));
                return out;
            }
        }
        int at = out.size();
        if (at > 0 && Grease.isGrease(out.get(at - 1).type())) at--;
        out.add(at, new Extension(ProfileExtensions.ENCRYPTED_CLIENT_HELLO, ech));
        return out;
    }

    /** An {@code ECHClientHello} of type outer (RFC 9849 section 5). */
    private byte[] outerExtension(byte[] encOut, byte[] payload) {
        Writer w = new Writer();
        w.u8(0).u16(selected.kdfId()).u16(selected.aead().id()).u8(selected.config().configId())
                .vector16(encOut).vector16(payload);
        return w.toByteArray();
    }

    /**
     * {@code EncodedClientHelloInner} (RFC 9849 section 5.1): the inner hello without its
     * header, with an empty {@code legacy_session_id}, the shared extensions replaced by one
     * {@code ech_outer_extensions}, and zeros padding it as section 6.1.3 recommends, as BoringSSL
     * pads it.
     */
    byte[] encodeInner(Inner inner, byte[] innerMessage) throws QuicException {
        ClientHello sent = (ClientHello) HandshakeMessage.decode(HandshakeType.CLIENT_HELLO,
                Arrays.copyOfRange(innerMessage, 4, innerMessage.length));
        List<Extension> extensions = new ArrayList<>();
        Writer references = new Writer();
        int list = references.open(1);
        boolean placed = false;
        for (Extension e : sent.extensions()) {
            if (!inner.compressed().contains(e.type())) {
                extensions.add(e);
                continue;
            }
            references.u16(e.type());
            if (!placed) {
                extensions.add(null); // where ech_outer_extensions goes
                placed = true;
            }
        }
        references.close(list);
        if (placed) extensions.set(extensions.indexOf(null), new Extension(ECH_OUTER_EXTENSIONS, references.toByteArray()));
        byte[] message = new ClientHello(sent.legacyVersion(), sent.random(), new byte[0], sent.cipherSuites(),
                sent.compressionMethods(), extensions).encode();
        int length = message.length - 4;
        int padding;
        int maxName = selected.config().maximumNameLength();
        if (innerName != null) {
            padding = Math.max(0, maxName - innerName.getBytes(StandardCharsets.US_ASCII).length);
        } else {
            padding = maxName + 9;
        }
        padding += 31 - ((length + padding - 1) % 32);
        byte[] out = new byte[length + padding];
        System.arraycopy(message, 4, out, 0, length);
        return out;
    }

    /**
     * An acceptance signal (RFC 9849 section 7.2): {@code HKDF-Expand-Label(HKDF-Extract(0,
     * ClientHelloInner.random), label, transcript_hash, 8)} with the negotiated suite's hash.
     */
    byte[] confirmation(CipherSuite suite, String label, byte[] transcriptHash) {
        Hkdf hkdf = suite.hkdf();
        byte[] prk = hkdf.extract(new byte[0], innerRandom);
        return hkdf.expandLabel(prk, label, transcriptHash, CONFIRMATION_LENGTH);
    }

    /** A ServerHello message with the last 8 bytes of its random zeroed, for {@link #ACCEPT_LABEL}. */
    static byte[] zeroConfirmation(byte[] serverHelloMessage) {
        byte[] out = serverHelloMessage.clone();
        // type and length (4), legacy_version (2), random (32): its last 8 bytes are 30 to 37
        Arrays.fill(out, 4 + 2 + 32 - CONFIRMATION_LENGTH, 4 + 2 + 32, (byte) 0);
        return out;
    }

    /** A HelloRetryRequest message with its {@code encrypted_client_hello} zeroed, for {@link #HRR_ACCEPT_LABEL}. */
    static byte[] zeroConfirmation(ServerHello hrr) {
        List<Extension> extensions = new ArrayList<>();
        for (Extension e : hrr.extensions()) {
            extensions.add(e.type() == ProfileExtensions.ENCRYPTED_CLIENT_HELLO
                    ? new Extension(e.type(), new byte[e.data().length]) : e);
        }
        return hrr.withExtensions(extensions).encode();
    }
}
