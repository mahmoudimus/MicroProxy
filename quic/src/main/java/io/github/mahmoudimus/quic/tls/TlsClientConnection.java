// The handshake checks follow ClientHandshake (ported from rustls src/client/hs.rs and
// src/client/tls13.rs, Apache-2.0), with TLS over TCP's rules in place of QUIC's: middlebox
// compatibility mode, ChangeCipherSpec, KeyUpdate, close_notify, no transport parameters and
// optional ALPN. ALPS and the second EncryptedExtensions follow BoringSSL's ssl/tls13_client.cc
// (ISC); certificate compression follows RFC 8879.
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.Extensions.KeyShare;
import io.github.mahmoudimus.quic.tls.Extensions.PskIdentity;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateEntry;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateMessage;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateRequest;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateVerify;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.EncryptedExtensions;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Finished;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.KeyUpdate;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.NewSessionTicket;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * A TLS 1.3 client connection over a byte stream, whose ClientHello is a {@link ClientHelloProfile}'s:
 * the browser's cipher suites, extensions, GREASE and key shares, and its behaviour where a server's
 * answer calls for it (ChangeCipherSpec before the second flight, the ALPS reply, certificate
 * decompression, resumption with the tickets it was given).
 *
 * <p>{@link #handshake()} runs the handshake; afterwards {@link #read()} and {@link #write}
 * carry application data, handling NewSessionTicket, KeyUpdate and alerts in between. Errors are
 * {@link TlsAlertException}s, after the alert has been sent when the error is ours.
 */
final class TlsClientConnection {

    /** Everything a connection needs that does not change from one connection to the next. */
    record Config(ClientHelloProfile profile, X509TrustManager trustManager, X509KeyManager keyManager,
            ClientSessionStore sessions, Map<String, byte[]> applicationSettings, CertificateDecompressor decompressor,
            SecureRandom random, InstantSource clock, int maxHandshakeMessageSize) {

        Config {
            Objects.requireNonNull(profile, "profile");
            Objects.requireNonNull(trustManager, "trustManager");
            sessions = sessions != null ? sessions : ClientSessionStore.NONE;
            applicationSettings = Map.copyOf(applicationSettings);
            decompressor = decompressor != null ? decompressor : CertificateDecompressor.ZLIB;
            Objects.requireNonNull(random, "random");
            Objects.requireNonNull(clock, "clock");
        }
    }

    /** A TLS failure: the alert sent or received, and why. */
    static final class TlsAlertException extends IOException {
        private final int alert;
        private final boolean received;

        TlsAlertException(int alert, boolean received, String message, Throwable cause) {
            super(message, cause);
            this.alert = alert;
            this.received = received;
        }

        /** {@return the alert description} */
        int alert() {
            return alert;
        }

        /** {@return whether the server sent the alert, rather than this client} */
        boolean received() {
            return received;
        }
    }

    /** Extensions a TLS 1.3 ServerHello may carry (RFC 8446 section 4.2). */
    private static final Set<Integer> SERVER_HELLO_EXTENSIONS = Set.of(
            ExtensionType.KEY_SHARE, ExtensionType.PRE_SHARED_KEY, ExtensionType.SUPPORTED_VERSIONS);
    /** Extensions a HelloRetryRequest may carry. */
    private static final Set<Integer> RETRY_EXTENSIONS = Set.of(
            ExtensionType.KEY_SHARE, ExtensionType.COOKIE, ExtensionType.SUPPORTED_VERSIONS);
    /** Extensions EncryptedExtensions may carry, when the client offered them. */
    private static final Set<Integer> ENCRYPTED_EXTENSIONS = Set.of(
            ExtensionType.SERVER_NAME, ExtensionType.MAX_FRAGMENT_LENGTH, ExtensionType.SUPPORTED_GROUPS,
            ExtensionType.USE_SRTP, ExtensionType.HEARTBEAT, ExtensionType.ALPN,
            ExtensionType.CLIENT_CERTIFICATE_TYPE, ExtensionType.SERVER_CERTIFICATE_TYPE, ExtensionType.EARLY_DATA,
            ProfileExtensions.RECORD_SIZE_LIMIT, ProfileExtensions.APPLICATION_SETTINGS,
            ProfileExtensions.ENCRYPTED_CLIENT_HELLO, ProfileExtensions.TRUST_ANCHORS);
    /** Extensions a server's CertificateEntry may carry, when the client offered them. */
    private static final Set<Integer> CERTIFICATE_EXTENSIONS = Set.of(
            ExtensionType.STATUS_REQUEST, ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, ProfileExtensions.TRUST_ANCHORS);
    /** The longest ticket lifetime (RFC 8446 section 4.6.1): 7 days. */
    private static final long MAX_TICKET_LIFETIME = 604800;
    /** The last 8 bytes of a TLS 1.3 server's random when it negotiates TLS 1.2 or below (RFC 8446 section 4.1.3). */
    private static final byte[] DOWNGRADE_TLS12 = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
    private static final byte[] DOWNGRADE_TLS11 = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00};

    private final Config config;
    private final String serverName;
    private final String verifyHost;
    private final List<String> alpn;
    private final String sessionKey;
    private final TlsRecordLayer records;
    private final Transcript transcript = new Transcript();
    private final ByteArrayOutputStream handshakeBuffer = new ByteArrayOutputStream();
    private final Map<Integer, KeyExchange> keyShares = new LinkedHashMap<>();
    private final Set<Integer> sentExtensions = new HashSet<>();
    private ClientHello hello;
    private SessionTicket ticket;
    private boolean pskOffered;
    private boolean resumed;
    private CipherSuite suite;
    private NamedGroup group;
    private KeySchedule keySchedule;
    private byte[] clientHandshakeSecret;
    private byte[] serverHandshakeSecret;
    private byte[] clientApplicationSecret;
    private byte[] serverApplicationSecret;
    private byte[] resumptionMaster;
    private boolean sentChangeCipherSpec;
    private boolean receivedChangeCipherSpec;
    private String negotiatedAlpn;
    private byte[] peerApplicationSettings;
    private List<X509Certificate> peerCertificates = List.of();
    private List<X509Certificate> localCertificates = List.of();
    private SignatureScheme peerSignatureScheme;
    private boolean handshakeDone;
    private int keyUpdatesReceived;
    private boolean readClosed;
    private boolean writeClosed;
    private final Object writeLock = new Object();

    /**
     * @param config what does not change between connections
     * @param in the stream from the server
     * @param out the stream to the server
     * @param serverName the name to send in SNI, or null for none (an IP literal is sent as none)
     * @param verifyHost the name the certificate must be valid for, or null not to check it
     * @param alpn the ALPN protocols to offer, most preferred first; empty for none
     * @param sessionKey the key tickets are kept under in {@link Config#sessions()}, such as
     *     {@code host:port}; null not to resume or keep tickets
     */
    TlsClientConnection(Config config, InputStream in, OutputStream out, String serverName, String verifyHost,
            List<String> alpn, String sessionKey) {
        this.config = config;
        this.serverName = sniName(serverName);
        this.verifyHost = verifyHost;
        this.alpn = List.copyOf(alpn);
        this.sessionKey = sessionKey;
        this.records = new TlsRecordLayer(in, out);
    }

    private static String sniName(String name) {
        if (name == null || HostnameChecker.isIpLiteral(name)) return null;
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }

    // --- the handshake ---

    /**
     * Runs the handshake to its end.
     *
     * @throws TlsAlertException if it fails, after sending the alert when the failure is ours
     * @throws IOException if the stream fails or closes
     */
    void handshake() throws IOException {
        try {
            runHandshake();
        } catch (QuicException e) {
            throw fail(e);
        }
    }

    private void runHandshake() throws IOException, QuicException {
        sendClientHello();
        Message first = expectServerHello();
        Message real = first;
        if (((ServerHello) first.message()).isHelloRetryRequest()) {
            onHelloRetryRequest((ServerHello) first.message(), first.raw());
            real = expectServerHello();
            if (((ServerHello) real.message()).isHelloRetryRequest()) {
                throw TlsAlert.unexpectedMessage("second HelloRetryRequest");
            }
        }
        transcript.start(suite);
        transcript.add(real.raw());
        onServerHello((ServerHello) real.message());
        records.plaintextVersion(HandshakeMessage.LEGACY_VERSION);

        boolean requestedCertificate = false;
        CertificateRequest certificateRequest = null;
        onEncryptedExtensions(expect(HandshakeType.ENCRYPTED_EXTENSIONS));
        if (!resumed) {
            Message next = readMessage();
            if (next.type() == HandshakeType.CERTIFICATE_REQUEST) {
                certificateRequest = onCertificateRequest(next);
                requestedCertificate = true;
                next = readMessage();
            }
            List<X509Certificate> chain = onCertificate(next);
            onCertificateVerify(expect(HandshakeType.CERTIFICATE_VERIFY), chain.get(0));
        }
        Message finished = expect(HandshakeType.FINISHED);
        requireAligned("Finished");
        onServerFinished(finished);
        sendSecondFlight(requestedCertificate ? certificateRequest : null);
        handshakeDone = true;
    }

    private void sendClientHello() throws IOException, QuicException {
        for (int code : config.profile().keyShareGroups()) {
            NamedGroup g = NamedGroup.forCode(code);
            if (g == null) throw new IllegalStateException("no key exchange for group 0x" + Integer.toHexString(code));
            keyShares.put(code, KeyExchange.generate(g, config.random()));
        }
        Map<Integer, byte[]> publicKeys = new LinkedHashMap<>();
        keyShares.forEach((code, kx) -> publicKeys.put(code, kx.publicKey()));
        HelloContext context = new HelloContext(serverName, alpn, publicKeys, Grease.random(config.random()),
                config.random());
        hello = config.profile().clientHello(context);
        ticket = sessionKey != null ? usable(config.sessions().take(sessionKey)) : null;
        byte[] encoded = encodeWithPsk(hello, true);
        transcript.add(encoded);
        records.write(TlsRecordLayer.HANDSHAKE, encoded);
        records.flush();
    }

    /** The ticket if it may be offered: unexpired, for this server, with a suite the profile offers. */
    private SessionTicket usable(SessionTicket t) {
        if (t == null || t.isExpired(config.clock().instant())) return null;
        if (!config.profile().tls13CipherSuites().contains(t.suite)) return null;
        if (!Objects.equals(t.serverName, serverName)) return null;
        return t;
    }

    /**
     * Encodes {@code h}, adding {@code pre_shared_key} last with its binder when there is a ticket
     * (RFC 8446 section 4.2.11.2), and records the extensions sent.
     */
    private byte[] encodeWithPsk(ClientHello h, boolean first) {
        pskOffered = ticket != null;
        ClientHello toSend = h;
        int hashLength = 0;
        if (pskOffered) {
            hashLength = ticket.suite.hkdf().hashLength();
            PskIdentity identity = new PskIdentity(ticket.ticket, ticket.obfuscatedAge(config.clock().instant()));
            List<Extension> extensions = new ArrayList<>(h.extensions());
            extensions.add(new Extension(ExtensionType.PRE_SHARED_KEY,
                    Extensions.encodePskOffer(List.of(identity), List.of(new byte[hashLength]))));
            toSend = h.withExtensions(extensions);
        }
        sentExtensions.clear();
        for (Extension e : toSend.extensions()) sentExtensions.add(e.type());
        byte[] encoded = toSend.encode();
        if (pskOffered) {
            byte[] prefix = Arrays.copyOf(encoded, encoded.length - (3 + hashLength));
            byte[] hash = first ? Transcript.newDigest(ticket.suite).digest(prefix) : transcript.hashWith(prefix);
            byte[] binder = new KeySchedule(ticket.suite, ticket.psk).binder(hash);
            System.arraycopy(binder, 0, encoded, encoded.length - hashLength, hashLength);
        }
        return encoded;
    }

    /** A ServerHello or HelloRetryRequest, checked, but not yet in the transcript. */
    private Message expectServerHello() throws IOException, QuicException {
        Message m = expect(HandshakeType.SERVER_HELLO);
        requireAligned("ServerHello");
        ServerHello sh = (ServerHello) m.message();
        boolean retry = sh.isHelloRetryRequest();
        checkHello(sh, retry ? "HelloRetryRequest" : "ServerHello", retry);
        return m;
    }

    /** The checks a ServerHello and a HelloRetryRequest share. */
    private void checkHello(ServerHello sh, String name, boolean retry) throws QuicException {
        Extensions.checkNoDuplicates(sh.extensions(), name);
        byte[] version = Extension.find(sh.extensions(), ExtensionType.SUPPORTED_VERSIONS);
        if (version == null) {
            byte[] tail = Arrays.copyOfRange(sh.random(), 24, 32);
            if (Arrays.equals(tail, DOWNGRADE_TLS12) || Arrays.equals(tail, DOWNGRADE_TLS11)) {
                throw TlsAlert.illegalParameter(name + " carries the TLS 1.3 downgrade sentinel");
            }
            throw TlsAlert.error(TlsAlert.PROTOCOL_VERSION, "the server selected TLS 1.2, which is not supported yet");
        }
        int selected = Extensions.decodeSupportedVersionServer(version);
        if (selected != HandshakeMessage.TLS13) {
            throw TlsAlert.illegalParameter(name + " selected version 0x" + Integer.toHexString(selected));
        }
        if (sh.legacyVersion() != HandshakeMessage.LEGACY_VERSION) {
            throw TlsAlert.illegalParameter(name + " legacy_version 0x" + Integer.toHexString(sh.legacyVersion()));
        }
        if (!Arrays.equals(sh.sessionId(), hello.sessionId())) {
            throw TlsAlert.illegalParameter(name + " legacy_session_id_echo does not match");
        }
        if (sh.compressionMethod() != 0) {
            throw TlsAlert.illegalParameter(name + " selected compression " + sh.compressionMethod());
        }
        CipherSuite s = CipherSuite.forCode(sh.cipherSuite());
        if (s == null || !config.profile().tls13CipherSuites().contains(s)) {
            throw TlsAlert.illegalParameter(name + " selected a cipher suite that was not offered");
        }
        if (suite != null && s != suite) {
            throw TlsAlert.illegalParameter("ServerHello selected a different cipher suite than its HelloRetryRequest");
        }
        Set<Integer> allowed = retry ? RETRY_EXTENSIONS : SERVER_HELLO_EXTENSIONS;
        for (Extension e : sh.extensions()) {
            boolean solicited = sentExtensions.contains(e.type()) || (retry && e.type() == ExtensionType.COOKIE);
            if (!solicited) {
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, name + " has unsolicited " + ExtensionType.name(e.type()));
            }
            if (!allowed.contains(e.type())) {
                throw TlsAlert.illegalParameter(name + " may not carry " + ExtensionType.name(e.type()));
            }
        }
        suite = s;
    }

    /**
     * A HelloRetryRequest: the second ClientHello is the first with the requested group's share in
     * place of every share (no GREASE share, as BoringSSL does) and the cookie, after a
     * ChangeCipherSpec.
     */
    private void onHelloRetryRequest(ServerHello hrr, byte[] hrrRaw) throws IOException, QuicException {
        byte[] cookieData = Extension.find(hrr.extensions(), ExtensionType.COOKIE);
        byte[] groupData = Extension.find(hrr.extensions(), ExtensionType.KEY_SHARE);
        byte[] cookie = cookieData != null ? Extensions.decodeCookie(cookieData) : null;
        if (cookie != null && cookie.length == 0) throw TlsAlert.illegalParameter("HelloRetryRequest has an empty cookie");
        if (cookie == null && groupData == null) throw TlsAlert.illegalParameter("HelloRetryRequest asks for no change");
        List<Extension> extensions = new ArrayList<>(hello.extensions());
        if (groupData != null) {
            int code = Extensions.decodeKeyShareRetry(groupData);
            byte[] offered = Extension.find(hello.extensions(), ExtensionType.SUPPORTED_GROUPS);
            boolean supported = offered != null
                    && Arrays.stream(Extensions.decodeU16List(offered, "supported_groups")).anyMatch(g -> g == code);
            NamedGroup requested = NamedGroup.forCode(code);
            if (!supported || requested == null) {
                throw TlsAlert.illegalParameter("HelloRetryRequest asks for a group that was not offered");
            }
            if (keyShares.containsKey(code)) {
                throw TlsAlert.illegalParameter("HelloRetryRequest asks for a group already offered");
            }
            KeyExchange kx = KeyExchange.generate(requested, config.random());
            keyShares.clear();
            keyShares.put(code, kx);
            replace(extensions, ExtensionType.KEY_SHARE,
                    Extensions.encodeKeyShareClient(List.of(new KeyShare(code, kx.publicKey()))));
        }
        if (cookie != null) {
            int at = extensions.size();
            // before the last GREASE extension, so GREASE stays last
            if (at > 0 && Grease.isGrease(extensions.get(at - 1).type())) at--;
            extensions.add(at, new Extension(ExtensionType.COOKIE, Extensions.encodeCookie(cookie)));
        }
        if (ticket != null && ticket.suite.hkdf() != suite.hkdf()) {
            ticket = null; // the PSK cannot be used with this suite's hash (RFC 8446 section 4.1.4)
        }
        // RFC 8446 section 4.4.1: message_hash(ClientHello1), HelloRetryRequest, ClientHello2
        transcript.start(suite);
        transcript.rollupForRetry();
        transcript.add(hrrRaw);
        hello = hello.withExtensions(extensions);
        byte[] encoded = encodeWithPsk(hello, false);
        transcript.add(encoded);
        sendChangeCipherSpec();
        records.write(TlsRecordLayer.HANDSHAKE, encoded);
        records.flush();
    }

    private static void replace(List<Extension> extensions, int type, byte[] body) {
        for (int i = 0; i < extensions.size(); i++) {
            if (extensions.get(i).type() == type) {
                extensions.set(i, new Extension(type, body));
                return;
            }
        }
    }

    private void onServerHello(ServerHello sh) throws QuicException {
        byte[] shareData = Extension.find(sh.extensions(), ExtensionType.KEY_SHARE);
        if (shareData == null) throw TlsAlert.error(TlsAlert.MISSING_EXTENSION, "ServerHello has no key_share");
        KeyShare share = Extensions.decodeKeyShareServer(shareData);
        KeyExchange ours = keyShares.get(share.group());
        if (ours == null) throw TlsAlert.illegalParameter("ServerHello key share is for a group that was not offered");
        byte[] shared = ours.agree(share.keyExchange());
        group = ours.group();
        byte[] selected = Extension.find(sh.extensions(), ExtensionType.PRE_SHARED_KEY);
        if (selected != null) {
            if (!pskOffered) {
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, "ServerHello selects a PSK that was not offered");
            }
            if (Extensions.decodePskSelected(selected) != 0) {
                throw TlsAlert.illegalParameter("ServerHello selects a PSK identity that was not offered");
            }
            if (suite.hkdf() != ticket.suite.hkdf()) {
                throw TlsAlert.illegalParameter("ServerHello resumes with a cipher suite of another hash");
            }
            resumed = true;
            peerCertificates = ticket.peerCertificates;
        }
        keySchedule = resumed ? new KeySchedule(suite, ticket.psk) : new KeySchedule(suite);
        keySchedule.inputSharedSecret(shared);
        byte[] hash = transcript.hash();
        clientHandshakeSecret = keySchedule.deriveSecret(KeySchedule.CLIENT_HANDSHAKE_TRAFFIC, hash);
        serverHandshakeSecret = keySchedule.deriveSecret(KeySchedule.SERVER_HANDSHAKE_TRAFFIC, hash);
        keySchedule.inputEmpty();
        records.readKeys(suite, serverHandshakeSecret);
    }

    private void onEncryptedExtensions(Message m) throws QuicException {
        transcript.add(m.raw());
        List<Extension> extensions = ((EncryptedExtensions) m.message()).extensions();
        Extensions.checkNoDuplicates(extensions, "EncryptedExtensions");
        for (Extension e : extensions) {
            if (!sentExtensions.contains(e.type())) {
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION,
                        "EncryptedExtensions has unsolicited " + ExtensionType.name(e.type()));
            }
            if (!ENCRYPTED_EXTENSIONS.contains(e.type())) {
                throw TlsAlert.illegalParameter("EncryptedExtensions may not carry " + ExtensionType.name(e.type()));
            }
        }
        byte[] nameAck = Extension.find(extensions, ExtensionType.SERVER_NAME);
        if (nameAck != null) Extensions.expectEmpty(nameAck, ExtensionType.SERVER_NAME);
        if (Extension.find(extensions, ExtensionType.EARLY_DATA) != null) {
            throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, "EncryptedExtensions accepts early data that was not offered");
        }
        byte[] alpnData = Extension.find(extensions, ExtensionType.ALPN);
        if (alpnData != null) {
            List<byte[]> selected = Extensions.decodeAlpn(alpnData);
            if (selected.size() != 1) throw TlsAlert.decodeError("server selected " + selected.size() + " application protocols");
            String protocol = new String(selected.get(0), StandardCharsets.ISO_8859_1);
            if (!alpn.contains(protocol)) {
                throw TlsAlert.illegalParameter("server selected an application protocol that was not offered");
            }
            negotiatedAlpn = protocol;
        }
        byte[] settings = Extension.find(extensions, ProfileExtensions.APPLICATION_SETTINGS);
        if (settings != null) {
            // ALPS is for the negotiated protocol, and only one the client has settings for
            if (negotiatedAlpn == null || !config.applicationSettings().containsKey(negotiatedAlpn)) {
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, "application_settings for a protocol not negotiated");
            }
            peerApplicationSettings = settings.clone();
        }
        byte[] sizeLimit = Extension.find(extensions, ProfileExtensions.RECORD_SIZE_LIMIT);
        if (sizeLimit != null) {
            int limit = Extensions.decodeU16(sizeLimit, "record_size_limit");
            if (limit < 64) throw TlsAlert.illegalParameter("record_size_limit " + limit);
            // RFC 8449 section 4: the limit counts the content type byte of TLSInnerPlaintext
            records.maxFragment(Math.min(TlsRecordLayer.MAX_FRAGMENT, limit - 1));
        }
    }

    private CertificateRequest onCertificateRequest(Message m) throws QuicException {
        transcript.add(m.raw());
        CertificateRequest request = (CertificateRequest) m.message();
        if (request.context().length != 0) {
            throw TlsAlert.illegalParameter("CertificateRequest during the handshake has a context");
        }
        Extensions.checkNoDuplicates(request.extensions(), "CertificateRequest");
        if (Extension.find(request.extensions(), ExtensionType.SIGNATURE_ALGORITHMS) == null) {
            throw TlsAlert.error(TlsAlert.MISSING_EXTENSION, "CertificateRequest has no signature_algorithms");
        }
        return request;
    }

    private List<X509Certificate> onCertificate(Message m) throws IOException, QuicException {
        CertificateMessage certificate;
        if (m.type() == HandshakeType.COMPRESSED_CERTIFICATE) {
            certificate = decompress(m.body());
        } else if (m.type() == HandshakeType.CERTIFICATE) {
            certificate = (CertificateMessage) m.message();
        } else {
            throw TlsAlert.unexpectedMessage("got " + HandshakeType.name(m.type()) + ", expected Certificate");
        }
        transcript.add(m.raw());
        if (certificate.context().length != 0) throw TlsAlert.illegalParameter("server Certificate has a request context");
        if (certificate.entries().isEmpty()) throw TlsAlert.decodeError("server sent no certificate");
        for (CertificateEntry entry : certificate.entries()) {
            Extensions.checkNoDuplicates(entry.extensions(), "CertificateEntry");
            for (Extension e : entry.extensions()) {
                if (!sentExtensions.contains(e.type())) {
                    throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION,
                            "CertificateEntry has unsolicited " + ExtensionType.name(e.type()));
                }
                if (!CERTIFICATE_EXTENSIONS.contains(e.type())) {
                    throw TlsAlert.illegalParameter("CertificateEntry may not carry " + ExtensionType.name(e.type()));
                }
            }
        }
        List<X509Certificate> chain = CertificateChecks.parse(certificate.entries());
        CertificateChecks.verifyServer(config.trustManager(), chain, verifyHost);
        peerCertificates = chain;
        return chain;
    }

    /** A CompressedCertificate (RFC 8879 section 4): an algorithm the client offered, and the exact length. */
    private CertificateMessage decompress(byte[] body) throws QuicException {
        Reader r = new Reader(body);
        int algorithm = r.u16("CompressedCertificate algorithm");
        int length = r.u24("CompressedCertificate uncompressed_length");
        byte[] data = r.vector24(1, "CompressedCertificate compressed_certificate_message");
        r.expectEnd("CompressedCertificate");
        byte[] offered = Extension.find(hello.extensions(), ProfileExtensions.COMPRESS_CERTIFICATE);
        boolean wasOffered = false;
        if (offered != null) {
            Reader list = new Reader(offered).sub8("compress_certificate");
            while (list.hasRemaining()) wasOffered |= list.u16("algorithm") == algorithm;
        }
        if (!wasOffered) throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "certificate compressed with an algorithm not offered");
        if (length > config.maxHandshakeMessageSize()) {
            throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "compressed certificate of " + length + " bytes");
        }
        byte[] plain;
        try {
            plain = config.decompressor().decompress(algorithm, data, length);
        } catch (IOException e) {
            throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "compressed certificate: " + e.getMessage());
        }
        if (plain == null) throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "no decompressor for algorithm " + algorithm);
        if (plain.length != length) throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "compressed certificate length mismatch");
        return (CertificateMessage) HandshakeMessage.decode(HandshakeType.CERTIFICATE, plain);
    }

    private void onCertificateVerify(Message m, X509Certificate leaf) throws QuicException {
        CertificateVerify verify = (CertificateVerify) m.message();
        SignatureScheme scheme = SignatureScheme.forCode(verify.scheme());
        byte[] offered = Extension.find(hello.extensions(), ExtensionType.SIGNATURE_ALGORITHMS);
        boolean wasOffered = offered != null
                && Arrays.stream(Extensions.decodeU16List(offered, "signature_algorithms")).anyMatch(c -> c == verify.scheme());
        if (scheme == null || !wasOffered || !scheme.allowedInCertificateVerify()) {
            throw TlsAlert.illegalParameter("CertificateVerify uses a signature scheme that was not offered for it");
        }
        if (!scheme.compatibleWith(leaf.getPublicKey())) {
            throw TlsAlert.illegalParameter("CertificateVerify scheme " + scheme + " does not fit the certificate key");
        }
        byte[] content = Signatures.content(true, transcript.hash());
        if (!Signatures.verify(scheme, leaf.getPublicKey(), content, verify.signature())) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "server CertificateVerify signature is invalid");
        }
        transcript.add(m.raw());
        peerSignatureScheme = scheme;
    }

    private void onServerFinished(Message m) throws QuicException {
        byte[] expected = keySchedule.finishedVerifyData(serverHandshakeSecret, transcript.hash());
        if (!MessageDigest.isEqual(expected, ((Finished) m.message()).verifyData())) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "server Finished is incorrect");
        }
        transcript.add(m.raw());
        byte[] hash = transcript.hash();
        clientApplicationSecret = keySchedule.deriveSecret(KeySchedule.CLIENT_APPLICATION_TRAFFIC, hash);
        serverApplicationSecret = keySchedule.deriveSecret(KeySchedule.SERVER_APPLICATION_TRAFFIC, hash);
        records.readKeys(suite, serverApplicationSecret);
    }

    /**
     * ChangeCipherSpec (middlebox compatibility mode), then, in BoringSSL's order, the client's
     * EncryptedExtensions with its ALPS when the server sent its own, the client certificate when
     * asked for, and Finished.
     */
    private void sendSecondFlight(CertificateRequest request) throws IOException, QuicException {
        sendChangeCipherSpec();
        records.writeKeys(suite, clientHandshakeSecret);
        if (peerApplicationSettings != null) {
            byte[] ours = config.applicationSettings().get(negotiatedAlpn);
            byte[] ee = new EncryptedExtensions(List.of(new Extension(ProfileExtensions.APPLICATION_SETTINGS, ours)))
                    .encode();
            transcript.add(ee);
            records.write(TlsRecordLayer.HANDSHAKE, ee);
        }
        if (request != null) sendClientCertificate(request);
        byte[] verifyData = keySchedule.finishedVerifyData(clientHandshakeSecret, transcript.hash());
        byte[] clientFinished = new Finished(verifyData).encode();
        transcript.add(clientFinished);
        records.write(TlsRecordLayer.HANDSHAKE, clientFinished);
        records.flush();
        resumptionMaster = keySchedule.deriveSecret(KeySchedule.RESUMPTION_MASTER, transcript.hash());
        records.writeKeys(suite, clientApplicationSecret);
    }

    private void sendChangeCipherSpec() throws IOException {
        if (sentChangeCipherSpec) return;
        sentChangeCipherSpec = true;
        records.writeChangeCipherSpec();
    }

    private void sendClientCertificate(CertificateRequest request) throws IOException, QuicException {
        int[] schemes = Extensions.decodeU16List(
                Extension.find(request.extensions(), ExtensionType.SIGNATURE_ALGORITHMS), "signature_algorithms");
        CertifiedKey key = null;
        SignatureScheme scheme = null;
        X509KeyManager km = config.keyManager();
        if (km != null) {
            for (int code : schemes) {
                SignatureScheme candidate = SignatureScheme.forCode(code);
                if (candidate == null || !candidate.allowedInCertificateVerify()) continue;
                String alias = km.chooseClientAlias(new String[] {keyType(candidate)}, null, null);
                if (alias == null) continue;
                CertifiedKey k = CertifiedKey.fromKeyManager(km, alias);
                if (k != null && candidate.compatibleWith(k.privateKey())) {
                    key = k;
                    scheme = candidate;
                    break;
                }
            }
        }
        List<CertificateEntry> entries = new ArrayList<>();
        if (key != null) {
            for (X509Certificate cert : key.chain()) {
                try {
                    entries.add(new CertificateEntry(cert.getEncoded(), List.of()));
                } catch (CertificateEncodingException e) {
                    throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot encode client certificate");
                }
            }
            localCertificates = key.chain();
        }
        byte[] certificate = new CertificateMessage(request.context(), entries).encode();
        transcript.add(certificate);
        records.write(TlsRecordLayer.HANDSHAKE, certificate);
        if (key == null) return;
        byte[] signature;
        try {
            signature = Signatures.sign(scheme, key.privateKey(), Signatures.content(false, transcript.hash()),
                    config.random());
        } catch (GeneralSecurityException e) {
            throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot sign CertificateVerify: " + e.getMessage());
        }
        byte[] verify = new CertificateVerify(scheme.code(), signature).encode();
        transcript.add(verify);
        records.write(TlsRecordLayer.HANDSHAKE, verify);
    }

    private static String keyType(SignatureScheme scheme) {
        return switch (scheme) {
            case ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384 -> "EC";
            case ED25519 -> "EdDSA";
            default -> "RSA";
        };
    }

    // --- handshake messages from records ---

    /** One handshake message: its type, decoded form (or null for CompressedCertificate), body and bytes. */
    private record Message(int type, HandshakeMessage message, byte[] body, byte[] raw) {}

    private Message expect(int type) throws IOException, QuicException {
        Message m = readMessage();
        if (m.type() != type) {
            throw TlsAlert.unexpectedMessage("got " + HandshakeType.name(m.type()) + ", expected " + HandshakeType.name(type));
        }
        return m;
    }

    /** Reads records until a whole handshake message is buffered. */
    private Message readMessage() throws IOException, QuicException {
        while (true) {
            byte[] buffered = handshakeBuffer.toByteArray();
            if (buffered.length >= 4) {
                int length = ((buffered[1] & 0xff) << 16) | ((buffered[2] & 0xff) << 8) | (buffered[3] & 0xff);
                if (length > config.maxHandshakeMessageSize()) {
                    throw TlsAlert.unexpectedMessage("a handshake message of " + length + " bytes");
                }
                if (buffered.length >= 4 + length) {
                    byte[] raw = Arrays.copyOf(buffered, 4 + length);
                    handshakeBuffer.reset();
                    handshakeBuffer.write(buffered, 4 + length, buffered.length - 4 - length);
                    int type = raw[0] & 0xff;
                    byte[] body = Arrays.copyOfRange(raw, 4, raw.length);
                    HandshakeMessage message = type == HandshakeType.COMPRESSED_CERTIFICATE ? null
                            : HandshakeMessage.decode(type, body);
                    return new Message(type, message, body, raw);
                }
            }
            TlsRecordLayer.Record record = records.read();
            if (record == null) throw new EOFException("the server closed the connection during the TLS handshake");
            switch (record.type()) {
                case TlsRecordLayer.HANDSHAKE -> {
                    if (record.fragment().length == 0) throw TlsAlert.unexpectedMessage("an empty handshake record");
                    handshakeBuffer.write(record.fragment());
                }
                case TlsRecordLayer.CHANGE_CIPHER_SPEC -> {
                    // RFC 8446 section 5: one change_cipher_spec of value 1, between ServerHello and Finished
                    if (handshakeDone || receivedChangeCipherSpec || record.fragment().length != 1
                            || record.fragment()[0] != 1 || suite == null) {
                        throw TlsAlert.unexpectedMessage("an unexpected change_cipher_spec");
                    }
                    receivedChangeCipherSpec = true;
                }
                case TlsRecordLayer.ALERT -> throw receivedAlert(record.fragment());
                default -> throw TlsAlert.unexpectedMessage("a record of type " + record.type() + " during the handshake");
            }
        }
    }

    /** RFC 8446 section 5.1: handshake messages may not span a change of keys. */
    private void requireAligned(String after) throws QuicException {
        if (handshakeBuffer.size() != 0) {
            throw TlsAlert.unexpectedMessage("handshake data after " + after + " in the same record");
        }
    }

    // --- application data ---

    /**
     * The next application data, or null once the server has closed its side (close_notify, or the
     * connection ending). NewSessionTicket and KeyUpdate are handled on the way.
     */
    byte[] read() throws IOException {
        if (!handshakeDone) throw new IllegalStateException("handshake not done");
        try {
            while (true) {
                if (readClosed) return null;
                if (handshakeBuffer.size() > 0 && onPostHandshake()) continue;
                TlsRecordLayer.Record record = records.read();
                if (record == null) {
                    readClosed = true;
                    return null;
                }
                switch (record.type()) {
                    case TlsRecordLayer.APPLICATION_DATA -> {
                        if (handshakeBuffer.size() != 0) throw TlsAlert.unexpectedMessage("data inside a handshake message");
                        if (record.fragment().length > 0) return record.fragment();
                    }
                    case TlsRecordLayer.HANDSHAKE -> {
                        handshakeBuffer.write(record.fragment());
                        onPostHandshake();
                    }
                    case TlsRecordLayer.ALERT -> {
                        if (isCloseNotify(record.fragment())) {
                            readClosed = true;
                            return null;
                        }
                        throw receivedAlert(record.fragment());
                    }
                    default -> throw TlsAlert.unexpectedMessage("a record of type " + record.type() + " after the handshake");
                }
            }
        } catch (QuicException e) {
            throw fail(e);
        }
    }

    /** Handles one whole buffered post-handshake message; false if none is whole yet. */
    private boolean onPostHandshake() throws IOException, QuicException {
        byte[] buffered = handshakeBuffer.toByteArray();
        if (buffered.length < 4) return false;
        int length = ((buffered[1] & 0xff) << 16) | ((buffered[2] & 0xff) << 8) | (buffered[3] & 0xff);
        if (length > config.maxHandshakeMessageSize()) throw TlsAlert.unexpectedMessage("a handshake message of " + length + " bytes");
        if (buffered.length < 4 + length) return false;
        handshakeBuffer.reset();
        handshakeBuffer.write(buffered, 4 + length, buffered.length - 4 - length);
        HandshakeMessage message = HandshakeMessage.decode(buffered[0] & 0xff, Arrays.copyOfRange(buffered, 4, 4 + length));
        if (message instanceof NewSessionTicket nst) {
            onNewSessionTicket(nst);
        } else if (message instanceof KeyUpdate update) {
            onKeyUpdate(update);
        } else {
            throw TlsAlert.unexpectedMessage("got " + HandshakeType.name(buffered[0] & 0xff) + " after the handshake");
        }
        return true;
    }

    private void onKeyUpdate(KeyUpdate update) throws IOException, QuicException {
        if (update.requestUpdate() != 0 && update.requestUpdate() != 1) {
            throw TlsAlert.illegalParameter("KeyUpdate request_update " + update.requestUpdate());
        }
        if (handshakeBuffer.size() != 0) throw TlsAlert.unexpectedMessage("handshake data after KeyUpdate in the same record");
        serverApplicationSecret = nextSecret(serverApplicationSecret);
        records.readKeys(suite, serverApplicationSecret);
        keyUpdatesReceived++;
        if (update.requestUpdate() == 1) {
            synchronized (writeLock) {
                if (writeClosed) return;
                records.write(TlsRecordLayer.HANDSHAKE, new KeyUpdate(0).encode());
                records.flush();
                clientApplicationSecret = nextSecret(clientApplicationSecret);
                records.writeKeys(suite, clientApplicationSecret);
            }
        }
    }

    /** {@code application_traffic_secret_N+1} (RFC 8446 section 7.2). */
    private byte[] nextSecret(byte[] secret) {
        return suite.hkdf().expandLabel(secret, "traffic upd", new byte[0], suite.hkdf().hashLength());
    }

    private void onNewSessionTicket(NewSessionTicket nst) throws QuicException {
        if (nst.lifetime() > MAX_TICKET_LIFETIME) throw TlsAlert.illegalParameter("NewSessionTicket lifetime exceeds 7 days");
        Extensions.checkNoDuplicates(nst.extensions(), "NewSessionTicket");
        long maxEarlyData = 0;
        byte[] earlyData = Extension.find(nst.extensions(), ExtensionType.EARLY_DATA);
        if (earlyData != null) maxEarlyData = Extensions.decodeMaxEarlyDataSize(earlyData);
        if (nst.lifetime() == 0 || sessionKey == null) return;
        byte[] psk = KeySchedule.resumptionPsk(suite, resumptionMaster, nst.nonce());
        config.sessions().put(sessionKey, new SessionTicket(serverName, suite, nst.ticket(), psk, nst.ageAdd(),
                nst.lifetime(), config.clock().instant(), maxEarlyData, negotiatedAlpn, null, peerCertificates));
    }

    /** Writes application data, in records of at most 2^14 bytes, and flushes. */
    void write(byte[] data, int off, int len) throws IOException {
        if (!handshakeDone) throw new IllegalStateException("handshake not done");
        synchronized (writeLock) {
            if (writeClosed) throw new IOException("the TLS connection is closed for writing");
            if (len > 0) records.write(TlsRecordLayer.APPLICATION_DATA, Arrays.copyOfRange(data, off, off + len));
            records.flush();
        }
    }

    /** Sends close_notify, once. */
    void closeWrite() throws IOException {
        synchronized (writeLock) {
            if (writeClosed) return;
            writeClosed = true;
            records.write(TlsRecordLayer.ALERT, new byte[] {1, TlsAlert.CLOSE_NOTIFY});
            records.flush();
        }
    }

    // --- alerts ---

    private static boolean isCloseNotify(byte[] alert) {
        return alert.length == 2 && alert[1] == TlsAlert.CLOSE_NOTIFY;
    }

    private TlsAlertException receivedAlert(byte[] alert) {
        readClosed = true;
        if (alert.length != 2) {
            return new TlsAlertException(TlsAlert.DECODE_ERROR, true, "a malformed alert", null);
        }
        int description = alert[1] & 0xff;
        String what = isCloseNotify(alert) ? "the server closed the connection during the handshake"
                : "the server sent " + TlsAlert.name(description);
        return new TlsAlertException(description, true, what, null);
    }

    /** Sends the alert for {@code e}, as well as the stream still allows, and makes the exception. */
    private TlsAlertException fail(QuicException e) {
        int alert = TlsAlert.fromErrorCode(e.code());
        if (alert < 0) alert = TlsAlert.INTERNAL_ERROR;
        synchronized (writeLock) {
            if (!writeClosed) {
                writeClosed = true;
                try {
                    records.write(TlsRecordLayer.ALERT, new byte[] {2, (byte) alert});
                    records.flush();
                } catch (IOException ignored) {
                    // the connection is going away anyway
                }
            }
        }
        readClosed = true;
        return new TlsAlertException(alert, false, e.getMessage(), e);
    }

    // --- what was negotiated ---

    String protocol() {
        return "TLSv1.3";
    }

    CipherSuite cipherSuite() {
        return suite;
    }

    NamedGroup negotiatedGroup() {
        return group;
    }

    /** {@return the ALPN protocol, or null if none was negotiated} */
    String applicationProtocol() {
        return negotiatedAlpn;
    }

    /** {@return the server's ALPS settings, or null if it sent none} */
    byte[] peerApplicationSettings() {
        return peerApplicationSettings == null ? null : peerApplicationSettings.clone();
    }

    List<X509Certificate> peerCertificates() {
        return peerCertificates;
    }

    List<X509Certificate> localCertificates() {
        return localCertificates;
    }

    SignatureScheme peerSignatureScheme() {
        return peerSignatureScheme;
    }

    boolean resumed() {
        return resumed;
    }

    /** {@return how many KeyUpdates the server has sent} */
    int keyUpdatesReceived() {
        return keyUpdatesReceived;
    }

    /** The legacy session id of the ClientHello, which the server echoed. */
    byte[] sessionId() {
        return hello.sessionId().clone();
    }

    String serverName() {
        return serverName;
    }
}
