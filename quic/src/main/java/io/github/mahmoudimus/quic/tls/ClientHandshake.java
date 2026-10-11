// Ported from rustls src/client/hs.rs (the ClientHello, ServerHello and HelloRetryRequest
// handling, the PSK offer and its binder, the early_data offer) and src/client/tls13.rs
// (EncryptedExtensions to Finished, client authentication, resumption, the early traffic secret,
// NewSessionTicket), with the QUIC rules of src/quic.rs: an empty legacy_session_id, no middlebox
// compatibility mode, no EndOfEarlyData, the quic_transport_parameters extension, strict ALPN and
// a max_early_data_size of 0xffffffff (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** The client side of the TLS 1.3 handshake. */
final class ClientHandshake implements Handshake {

    /** Extensions a TLS 1.3 ServerHello may carry (RFC 8446 section 4.2). */
    private static final Set<Integer> SERVER_HELLO_EXTENSIONS = Set.of(
            ExtensionType.KEY_SHARE, ExtensionType.PRE_SHARED_KEY, ExtensionType.SUPPORTED_VERSIONS);
    /** Extensions a HelloRetryRequest may carry. */
    private static final Set<Integer> RETRY_EXTENSIONS = Set.of(
            ExtensionType.KEY_SHARE, ExtensionType.COOKIE, ExtensionType.SUPPORTED_VERSIONS);
    /** Extensions EncryptedExtensions may carry (RFC 8446 section 4.2, RFC 9001 section 8.2). */
    private static final Set<Integer> ENCRYPTED_EXTENSIONS = Set.of(
            ExtensionType.SERVER_NAME, ExtensionType.MAX_FRAGMENT_LENGTH, ExtensionType.SUPPORTED_GROUPS,
            ExtensionType.USE_SRTP, ExtensionType.HEARTBEAT, ExtensionType.ALPN,
            ExtensionType.CLIENT_CERTIFICATE_TYPE, ExtensionType.SERVER_CERTIFICATE_TYPE,
            ExtensionType.EARLY_DATA, ExtensionType.QUIC_TRANSPORT_PARAMETERS);
    /** The longest ticket lifetime (RFC 8446 section 4.6.1): 7 days. */
    private static final long MAX_TICKET_LIFETIME = 604800;
    /** Extensions a server's CertificateEntry may carry. */
    private static final Set<Integer> CERTIFICATE_EXTENSIONS = Set.of(
            ExtensionType.STATUS_REQUEST, ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP);
    /** Advertised for certificate signatures only, as RFC 8446 section 4.2.3 allows. */
    private static final List<SignatureScheme> CERTIFICATE_ONLY_SCHEMES = List.of(
            SignatureScheme.RSA_PKCS1_SHA256, SignatureScheme.RSA_PKCS1_SHA384, SignatureScheme.RSA_PKCS1_SHA512);

    private sealed interface State {}

    private record ExpectServerHello(boolean retried) implements State {}

    private record ExpectEncryptedExtensions() implements State {}

    private record ExpectCertificateOrCertificateRequest() implements State {}

    private record ExpectCertificate(AuthRequest request) implements State {}

    private record ExpectCertificateVerify(List<X509Certificate> chain, AuthRequest request) implements State {}

    private record ExpectFinished(AuthRequest request) implements State {}

    private record Traffic() implements State {}

    /** A server's CertificateRequest: its context and the schemes it accepts. */
    private record AuthRequest(byte[] context, int[] schemes) {}

    private final TlsSession session;
    private final TlsConfig config;
    private final String serverName;
    private final byte[] random = new byte[32];
    private final Set<Integer> sentExtensions = new HashSet<>();
    private final Transcript transcript = new Transcript();
    private KeyExchange keyShare;
    private byte[] cookie;
    private CipherSuite retrySuite;
    private KeySchedule keySchedule;
    private byte[] clientHandshakeSecret;
    private byte[] serverHandshakeSecret;
    private State state;
    /** The ticket to resume with, or null; dropped if a retry selects a suite of another hash. */
    private SessionTicket ticket;
    /** Whether the latest ClientHello offered a PSK. */
    private boolean pskOffered;
    /** Whether the first ClientHello offered early data. */
    private boolean earlyDataOffered;
    private boolean resumed;
    private byte[] resumptionMaster;

    ClientHandshake(TlsSession session, String serverName, SessionTicket ticket) {
        this.session = session;
        this.config = session.config;
        this.serverName = serverName;
        this.ticket = usable(ticket);
        config.random.nextBytes(random);
        session.clientRandom(random);
        keyShare = KeyExchange.generate(config.groups.get(0), config.random);
        sendClientHello();
        state = new ExpectServerHello(false);
    }

    /** The ticket if this connection may offer it: unexpired, for this server, with a suite we offer. */
    private SessionTicket usable(SessionTicket t) {
        if (t == null || t.isExpired(config.clock.instant()) || !config.cipherSuites.contains(t.suite)) {
            return null;
        }
        if (!Objects.equals(t.serverName, sniName())) {
            return null;
        }
        return t;
    }

    /** The name sent in SNI, or null. */
    private String sniName() {
        if (serverName == null || HostnameChecker.isIpLiteral(serverName)) {
            return null;
        }
        return serverName.endsWith(".") ? serverName.substring(0, serverName.length() - 1) : serverName;
    }

    /** Whether the first ClientHello offered early data. */
    boolean earlyDataOffered() {
        return earlyDataOffered;
    }

    @Override
    public void handle(HandshakeMessage message, byte[] raw) throws QuicException {
        state = switch (state) {
            case ExpectServerHello s -> onServerHello(s, message, raw);
            case ExpectEncryptedExtensions s -> onEncryptedExtensions(message, raw);
            case ExpectCertificateOrCertificateRequest s -> onCertificateOrRequest(message, raw);
            case ExpectCertificate s -> onCertificate(s.request(), message, raw);
            case ExpectCertificateVerify s -> onCertificateVerify(s, message, raw);
            case ExpectFinished s -> onFinished(s, message, raw);
            case Traffic s -> onTraffic(message);
        };
    }

    private static QuicException unexpected(HandshakeMessage message, String expected) {
        return TlsAlert.unexpectedMessage("got " + HandshakeType.name(message.type()) + ", expected " + expected);
    }

    // --- ClientHello ---

    private List<SignatureScheme> advertisedSchemes() {
        Set<SignatureScheme> schemes = new LinkedHashSet<>(config.signatureSchemes);
        schemes.addAll(CERTIFICATE_ONLY_SCHEMES);
        return List.copyOf(schemes);
    }

    private void sendClientHello() {
        List<Extension> extensions = new ArrayList<>();
        String sni = sniName();
        if (sni != null) {
            extensions.add(new Extension(ExtensionType.SERVER_NAME, Extensions.encodeServerName(sni)));
        }
        extensions.add(new Extension(ExtensionType.SUPPORTED_GROUPS,
                Extensions.encodeU16List(config.groups.stream().mapToInt(NamedGroup::code).toArray())));
        extensions.add(new Extension(ExtensionType.SIGNATURE_ALGORITHMS,
                Extensions.encodeU16List(advertisedSchemes().stream().mapToInt(SignatureScheme::code).toArray())));
        extensions.add(new Extension(ExtensionType.ALPN, Extensions.encodeAlpn(config.alpnProtocols)));
        extensions.add(new Extension(ExtensionType.QUIC_TRANSPORT_PARAMETERS, session.localTransportParameters));
        extensions.add(new Extension(ExtensionType.SUPPORTED_VERSIONS,
                Extensions.encodeSupportedVersionsClient(HandshakeMessage.TLS13)));
        extensions.add(new Extension(ExtensionType.KEY_SHARE, Extensions.encodeKeyShareClient(
                List.of(new KeyShare(keyShare.group().code(), keyShare.publicKey())))));
        if (cookie != null) {
            extensions.add(new Extension(ExtensionType.COOKIE, Extensions.encodeCookie(cookie)));
        }
        // Only psk_dhe_ke: a resumed handshake always has a fresh (EC)DHE exchange
        extensions.add(new Extension(ExtensionType.PSK_KEY_EXCHANGE_MODES,
                Extensions.encodePskKeyExchangeModes(Extensions.PSK_DHE_KE)));
        boolean first = !transcript.started();
        pskOffered = ticket != null;
        int hashLength = 0;
        if (pskOffered) {
            byte[] ticketAlpn = ticket.alpn.getBytes(StandardCharsets.ISO_8859_1);
            if (first && config.earlyData && ticket.allowsEarlyData()
                    && config.alpnProtocols.stream().anyMatch(p -> Arrays.equals(p, ticketAlpn))) {
                // Early data only in the first ClientHello (RFC 8446 section 4.2.10)
                extensions.add(new Extension(ExtensionType.EARLY_DATA, new byte[0]));
                earlyDataOffered = true;
            }
            hashLength = ticket.suite.hkdf().hashLength();
            PskIdentity identity = new PskIdentity(ticket.ticket, ticket.obfuscatedAge(config.clock.instant()));
            // The binder is filled in once the rest of the message is known; pre_shared_key goes last
            extensions.add(new Extension(ExtensionType.PRE_SHARED_KEY,
                    Extensions.encodePskOffer(List.of(identity), List.of(new byte[hashLength]))));
        }
        for (Extension e : extensions) sentExtensions.add(e.type());
        ClientHello hello = new ClientHello(HandshakeMessage.LEGACY_VERSION, random, new byte[0],
                config.cipherSuites.stream().mapToInt(CipherSuite::code).toArray(), new byte[] {0}, extensions);
        byte[] encoded = hello.encode();
        KeySchedule early = null;
        if (pskOffered) {
            // RFC 8446 section 4.2.11.2: the binder covers the transcript up to the ClientHello
            // without its binders list (2 bytes of list length, 1 of binder length, the binder)
            byte[] prefix = Arrays.copyOf(encoded, encoded.length - (3 + hashLength));
            byte[] hash = first ? Transcript.newDigest(ticket.suite).digest(prefix) : transcript.hashWith(prefix);
            early = new KeySchedule(ticket.suite, ticket.psk);
            System.arraycopy(early.binder(hash), 0, encoded, encoded.length - hashLength, hashLength);
        }
        transcript.add(encoded);
        session.send(EncryptionLevel.INITIAL, encoded);
        if (earlyDataOffered && first) {
            byte[] secret = early.deriveSecret(KeySchedule.CLIENT_EARLY_TRAFFIC,
                    Transcript.newDigest(ticket.suite).digest(encoded));
            session.earlySecrets(ticket.suite, secret);
        }
    }

    // --- ServerHello and HelloRetryRequest ---

    private State onServerHello(ExpectServerHello st, HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof ServerHello hello)) throw unexpected(message, "ServerHello");
        session.requireAligned();
        boolean retry = hello.isHelloRetryRequest();
        String name = retry ? "HelloRetryRequest" : "ServerHello";
        if (retry && st.retried()) throw TlsAlert.unexpectedMessage("second HelloRetryRequest");
        CipherSuite suite = checkHello(hello, name, retry);
        return retry ? onHelloRetryRequest(hello, suite, raw) : onRealServerHello(st, hello, suite, raw);
    }

    /** The checks a ServerHello and a HelloRetryRequest share; returns the selected suite. */
    private CipherSuite checkHello(ServerHello hello, String name, boolean retry) throws QuicException {
        Set<Integer> allowed = retry ? RETRY_EXTENSIONS : SERVER_HELLO_EXTENSIONS;
        Extensions.checkNoDuplicates(hello.extensions(), name);
        byte[] version = Extension.find(hello.extensions(), ExtensionType.SUPPORTED_VERSIONS);
        if (version == null) {
            throw TlsAlert.error(TlsAlert.PROTOCOL_VERSION, "server did not select TLS 1.3");
        }
        int selected = Extensions.decodeSupportedVersionServer(version);
        if (selected != HandshakeMessage.TLS13) {
            throw TlsAlert.illegalParameter(name + " selected version 0x" + Integer.toHexString(selected));
        }
        if (hello.legacyVersion() != HandshakeMessage.LEGACY_VERSION) {
            throw TlsAlert.illegalParameter(name + " legacy_version 0x" + Integer.toHexString(hello.legacyVersion()));
        }
        if (hello.sessionId().length != 0) {
            // QUIC clients send an empty legacy_session_id (RFC 9001 section 8.4), so the echo must be empty.
            throw TlsAlert.illegalParameter(name + " legacy_session_id_echo does not match");
        }
        if (hello.compressionMethod() != 0) {
            throw TlsAlert.illegalParameter(name + " selected compression " + hello.compressionMethod());
        }
        CipherSuite suite = CipherSuite.forCode(hello.cipherSuite());
        if (suite == null || !config.cipherSuites.contains(suite)) {
            throw TlsAlert.illegalParameter(name + " selected a cipher suite that was not offered");
        }
        for (Extension e : hello.extensions()) {
            // A HelloRetryRequest's cookie is the one extension a server sends unasked (RFC 8446 section 4.2).
            boolean solicited = sentExtensions.contains(e.type()) || (retry && e.type() == ExtensionType.COOKIE);
            if (!solicited) {
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, name + " has unsolicited " + ExtensionType.name(e.type()));
            }
            if (!allowed.contains(e.type())) {
                throw TlsAlert.illegalParameter(name + " may not carry " + ExtensionType.name(e.type()));
            }
        }
        return suite;
    }

    private State onHelloRetryRequest(ServerHello hrr, CipherSuite suite, byte[] raw) throws QuicException {
        byte[] cookieData = Extension.find(hrr.extensions(), ExtensionType.COOKIE);
        byte[] groupData = Extension.find(hrr.extensions(), ExtensionType.KEY_SHARE);
        byte[] newCookie = cookieData != null ? Extensions.decodeCookie(cookieData) : null;
        if (newCookie != null && newCookie.length == 0) {
            throw TlsAlert.illegalParameter("HelloRetryRequest has an empty cookie");
        }
        if (newCookie == null && groupData == null) {
            throw TlsAlert.illegalParameter("HelloRetryRequest asks for no change");
        }
        KeyExchange share = keyShare;
        if (groupData != null) {
            int code = Extensions.decodeKeyShareRetry(groupData);
            NamedGroup requested = NamedGroup.forCode(code);
            // RFC 8446 section 4.2.8: a group we support, and not the one we already sent a share for.
            if (requested == null || !config.groups.contains(requested)) {
                throw TlsAlert.illegalParameter("HelloRetryRequest asks for a group that was not offered");
            }
            if (requested == keyShare.group()) {
                throw TlsAlert.illegalParameter("HelloRetryRequest asks for the group already offered");
            }
            share = KeyExchange.generate(requested, config.random);
        }
        if (ticket != null && ticket.suite.hkdf() != suite.hkdf()) {
            ticket = null; // the PSK cannot be used with this suite's hash (RFC 8446 section 4.1.4)
        }
        retrySuite = suite;
        transcript.start(suite);
        transcript.rollupForRetry();
        transcript.add(raw);
        keyShare = share;
        cookie = newCookie;
        session.helloRetried();
        sendClientHello();
        return new ExpectServerHello(true);
    }

    private State onRealServerHello(ExpectServerHello st, ServerHello hello, CipherSuite suite, byte[] raw)
            throws QuicException {
        if (st.retried() && suite != retrySuite) {
            throw TlsAlert.illegalParameter("ServerHello selected a different cipher suite than its HelloRetryRequest");
        }
        byte[] shareData = Extension.find(hello.extensions(), ExtensionType.KEY_SHARE);
        if (shareData == null) throw TlsAlert.error(TlsAlert.MISSING_EXTENSION, "ServerHello has no key_share");
        KeyShare share = Extensions.decodeKeyShareServer(shareData);
        if (share.group() != keyShare.group().code()) {
            throw TlsAlert.illegalParameter("ServerHello key share is for a group that was not offered");
        }
        byte[] shared = keyShare.agree(share.keyExchange());
        byte[] selected = Extension.find(hello.extensions(), ExtensionType.PRE_SHARED_KEY);
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
            session.resumed();
            session.peerCertificates(ticket.peerCertificates);
        }
        session.negotiated(suite, keyShare.group());
        transcript.start(suite);
        transcript.add(raw);
        keySchedule = resumed ? new KeySchedule(suite, ticket.psk) : new KeySchedule(suite);
        keySchedule.inputSharedSecret(shared);
        byte[] hash = transcript.hash();
        clientHandshakeSecret = keySchedule.deriveSecret(KeySchedule.CLIENT_HANDSHAKE_TRAFFIC, hash);
        serverHandshakeSecret = keySchedule.deriveSecret(KeySchedule.SERVER_HANDSHAKE_TRAFFIC, hash);
        keySchedule.inputEmpty();
        session.handshakeSecrets(clientHandshakeSecret, serverHandshakeSecret);
        session.readLevel(EncryptionLevel.HANDSHAKE);
        return new ExpectEncryptedExtensions();
    }

    // --- EncryptedExtensions ---

    private State onEncryptedExtensions(HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof EncryptedExtensions ee)) throw unexpected(message, "EncryptedExtensions");
        transcript.add(raw);
        List<Extension> extensions = ee.extensions();
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
        byte[] earlyData = Extension.find(extensions, ExtensionType.EARLY_DATA);
        if (earlyData != null && (!earlyDataOffered || session.usedHelloRetryRequest())) {
            throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, "EncryptedExtensions accepts early data that was not offered");
        }
        if (earlyData != null) {
            Extensions.expectEmpty(earlyData, ExtensionType.EARLY_DATA);
            if (!resumed || session.cipherSuite() != ticket.suite) {
                // RFC 8446 section 4.2.10: early data needs the first PSK and the ticket's suite
                throw TlsAlert.illegalParameter("server accepts early data without resuming with the ticket's suite");
            }
        }

        byte[] alpnData = Extension.find(extensions, ExtensionType.ALPN);
        if (alpnData == null) {
            // RFC 9001 section 8.1: QUIC requires ALPN.
            throw TlsAlert.error(TlsAlert.NO_APPLICATION_PROTOCOL, "server selected no application protocol");
        }
        List<byte[]> selected = Extensions.decodeAlpn(alpnData);
        if (selected.size() != 1) {
            throw TlsAlert.decodeError("server selected " + selected.size() + " application protocols");
        }
        byte[] protocol = selected.get(0);
        if (config.alpnProtocols.stream().noneMatch(p -> Arrays.equals(p, protocol))) {
            throw TlsAlert.illegalParameter("server selected an application protocol that was not offered");
        }
        session.alpn(new String(protocol, StandardCharsets.ISO_8859_1));
        if (earlyData != null) {
            if (!session.negotiatedAlpn().equals(ticket.alpn)) {
                throw TlsAlert.illegalParameter("server accepts early data for another application protocol");
            }
            session.earlyDataAccepted();
        }

        byte[] parameters = Extension.find(extensions, ExtensionType.QUIC_TRANSPORT_PARAMETERS);
        if (parameters == null) {
            throw TlsAlert.error(TlsAlert.MISSING_EXTENSION, "server sent no quic_transport_parameters");
        }
        session.peerTransportParameters(parameters);
        return resumed ? new ExpectFinished(null) : new ExpectCertificateOrCertificateRequest();
    }

    // --- CertificateRequest, Certificate, CertificateVerify ---

    private State onCertificateOrRequest(HandshakeMessage message, byte[] raw) throws QuicException {
        if (message instanceof CertificateRequest request) {
            transcript.add(raw);
            if (request.context().length != 0) {
                throw TlsAlert.illegalParameter("CertificateRequest during the handshake has a context");
            }
            Extensions.checkNoDuplicates(request.extensions(), "CertificateRequest");
            byte[] schemes = Extension.find(request.extensions(), ExtensionType.SIGNATURE_ALGORITHMS);
            if (schemes == null) {
                throw TlsAlert.error(TlsAlert.MISSING_EXTENSION, "CertificateRequest has no signature_algorithms");
            }
            AuthRequest auth = new AuthRequest(request.context(),
                    Extensions.decodeU16List(schemes, "signature_algorithms"));
            return new ExpectCertificate(auth);
        }
        return onCertificate(null, message, raw);
    }

    private State onCertificate(AuthRequest request, HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof CertificateMessage certificate)) {
            throw unexpected(message, request == null ? "Certificate or CertificateRequest" : "Certificate");
        }
        transcript.add(raw);
        if (certificate.context().length != 0) {
            throw TlsAlert.illegalParameter("server Certificate has a request context");
        }
        if (certificate.entries().isEmpty()) {
            // RFC 8446 section 4.4.2.4.
            throw TlsAlert.decodeError("server sent no certificate");
        }
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
        if (!config.trustAllCertificates) {
            CertificateChecks.verifyServer(config.serverTrust(), chain, config.verifyHostname ? serverName : null);
        }
        session.peerCertificates(chain);
        return new ExpectCertificateVerify(chain, request);
    }

    private State onCertificateVerify(ExpectCertificateVerify st, HandshakeMessage message, byte[] raw)
            throws QuicException {
        if (!(message instanceof CertificateVerify verify)) throw unexpected(message, "CertificateVerify");
        SignatureScheme scheme = SignatureScheme.forCode(verify.scheme());
        if (scheme == null || !config.signatureSchemes.contains(scheme)) {
            // Includes rsa_pkcs1, advertised for certificates but not allowed here (RFC 8446 section 4.4.3).
            throw TlsAlert.illegalParameter("CertificateVerify uses a signature scheme that was not offered for it");
        }
        X509Certificate leaf = st.chain().get(0);
        if (!scheme.compatibleWith(leaf.getPublicKey())) {
            throw TlsAlert.illegalParameter("CertificateVerify scheme " + scheme + " does not fit the certificate key");
        }
        byte[] content = Signatures.content(true, transcript.hash());
        if (!Signatures.verify(scheme, leaf.getPublicKey(), content, verify.signature())) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "server CertificateVerify signature is invalid");
        }
        transcript.add(raw);
        session.peerSignatureScheme(scheme);
        return new ExpectFinished(st.request());
    }

    // --- Finished ---

    private State onFinished(ExpectFinished st, HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof Finished finished)) throw unexpected(message, "Finished");
        session.requireAligned();
        byte[] expected = keySchedule.finishedVerifyData(serverHandshakeSecret, transcript.hash());
        if (!MessageDigest.isEqual(expected, finished.verifyData())) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "server Finished is incorrect");
        }
        transcript.add(raw);
        byte[] hash = transcript.hash();
        byte[] clientApplication = keySchedule.deriveSecret(KeySchedule.CLIENT_APPLICATION_TRAFFIC, hash);
        byte[] serverApplication = keySchedule.deriveSecret(KeySchedule.SERVER_APPLICATION_TRAFFIC, hash);
        byte[] exporterMaster = keySchedule.deriveSecret(KeySchedule.EXPORTER_MASTER, hash);

        if (st.request() != null) sendClientCertificate(st.request());
        byte[] verifyData = keySchedule.finishedVerifyData(clientHandshakeSecret, transcript.hash());
        byte[] clientFinished = new Finished(verifyData).encode();
        transcript.add(clientFinished);
        session.send(EncryptionLevel.HANDSHAKE, clientFinished);
        resumptionMaster = keySchedule.deriveSecret(KeySchedule.RESUMPTION_MASTER, transcript.hash());

        session.applicationSecrets(keySchedule, clientApplication, serverApplication, exporterMaster);
        session.readLevel(EncryptionLevel.ONE_RTT);
        session.completed();
        return new Traffic();
    }

    private void sendClientCertificate(AuthRequest request) throws QuicException {
        CertifiedKey key = config.clientCertificate;
        SignatureScheme scheme = null;
        if (key != null) {
            for (int code : request.schemes()) {
                SignatureScheme candidate = SignatureScheme.forCode(code);
                if (candidate != null && config.signatureSchemes.contains(candidate)
                        && candidate.compatibleWith(key.privateKey())) {
                    scheme = candidate;
                    break;
                }
            }
        }
        List<CertificateEntry> entries = new ArrayList<>();
        if (scheme != null) {
            for (X509Certificate cert : key.chain()) {
                try {
                    entries.add(new CertificateEntry(cert.getEncoded(), List.of()));
                } catch (CertificateEncodingException e) {
                    throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot encode client certificate");
                }
            }
        }
        byte[] certificate = new CertificateMessage(request.context(), entries).encode();
        transcript.add(certificate);
        session.send(EncryptionLevel.HANDSHAKE, certificate);
        if (scheme == null) return;
        byte[] signature;
        try {
            signature = Signatures.sign(scheme, key.privateKey(), Signatures.content(false, transcript.hash()), config.random);
        } catch (GeneralSecurityException e) {
            throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot sign CertificateVerify: " + e.getMessage());
        }
        byte[] verify = new CertificateVerify(scheme.code(), signature).encode();
        transcript.add(verify);
        session.send(EncryptionLevel.HANDSHAKE, verify);
    }

    // --- after the handshake ---

    private State onTraffic(HandshakeMessage message) throws QuicException {
        if (message instanceof NewSessionTicket nst) {
            onNewSessionTicket(nst);
            return new Traffic();
        }
        if (message instanceof KeyUpdate) {
            throw TlsAlert.unexpectedMessage("KeyUpdate is not used in QUIC (RFC 9001 section 6)");
        }
        throw unexpected(message, "NewSessionTicket");
    }

    private void onNewSessionTicket(NewSessionTicket nst) throws QuicException {
        if (nst.lifetime() > MAX_TICKET_LIFETIME) {
            throw TlsAlert.illegalParameter("NewSessionTicket lifetime exceeds 7 days");
        }
        Extensions.checkNoDuplicates(nst.extensions(), "NewSessionTicket");
        long maxEarlyData = 0;
        byte[] earlyData = Extension.find(nst.extensions(), ExtensionType.EARLY_DATA);
        if (earlyData != null) {
            maxEarlyData = Extensions.decodeMaxEarlyDataSize(earlyData);
            if (maxEarlyData != SessionTicket.QUIC_MAX_EARLY_DATA) {
                throw new QuicException(QuicException.PROTOCOL_VIOLATION,
                        "NewSessionTicket max_early_data_size is not 0xffffffff (RFC 9001 section 4.6.1)");
            }
        }
        if (nst.lifetime() == 0) {
            return; // RFC 8446 section 4.6.1: discard it at once
        }
        CipherSuite suite = session.cipherSuite();
        byte[] psk = KeySchedule.resumptionPsk(suite, resumptionMaster, nst.nonce());
        session.newTicket(new SessionTicket(sniName(), suite, nst.ticket(), psk, nst.ageAdd(), nst.lifetime(),
                config.clock.instant(), maxEarlyData, session.negotiatedAlpn(), session.peerTransportParameters(),
                session.peerCertificates()));
    }
}
