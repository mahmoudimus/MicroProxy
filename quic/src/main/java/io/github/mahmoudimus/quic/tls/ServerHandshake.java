// Ported from rustls src/server/hs.rs (ClientHello validation, certificate, suite and group
// selection, ALPN) and src/server/tls13.rs (HelloRetryRequest, PSK acceptance with binder and
// freshness checks, the early data decision, the server's flight, client authentication, Finished
// and ticket issuance), with the QUIC rules of src/quic.rs: the quic_transport_parameters
// extension, strict ALPN, no middlebox compatibility mode, a max_early_data_size of 0xffffffff
// and 0-RTT keys from the client early traffic secret (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.Extensions.KeyShare;
import io.github.mahmoudimus.quic.tls.Extensions.PskIdentity;
import io.github.mahmoudimus.quic.tls.Extensions.PskOffer;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateEntry;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateMessage;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateRequest;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.CertificateVerify;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.EncryptedExtensions;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Finished;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.NewSessionTicket;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** The server side of the TLS 1.3 handshake. */
final class ServerHandshake implements Handshake {

    private sealed interface State {}

    /** Waiting for a ClientHello; {@code retry} is set after a HelloRetryRequest. */
    private record ExpectClientHello(Retry retry) implements State {}

    private record ExpectCertificate() implements State {}

    private record ExpectCertificateVerify(List<X509Certificate> chain) implements State {}

    private record ExpectFinished() implements State {}

    private record Traffic() implements State {}

    /** What the second ClientHello must agree with. */
    private record Retry(String serverName, CipherSuite suite, NamedGroup group) {}

    /** An accepted PSK: the identity's index, the ticket's state and the two ticket ages. */
    private record Resumption(int index, ServerTicket ticket, long clientAgeMillis, long serverAgeMillis) {}

    private final TlsSession session;
    private final TlsConfig config;
    private final Transcript transcript = new Transcript();
    private KeySchedule keySchedule;
    private byte[] clientHandshakeSecret;
    private State state = new ExpectClientHello(null);
    /** Whether the client offered psk_dhe_ke, so it can use tickets. */
    private boolean ticketsWanted;

    ServerHandshake(TlsSession session) {
        this.session = session;
        this.config = session.config;
    }

    /** Whether this server resumes sessions and sends tickets. */
    private boolean resumption() {
        return config.ticketer != null && config.clientAuth == ClientAuth.NONE;
    }

    @Override
    public void handle(HandshakeMessage message, byte[] raw) throws QuicException {
        state = switch (state) {
            case ExpectClientHello s -> onClientHello(s, message, raw);
            case ExpectCertificate s -> onCertificate(message, raw);
            case ExpectCertificateVerify s -> onCertificateVerify(s, message, raw);
            case ExpectFinished s -> onFinished(message, raw);
            case Traffic s -> throw TlsAlert.unexpectedMessage(
                    "got " + HandshakeType.name(message.type()) + " after the handshake");
        };
    }

    private static QuicException unexpected(HandshakeMessage message, String expected) {
        return TlsAlert.unexpectedMessage("got " + HandshakeType.name(message.type()) + ", expected " + expected);
    }

    private static QuicException missing(int extension) {
        return TlsAlert.error(TlsAlert.MISSING_EXTENSION, "ClientHello has no " + ExtensionType.name(extension));
    }

    // --- ClientHello ---

    private State onClientHello(ExpectClientHello st, HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof ClientHello hello)) throw unexpected(message, "ClientHello");
        session.requireAligned();
        List<Extension> extensions = hello.extensions();
        Extensions.checkNoDuplicates(extensions, "ClientHello");

        byte[] versions = Extension.find(extensions, ExtensionType.SUPPORTED_VERSIONS);
        if (versions == null) throw TlsAlert.error(TlsAlert.PROTOCOL_VERSION, "client does not offer TLS 1.3");
        boolean tls13 = false;
        for (int v : Extensions.decodeSupportedVersionsClient(versions)) tls13 |= v == HandshakeMessage.TLS13;
        if (!tls13) throw TlsAlert.error(TlsAlert.PROTOCOL_VERSION, "client does not offer TLS 1.3");

        if (hello.compressionMethods().length != 1 || hello.compressionMethods()[0] != 0) {
            throw TlsAlert.illegalParameter("ClientHello must offer exactly the null compression method");
        }
        if (hello.sessionId().length != 0) {
            throw new QuicException(QuicException.PROTOCOL_VIOLATION,
                    "ClientHello has a legacy_session_id, which QUIC forbids (RFC 9001 section 8.4)");
        }
        byte[] psk = Extension.find(extensions, ExtensionType.PRE_SHARED_KEY);
        if (psk != null && extensions.get(extensions.size() - 1).type() != ExtensionType.PRE_SHARED_KEY) {
            throw TlsAlert.illegalParameter("pre_shared_key is not the last extension");
        }
        byte[] pskModes = Extension.find(extensions, ExtensionType.PSK_KEY_EXCHANGE_MODES);
        if (psk != null && pskModes == null) throw missing(ExtensionType.PSK_KEY_EXCHANGE_MODES);
        PskOffer pskOffer = psk != null ? Extensions.decodePskOffer(psk) : null;
        if (pskOffer != null && pskOffer.binders().size() != pskOffer.identities().size()) {
            throw TlsAlert.illegalParameter("pre_shared_key has " + pskOffer.identities().size()
                    + " identities and " + pskOffer.binders().size() + " binders");
        }
        boolean pskDhe = false;
        if (pskModes != null) {
            for (byte mode : Extensions.decodePskKeyExchangeModes(pskModes)) pskDhe |= mode == Extensions.PSK_DHE_KE;
        }
        // Only psk_dhe_ke is used: a client that offers psk_ke alone gets a full handshake and no tickets
        ticketsWanted = pskDhe;
        byte[] earlyDataRequest = Extension.find(extensions, ExtensionType.EARLY_DATA);
        if (earlyDataRequest != null) Extensions.expectEmpty(earlyDataRequest, ExtensionType.EARLY_DATA);
        if (st.retry() != null && earlyDataRequest != null) {
            throw TlsAlert.illegalParameter("second ClientHello offers early data");
        }

        byte[] schemesData = Extension.find(extensions, ExtensionType.SIGNATURE_ALGORITHMS);
        if (schemesData == null) throw missing(ExtensionType.SIGNATURE_ALGORITHMS);
        int[] schemeCodes = Extensions.decodeU16List(schemesData, "signature_algorithms");
        byte[] certSchemes = Extension.find(extensions, ExtensionType.SIGNATURE_ALGORITHMS_CERT);
        if (certSchemes != null) Extensions.decodeU16List(certSchemes, "signature_algorithms_cert");

        byte[] groupsData = Extension.find(extensions, ExtensionType.SUPPORTED_GROUPS);
        byte[] sharesData = Extension.find(extensions, ExtensionType.KEY_SHARE);
        if (groupsData == null) throw missing(ExtensionType.SUPPORTED_GROUPS);
        if (sharesData == null) throw missing(ExtensionType.KEY_SHARE);
        int[] groupCodes = Extensions.decodeU16List(groupsData, "supported_groups");
        List<KeyShare> shares = Extensions.decodeKeyShareClient(sharesData);
        Set<Integer> shareGroups = new HashSet<>();
        for (KeyShare share : shares) {
            if (!shareGroups.add(share.group())) throw TlsAlert.illegalParameter("ClientHello repeats a key share group");
            if (!contains(groupCodes, share.group())) {
                throw TlsAlert.illegalParameter("ClientHello has a key share for a group not in supported_groups");
            }
        }

        byte[] parameters = Extension.find(extensions, ExtensionType.QUIC_TRANSPORT_PARAMETERS);
        if (parameters == null) throw missing(ExtensionType.QUIC_TRANSPORT_PARAMETERS);

        byte[] nameData = Extension.find(extensions, ExtensionType.SERVER_NAME);
        String serverName = nameData != null ? Extensions.decodeServerName(nameData) : null;
        byte[] alpnData = Extension.find(extensions, ExtensionType.ALPN);
        List<byte[]> offeredAlpn = alpnData != null ? Extensions.decodeAlpn(alpnData) : List.of();

        if (st.retry() != null && !Objects.equals(serverName, st.retry().serverName())) {
            throw TlsAlert.illegalParameter("second ClientHello changed the server name");
        }

        CipherSuite suite = null;
        for (CipherSuite candidate : config.cipherSuites) {
            if (contains(hello.cipherSuites(), candidate.code())) {
                suite = candidate;
                break;
            }
        }
        if (suite == null) throw TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, "no cipher suite in common");
        if (st.retry() != null && suite != st.retry().suite()) {
            throw TlsAlert.illegalParameter("second ClientHello changed the cipher suite");
        }

        // Our most preferred group the client sent a share for; failing that, our most preferred
        // group it supports, asked for with a HelloRetryRequest.
        // After a retry, only the group asked for will do.
        List<NamedGroup> acceptable = st.retry() != null ? List.of(st.retry().group()) : config.groups;
        NamedGroup group = null;
        KeyShare share = null;
        for (NamedGroup candidate : acceptable) {
            for (KeyShare s : shares) {
                if (s.group() == candidate.code()) {
                    group = candidate;
                    share = s;
                    break;
                }
            }
            if (share != null) break;
        }
        if (st.retry() != null && share == null) {
            throw TlsAlert.illegalParameter("second ClientHello has no key share for the requested group");
        }
        transcript.start(suite);
        if (share == null) {
            transcript.add(raw);
            NamedGroup retryGroup = null;
            for (NamedGroup candidate : config.groups) {
                if (contains(groupCodes, candidate.code())) {
                    retryGroup = candidate;
                    break;
                }
            }
            if (retryGroup == null) throw TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, "no group in common");
            sendHelloRetryRequest(hello, suite, retryGroup);
            return new ExpectClientHello(new Retry(serverName, suite, retryGroup));
        }

        Resumption resuming = pskOffer != null && pskDhe && resumption()
                ? acceptPsk(pskOffer, raw, suite, serverName) : null;
        transcript.add(raw);

        ClientHelloInfo info = clientHelloInfo(serverName, offeredAlpn, schemeCodes, hello.cipherSuites(), groupCodes);
        String alpn = selectAlpn(info, offeredAlpn);
        CertifiedKey certified = null;
        SignatureScheme scheme = null;
        if (resuming == null) {
            certified = selectCertificate(info);
            for (SignatureScheme candidate : info.signatureSchemes()) {
                if (config.signatureSchemes.contains(candidate) && candidate.compatibleWith(certified.privateKey())) {
                    scheme = candidate;
                    break;
                }
            }
            if (scheme == null) {
                throw TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, "no signature scheme in common for the certificate");
            }
        }

        session.serverName(serverName);
        session.alpn(alpn);
        session.peerTransportParameters(parameters);
        session.negotiated(suite, group);

        keySchedule = resuming != null ? new KeySchedule(suite, resuming.ticket().psk()) : new KeySchedule(suite);
        boolean earlyData = earlyDataRequest != null && st.retry() == null
                && acceptEarlyData(resuming, suite, serverName, alpn);
        if (resuming != null) session.resumed();
        if (earlyData) {
            session.earlyDataAccepted();
            session.earlySecrets(suite, keySchedule.deriveSecret(KeySchedule.CLIENT_EARLY_TRAFFIC, transcript.hash()));
        }

        KeyExchange ours = KeyExchange.generate(group, config.random);
        byte[] shared = ours.agree(share.keyExchange());
        sendServerHello(hello, suite, ours, resuming != null ? resuming.index() : -1);
        keySchedule.inputSharedSecret(shared);
        byte[] hash = transcript.hash();
        clientHandshakeSecret = keySchedule.deriveSecret(KeySchedule.CLIENT_HANDSHAKE_TRAFFIC, hash);
        byte[] serverHandshakeSecret = keySchedule.deriveSecret(KeySchedule.SERVER_HANDSHAKE_TRAFFIC, hash);
        keySchedule.inputEmpty();
        session.handshakeSecrets(clientHandshakeSecret, serverHandshakeSecret);

        sendEncryptedExtensions(serverName, alpn, earlyData);
        if (resuming == null) {
            if (config.clientAuth != ClientAuth.NONE) sendCertificateRequest();
            sendCertificate(certified);
            sendCertificateVerify(scheme, certified);
        }
        byte[] verifyData = keySchedule.finishedVerifyData(serverHandshakeSecret, transcript.hash());
        sendHandshake(new Finished(verifyData).encode());

        hash = transcript.hash();
        session.applicationSecrets(keySchedule,
                keySchedule.deriveSecret(KeySchedule.CLIENT_APPLICATION_TRAFFIC, hash),
                keySchedule.deriveSecret(KeySchedule.SERVER_APPLICATION_TRAFFIC, hash),
                keySchedule.deriveSecret(KeySchedule.EXPORTER_MASTER, hash));
        session.readLevel(EncryptionLevel.HANDSHAKE);
        return config.clientAuth != ClientAuth.NONE && resuming == null ? new ExpectCertificate() : new ExpectFinished();
    }

    /**
     * Looks for an offered ticket this server can resume (RFC 8446 section 4.2.11): one it sealed,
     * unexpired, for the same server name and a suite of the same hash. The first such identity's
     * binder must be correct; tickets that do not open are passed over, as another server's or an
     * old key's may be.
     */
    private Resumption acceptPsk(PskOffer offer, byte[] raw, CipherSuite suite, String serverName)
            throws QuicException {
        Instant now = config.clock.instant();
        byte[] prefix = null;
        for (int i = 0; i < offer.identities().size(); i++) {
            PskIdentity identity = offer.identities().get(i);
            byte[] plain = config.ticketer.decrypt(identity.identity());
            ServerTicket ticket = plain != null ? ServerTicket.decode(plain) : null;
            if (ticket == null || ticket.suite().hkdf() != suite.hkdf()
                    || !Objects.equals(ticket.serverName(), serverName)) {
                continue;
            }
            long serverAge = Duration.between(ticket.issued(), now).toMillis();
            if (serverAge < 0 || serverAge > ticket.lifetimeSeconds() * 1000) {
                continue; // expired
            }
            if (prefix == null) {
                prefix = Arrays.copyOf(raw, raw.length - offer.bindersLength());
            }
            byte[] expected = new KeySchedule(suite, ticket.psk()).binder(transcript.hashWith(prefix));
            if (!MessageDigest.isEqual(expected, offer.binders().get(i))) {
                throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "PSK binder is incorrect");
            }
            long clientAge = (identity.obfuscatedTicketAge() - ticket.ageAdd()) & 0xffffffffL;
            return new Resumption(i, ticket, clientAge, serverAge);
        }
        return null;
    }

    /**
     * Whether to accept 0-RTT (RFC 8446 section 4.2.10, RFC 9001 section 4.6): only with the first
     * PSK, a ticket that allows it, the same suite, ALPN protocol and server name, transport
     * parameters no smaller than those the ticket remembers, and the policy's consent.
     */
    private boolean acceptEarlyData(Resumption resuming, CipherSuite suite, String serverName, String alpn) {
        if (resuming == null || resuming.index() != 0 || !config.earlyData) {
            return false;
        }
        ServerTicket ticket = resuming.ticket();
        if (ticket.maxEarlyDataSize() != SessionTicket.QUIC_MAX_EARLY_DATA || ticket.suite() != suite
                || !ticket.alpn().equals(alpn) || !Objects.equals(ticket.serverName(), serverName)) {
            return false;
        }
        try {
            if (session.earlyDataParameters != null && !session.earlyDataParameters.test(ticket.transportParameters())) {
                return false;
            }
            return config.earlyDataPolicy.accept(new EarlyDataAttempt(serverName, alpn, ticket.id(), ticket.issued(),
                    Duration.ofMillis(resuming.clientAgeMillis()), Duration.ofMillis(resuming.serverAgeMillis())));
        } catch (RuntimeException e) {
            return false; // a failing policy rejects early data; the handshake goes on
        }
    }

    private static boolean contains(int[] values, int value) {
        for (int v : values) {
            if (v == value) return true;
        }
        return false;
    }

    private static ClientHelloInfo clientHelloInfo(String serverName, List<byte[]> alpn, int[] schemes,
            int[] suites, int[] groups) {
        List<String> protocols = new ArrayList<>();
        for (byte[] p : alpn) protocols.add(new String(p, StandardCharsets.ISO_8859_1));
        List<SignatureScheme> schemeList = new ArrayList<>();
        for (int code : schemes) {
            SignatureScheme s = SignatureScheme.forCode(code);
            if (s != null && s.allowedInCertificateVerify() && !schemeList.contains(s)) schemeList.add(s);
        }
        List<CipherSuite> suiteList = new ArrayList<>();
        for (int code : suites) {
            CipherSuite s = CipherSuite.forCode(code);
            if (s != null && !suiteList.contains(s)) suiteList.add(s);
        }
        List<NamedGroup> groupList = new ArrayList<>();
        for (int code : groups) {
            NamedGroup g = NamedGroup.forCode(code);
            if (g != null && !groupList.contains(g)) groupList.add(g);
        }
        return new ClientHelloInfo(serverName, protocols, schemeList, suiteList, groupList);
    }

    /** RFC 9001 section 8.1: QUIC requires ALPN, so no common protocol is fatal. */
    private String selectAlpn(ClientHelloInfo info, List<byte[]> offered) throws QuicException {
        if (offered.isEmpty()) {
            throw TlsAlert.error(TlsAlert.NO_APPLICATION_PROTOCOL, "client offered no application protocol");
        }
        String selected;
        if (config.alpnSelector != null) {
            selected = select(() -> config.alpnSelector.apply(info), "ALPN selector");
            if (selected != null && !info.alpnProtocols().contains(selected)) selected = null;
        } else {
            selected = null;
            for (byte[] ours : config.alpnProtocols) {
                String candidate = new String(ours, StandardCharsets.ISO_8859_1);
                if (info.alpnProtocols().contains(candidate)) {
                    selected = candidate;
                    break;
                }
            }
        }
        if (selected == null) {
            throw TlsAlert.error(TlsAlert.NO_APPLICATION_PROTOCOL, "no application protocol in common");
        }
        return selected;
    }

    private CertifiedKey selectCertificate(ClientHelloInfo info) throws QuicException {
        CertifiedKey key = select(() -> config.certificateSelector.apply(info), "certificate selector");
        if (key == null) {
            throw info.serverName() != null
                    ? TlsAlert.error(TlsAlert.UNRECOGNIZED_NAME, "no certificate for " + info.serverName())
                    : TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, "no certificate");
        }
        return key;
    }

    private interface Selection<T> {
        T get();
    }

    private static <T> T select(Selection<T> selection, String what) throws QuicException {
        try {
            return selection.get();
        } catch (RuntimeException e) {
            QuicException error = TlsAlert.error(TlsAlert.INTERNAL_ERROR, what + " failed: " + e);
            error.initCause(e);
            throw error;
        }
    }

    // --- the server's messages ---

    private void sendHelloRetryRequest(ClientHello hello, CipherSuite suite, NamedGroup group) {
        List<Extension> extensions = List.of(
                new Extension(ExtensionType.SUPPORTED_VERSIONS,
                        Extensions.encodeSupportedVersionServer(HandshakeMessage.TLS13)),
                new Extension(ExtensionType.KEY_SHARE, Extensions.encodeKeyShareRetry(group.code())));
        byte[] retry = new ServerHello(HandshakeMessage.LEGACY_VERSION, HandshakeMessage.HELLO_RETRY_REQUEST_RANDOM,
                hello.sessionId(), suite.code(), 0, extensions).encode();
        transcript.rollupForRetry();
        transcript.add(retry);
        session.send(EncryptionLevel.INITIAL, retry);
        session.helloRetried();
    }

    private void sendServerHello(ClientHello hello, CipherSuite suite, KeyExchange share, int pskIdentity) {
        session.clientRandom(hello.random());
        byte[] random = new byte[32];
        config.random.nextBytes(random);
        List<Extension> extensions = new ArrayList<>();
        extensions.add(new Extension(ExtensionType.SUPPORTED_VERSIONS,
                Extensions.encodeSupportedVersionServer(HandshakeMessage.TLS13)));
        extensions.add(new Extension(ExtensionType.KEY_SHARE,
                Extensions.encodeKeyShareServer(new KeyShare(share.group().code(), share.publicKey()))));
        if (pskIdentity >= 0) {
            extensions.add(new Extension(ExtensionType.PRE_SHARED_KEY, Extensions.encodePskSelected(pskIdentity)));
        }
        byte[] serverHello = new ServerHello(HandshakeMessage.LEGACY_VERSION, random, hello.sessionId(),
                suite.code(), 0, extensions).encode();
        transcript.add(serverHello);
        session.send(EncryptionLevel.INITIAL, serverHello);
    }

    private void sendHandshake(byte[] message) {
        transcript.add(message);
        session.send(EncryptionLevel.HANDSHAKE, message);
    }

    private void sendEncryptedExtensions(String serverName, String alpn, boolean earlyData) {
        List<Extension> extensions = new ArrayList<>();
        if (serverName != null) extensions.add(new Extension(ExtensionType.SERVER_NAME, new byte[0]));
        if (earlyData) extensions.add(new Extension(ExtensionType.EARLY_DATA, new byte[0]));
        extensions.add(new Extension(ExtensionType.ALPN,
                Extensions.encodeAlpn(List.of(alpn.getBytes(StandardCharsets.ISO_8859_1)))));
        extensions.add(new Extension(ExtensionType.QUIC_TRANSPORT_PARAMETERS, session.localTransportParameters));
        sendHandshake(new EncryptedExtensions(extensions).encode());
    }

    private void sendCertificateRequest() {
        int[] schemes = config.signatureSchemes.stream().mapToInt(SignatureScheme::code).toArray();
        sendHandshake(new CertificateRequest(new byte[0], List.of(
                new Extension(ExtensionType.SIGNATURE_ALGORITHMS, Extensions.encodeU16List(schemes)))).encode());
    }

    private void sendCertificate(CertifiedKey certified) throws QuicException {
        List<CertificateEntry> entries = new ArrayList<>();
        for (X509Certificate cert : certified.chain()) {
            try {
                entries.add(new CertificateEntry(cert.getEncoded(), List.of()));
            } catch (CertificateEncodingException e) {
                throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot encode certificate");
            }
        }
        sendHandshake(new CertificateMessage(new byte[0], entries).encode());
    }

    private void sendCertificateVerify(SignatureScheme scheme, CertifiedKey certified) throws QuicException {
        byte[] signature;
        try {
            signature = Signatures.sign(scheme, certified.privateKey(),
                    Signatures.content(true, transcript.hash()), config.random);
        } catch (GeneralSecurityException e) {
            throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot sign CertificateVerify: " + e.getMessage());
        }
        sendHandshake(new CertificateVerify(scheme.code(), signature).encode());
    }

    // --- client authentication and Finished ---

    private State onCertificate(HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof CertificateMessage certificate)) throw unexpected(message, "Certificate");
        transcript.add(raw);
        if (certificate.context().length != 0) {
            throw TlsAlert.illegalParameter("client Certificate has the wrong request context");
        }
        for (CertificateEntry entry : certificate.entries()) {
            Extensions.checkNoDuplicates(entry.extensions(), "CertificateEntry");
            if (!entry.extensions().isEmpty()) {
                // The CertificateRequest asked for no certificate extensions.
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, "CertificateEntry has unsolicited "
                        + ExtensionType.name(entry.extensions().get(0).type()));
            }
        }
        if (certificate.entries().isEmpty()) {
            if (config.clientAuth == ClientAuth.REQUIRE) {
                throw TlsAlert.error(TlsAlert.CERTIFICATE_REQUIRED, "client sent no certificate");
            }
            return new ExpectFinished();
        }
        List<X509Certificate> chain = CertificateChecks.parse(certificate.entries());
        CertificateChecks.verifyClient(config.clientTrust(), chain);
        return new ExpectCertificateVerify(chain);
    }

    private State onCertificateVerify(ExpectCertificateVerify st, HandshakeMessage message, byte[] raw)
            throws QuicException {
        if (!(message instanceof CertificateVerify verify)) throw unexpected(message, "CertificateVerify");
        SignatureScheme scheme = SignatureScheme.forCode(verify.scheme());
        if (scheme == null || !config.signatureSchemes.contains(scheme)) {
            throw TlsAlert.illegalParameter("CertificateVerify uses a signature scheme that was not requested");
        }
        X509Certificate leaf = st.chain().get(0);
        if (!scheme.compatibleWith(leaf.getPublicKey())) {
            throw TlsAlert.illegalParameter("CertificateVerify scheme " + scheme + " does not fit the certificate key");
        }
        byte[] content = Signatures.content(false, transcript.hash());
        if (!Signatures.verify(scheme, leaf.getPublicKey(), content, verify.signature())) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "client CertificateVerify signature is invalid");
        }
        transcript.add(raw);
        session.peerCertificates(st.chain());
        session.peerSignatureScheme(scheme);
        return new ExpectFinished();
    }

    private State onFinished(HandshakeMessage message, byte[] raw) throws QuicException {
        if (!(message instanceof Finished finished)) throw unexpected(message, "Finished");
        session.requireAligned();
        byte[] expected = keySchedule.finishedVerifyData(clientHandshakeSecret, transcript.hash());
        if (!MessageDigest.isEqual(expected, finished.verifyData())) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "client Finished is incorrect");
        }
        transcript.add(raw);
        session.readLevel(EncryptionLevel.ONE_RTT);
        session.completed();
        if (resumption() && ticketsWanted && config.ticketsPerConnection > 0) {
            byte[] resumptionMaster = keySchedule.deriveSecret(KeySchedule.RESUMPTION_MASTER, transcript.hash());
            for (int i = 0; i < config.ticketsPerConnection; i++) {
                sendTicket(resumptionMaster, new byte[] {(byte) i});
            }
        }
        return new Traffic();
    }

    /** Sends a NewSessionTicket (RFC 8446 section 4.6.1) sealing the session with the ticketer. */
    private void sendTicket(byte[] resumptionMaster, byte[] nonce) {
        CipherSuite suite = session.cipherSuite();
        long ageAdd = config.random.nextInt() & 0xffffffffL;
        byte[] id = new byte[ServerTicket.ID_LENGTH];
        config.random.nextBytes(id);
        long lifetime = config.ticketer.lifetime().toSeconds();
        long maxEarlyData = config.earlyData ? SessionTicket.QUIC_MAX_EARLY_DATA : 0;
        ServerTicket state = new ServerTicket(suite, KeySchedule.resumptionPsk(suite, resumptionMaster, nonce), ageAdd,
                config.clock.instant(), lifetime, maxEarlyData, session.serverName(), session.negotiatedAlpn(),
                session.localTransportParameters, id);
        byte[] ticket = config.ticketer.encrypt(state.encode());
        List<Extension> extensions = config.earlyData
                ? List.of(new Extension(ExtensionType.EARLY_DATA, Extensions.encodeMaxEarlyDataSize(maxEarlyData)))
                : List.of();
        session.send(EncryptionLevel.ONE_RTT, new NewSessionTicket(lifetime, ageAdd, nonce, ticket, extensions).encode());
    }
}
