// The flow and checks are ported from Go src/crypto/tls/handshake_client.go and key_agreement.go
// (BSD-3-Clause, Copyright 2009 The Go Authors): the full handshake with ECDHE or RSA key
// exchange, the abbreviated one with a session ticket (RFC 5077), the extended master secret
// (RFC 7627) and renegotiation_info (RFC 5746).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.Extension;
import io.github.mahmoudimus.quic.tls.HandshakeMessage.ServerHello;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.net.ssl.X509KeyManager;

/**
 * The TLS 1.2 part of a {@link TlsClientConnection}: what follows a ServerHello that selects TLS
 * 1.2 from the profile's hello. The full handshake (Certificate, optional CertificateStatus,
 * ServerKeyExchange for ECDHE, optional CertificateRequest, ServerHelloDone; then the client's
 * flight) or, when the server takes the offered ticket, the abbreviated one.
 */
final class Tls12ClientHandshake {

    /** A TLS 1.2 session a client can resume with its ticket. */
    record Session(Tls12CipherSuite suite, byte[] masterSecret, byte[] ticket, boolean extendedMasterSecret,
            String serverName, String alpn, List<X509Certificate> peerCertificates, Instant received, long lifetimeSeconds) {

        boolean usable(Instant now, String sni) {
            return now.isBefore(received.plusSeconds(lifetimeSeconds)) && !now.isBefore(received)
                    && java.util.Objects.equals(serverName, sni);
        }
    }

    /** What the handshake negotiated. */
    record Result(Tls12CipherSuite suite, String alpn, List<X509Certificate> peerCertificates,
            List<X509Certificate> localCertificates, SignatureScheme peerSignatureScheme, boolean resumed, Session session) {}

    /** Extensions a TLS 1.2 ServerHello may carry, when the client offered them. */
    private static final Set<Integer> SERVER_HELLO_EXTENSIONS = Set.of(
            ExtensionType.SERVER_NAME, ExtensionType.MAX_FRAGMENT_LENGTH, ExtensionType.STATUS_REQUEST,
            11 /* ec_point_formats */, ExtensionType.ALPN, ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP,
            23 /* extended_master_secret */, 35 /* session_ticket */, 0xff01 /* renegotiation_info */,
            ProfileExtensions.RECORD_SIZE_LIMIT);

    private static final int HELLO_REQUEST = 0;
    private static final int SERVER_KEY_EXCHANGE = 12;
    private static final int SERVER_HELLO_DONE = 14;
    private static final int CLIENT_KEY_EXCHANGE = 16;
    private static final int CERTIFICATE_STATUS = 22;
    private static final int X25519 = 29;
    private static final int SECP256R1 = 23;
    private static final int SECP384R1 = 24;

    private final TlsClientConnection.Config config;
    private final TlsRecordLayer records;
    private final ByteArrayOutputStream handshakeBuffer;
    private final ClientHello hello;
    private final ServerHello serverHello;
    private final String serverName;
    private final String verifyHost;
    private final List<String> alpn;
    private final Session offered;
    /** Every handshake message so far, for Finished, the session hash and CertificateVerify. */
    private final ByteArrayOutputStream transcript = new ByteArrayOutputStream();
    private final Tls12CipherSuite suite;
    private final List<Extension> serverExtensions;
    private List<X509Certificate> peerCertificates = List.of();
    private List<X509Certificate> localCertificates = List.of();
    private SignatureScheme peerSignatureScheme;
    private byte[] masterSecret;
    private Tls12Prf.Keys keys;
    private byte[] newTicket;
    private long newTicketLifetime;

    /**
     * @param helloRaw the ClientHello as sent
     * @param serverHelloRaw the ServerHello as received
     * @param handshakeBuffer handshake bytes already read past the ServerHello, which this continues from
     * @param offered the session whose ticket the hello carries, or null
     */
    Tls12ClientHandshake(TlsClientConnection.Config config, TlsRecordLayer records, ByteArrayOutputStream handshakeBuffer,
            ClientHello hello, byte[] helloRaw, ServerHello serverHello, byte[] serverHelloRaw, String serverName,
            String verifyHost, List<String> alpn, Session offered) throws QuicException {
        this.config = config;
        this.records = records;
        this.handshakeBuffer = handshakeBuffer;
        this.hello = hello;
        this.serverHello = serverHello;
        this.serverName = serverName;
        this.verifyHost = verifyHost;
        this.alpn = alpn;
        this.offered = offered;
        transcript.writeBytes(helloRaw);
        transcript.writeBytes(serverHelloRaw);
        this.suite = checkServerHello();
        this.serverExtensions = serverHello.extensions();
    }

    private Tls12CipherSuite checkServerHello() throws QuicException {
        Tls12CipherSuite s = Tls12CipherSuite.forCode(serverHello.cipherSuite());
        boolean wasOffered = Arrays.stream(hello.cipherSuites()).anyMatch(c -> c == serverHello.cipherSuite());
        if (s == null || !wasOffered) throw TlsAlert.illegalParameter("ServerHello selected a cipher suite that was not offered");
        if (serverHello.compressionMethod() != 0) {
            throw TlsAlert.illegalParameter("ServerHello selected compression " + serverHello.compressionMethod());
        }
        Extensions.checkNoDuplicates(serverHello.extensions(), "ServerHello");
        Set<Integer> sent = new java.util.HashSet<>();
        for (Extension e : hello.extensions()) sent.add(e.type());
        for (Extension e : serverHello.extensions()) {
            if (!sent.contains(e.type())) {
                throw TlsAlert.error(TlsAlert.UNSUPPORTED_EXTENSION, "ServerHello has unsolicited " + ExtensionType.name(e.type()));
            }
            if (!SERVER_HELLO_EXTENSIONS.contains(e.type())) {
                throw TlsAlert.illegalParameter("a TLS 1.2 ServerHello may not carry " + ExtensionType.name(e.type()));
            }
        }
        byte[] ri = Extension.find(serverHello.extensions(), 0xff01);
        if (ri != null && !Arrays.equals(ri, new byte[] {0})) {
            throw TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, "renegotiation_info of an initial handshake is not empty");
        }
        byte[] ems = Extension.find(serverHello.extensions(), 23);
        if (ems != null) Extensions.expectEmpty(ems, 23);
        return s;
    }

    String negotiatedAlpn() throws QuicException {
        byte[] data = Extension.find(serverExtensions, ExtensionType.ALPN);
        if (data == null) return null;
        List<byte[]> selected = Extensions.decodeAlpn(data);
        if (selected.size() != 1) throw TlsAlert.decodeError("server selected " + selected.size() + " application protocols");
        String protocol = new String(selected.get(0), StandardCharsets.ISO_8859_1);
        if (!alpn.contains(protocol)) throw TlsAlert.illegalParameter("server selected an application protocol that was not offered");
        return protocol;
    }

    /** Runs the rest of the handshake. */
    Result run() throws IOException, QuicException {
        String protocol = negotiatedAlpn();
        boolean resumed = offered != null && hello.sessionId().length > 0
                && Arrays.equals(serverHello.sessionId(), hello.sessionId());
        if (resumed) {
            if (offered.suite() != suite) throw TlsAlert.illegalParameter("resumption with another cipher suite");
            boolean ems = Extension.find(serverExtensions, 23) != null;
            if (ems != offered.extendedMasterSecret()) {
                throw TlsAlert.error(TlsAlert.HANDSHAKE_FAILURE, "resumption changes the extended master secret");
            }
            masterSecret = offered.masterSecret();
            peerCertificates = offered.peerCertificates();
            keys = Tls12Prf.keys(suite, masterSecret, hello.random(), serverHello.random());
            readServerFinish();
            sendClientFinish();
        } else {
            fullHandshake();
        }
        Session session = null;
        byte[] ticket = newTicket != null ? newTicket : resumed ? offered.ticket() : null;
        if (ticket != null && ticket.length > 0) {
            long lifetime = newTicket != null ? (newTicketLifetime == 0 ? 7200 : Math.min(newTicketLifetime, 604800))
                    : offered.lifetimeSeconds();
            session = new Session(suite, masterSecret, ticket, Extension.find(serverExtensions, 23) != null, serverName,
                    protocol, peerCertificates, config.clock().instant(), lifetime);
        }
        return new Result(suite, protocol, peerCertificates, localCertificates, peerSignatureScheme, resumed, session);
    }

    private void fullHandshake() throws IOException, QuicException {
        Message m = readMessage();
        if (m.type() != HandshakeType.CERTIFICATE) throw unexpected(m, "Certificate");
        transcript.writeBytes(m.raw());
        peerCertificates = parseCertificates(m.body());
        CertificateChecks.verifyServerWithCauses(config.trustManager(), peerCertificates, authType(), verifyHost);
        PublicKey serverKey = peerCertificates.get(0).getPublicKey();
        checkKeyFitsSuite(serverKey);

        m = readMessage();
        if (m.type() == CERTIFICATE_STATUS) {
            if (Extension.find(serverExtensions, ExtensionType.STATUS_REQUEST) == null) {
                throw TlsAlert.unexpectedMessage("CertificateStatus without status_request");
            }
            transcript.writeBytes(m.raw());
            m = readMessage();
        }
        KeyExchange ecdhe = null;
        byte[] serverPoint = null;
        if (suite.keyExchange != Tls12CipherSuite.KeyExchange.RSA) {
            if (m.type() != SERVER_KEY_EXCHANGE) throw unexpected(m, "ServerKeyExchange");
            transcript.writeBytes(m.raw());
            Reader r = new Reader(m.body());
            byte[] params = parseServerKeyExchange(r, m.body(), serverKey);
            int curve = ((params[1] & 0xff) << 8) | (params[2] & 0xff);
            serverPoint = Arrays.copyOfRange(params, 4, params.length);
            ecdhe = KeyExchange.generate(NamedGroup.forCode(curve), config.random());
            m = readMessage();
        }
        byte[] request = null;
        if (m.type() == HandshakeType.CERTIFICATE_REQUEST) {
            transcript.writeBytes(m.raw());
            request = m.body();
            m = readMessage();
        }
        if (m.type() != SERVER_HELLO_DONE) throw unexpected(m, "ServerHelloDone");
        if (m.body().length != 0) throw TlsAlert.decodeError("ServerHelloDone is not empty");
        transcript.writeBytes(m.raw());

        if (request != null) sendClientCertificate(request);
        byte[] preMaster;
        byte[] clientKeyExchange;
        if (ecdhe != null) {
            preMaster = ecdhe.agree(serverPoint);
            Writer w = new Writer();
            w.vector8(ecdhe.publicKey());
            clientKeyExchange = w.toByteArray();
        } else {
            preMaster = new byte[48];
            config.random().nextBytes(preMaster);
            preMaster[0] = 3;
            preMaster[1] = 3;
            byte[] encrypted;
            try {
                Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsa.init(Cipher.ENCRYPT_MODE, serverKey, config.random());
                encrypted = rsa.doFinal(preMaster);
            } catch (GeneralSecurityException e) {
                throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot encrypt the premaster secret: " + e.getMessage());
            }
            Writer w = new Writer();
            w.vector16(encrypted);
            clientKeyExchange = w.toByteArray();
        }
        sendHandshake(CLIENT_KEY_EXCHANGE, clientKeyExchange);
        if (request != null && !localCertificates.isEmpty()) sendCertificateVerify(request);

        boolean ems = Extension.find(serverExtensions, 23) != null;
        masterSecret = ems
                ? Tls12Prf.extendedMasterSecret(suite, preMaster, sessionHashThroughClientKeyExchange)
                : Tls12Prf.masterSecret(suite, preMaster, hello.random(), serverHello.random());
        keys = Tls12Prf.keys(suite, masterSecret, hello.random(), serverHello.random());
        sendClientFinish();
        readServerFinish();
    }

    /** The session hash (RFC 7627 section 3), taken when ClientKeyExchange is added. */
    private byte[] sessionHashThroughClientKeyExchange;

    private void sendHandshake(int type, byte[] body) throws IOException {
        Writer w = new Writer();
        w.u8(type);
        w.vector24(body);
        byte[] message = w.toByteArray();
        transcript.writeBytes(message);
        if (type == CLIENT_KEY_EXCHANGE) sessionHashThroughClientKeyExchange = hash();
        records.write(TlsRecordLayer.HANDSHAKE, message);
    }

    private byte[] hash() {
        try {
            return MessageDigest.getInstance(suite.transcriptHash()).digest(transcript.toByteArray());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private void sendClientFinish() throws IOException {
        records.writeChangeCipherSpec();
        records.writeKeys12(suite, keys.clientMac(), keys.clientKey(), keys.clientIv(), config.random());
        byte[] verifyData = Tls12Prf.finished(suite, masterSecret, true, hash());
        sendHandshake(HandshakeType.FINISHED, verifyData);
        records.flush();
    }

    /** [NewSessionTicket], ChangeCipherSpec, then the server's Finished under its new keys. */
    private void readServerFinish() throws IOException, QuicException {
        records.flush();
        boolean ticketExpected = Extension.find(serverExtensions, 35) != null;
        Message m = readMessageOrChangeCipherSpec();
        if (m != null && m.type() == HandshakeType.NEW_SESSION_TICKET) {
            if (!ticketExpected) throw TlsAlert.unexpectedMessage("NewSessionTicket without session_ticket");
            transcript.writeBytes(m.raw());
            Reader r = new Reader(m.body());
            newTicketLifetime = r.u32("ticket_lifetime_hint");
            newTicket = r.vector16(0, "ticket");
            r.expectEnd("NewSessionTicket");
            m = readMessageOrChangeCipherSpec();
        }
        if (m != null) throw unexpected(m, "ChangeCipherSpec");
        if (handshakeBuffer.size() != 0) throw TlsAlert.unexpectedMessage("handshake data before ChangeCipherSpec");
        records.readKeys12(suite, keys.serverMac(), keys.serverKey(), keys.serverIv());
        byte[] expected = Tls12Prf.finished(suite, masterSecret, false, hash());
        m = readMessage();
        if (m.type() != HandshakeType.FINISHED) throw unexpected(m, "Finished");
        if (!MessageDigest.isEqual(expected, m.body())) throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "server Finished is incorrect");
        transcript.writeBytes(m.raw());
        if (handshakeBuffer.size() != 0) throw TlsAlert.unexpectedMessage("handshake data after Finished");
    }

    // --- certificates and the key exchange ---

    private String authType() {
        return switch (suite.keyExchange) {
            case ECDHE_ECDSA -> "ECDHE_ECDSA";
            case ECDHE_RSA -> "ECDHE_RSA";
            case RSA -> "RSA";
        };
    }

    private void checkKeyFitsSuite(PublicKey key) throws QuicException {
        boolean rsa = key instanceof RSAPublicKey;
        boolean ec = key instanceof ECPublicKey;
        boolean fits = switch (suite.keyExchange) {
            case ECDHE_ECDSA -> ec;
            case ECDHE_RSA, RSA -> rsa;
        };
        if (!fits) throw TlsAlert.error(TlsAlert.UNSUPPORTED_CERTIFICATE, "the certificate's key does not fit " + suite);
    }

    /** A TLS 1.2 Certificate: {@code ASN.1Cert certificate_list<0..2^24-1>} (RFC 5246 section 7.4.2). */
    private static List<X509Certificate> parseCertificates(byte[] body) throws QuicException {
        Reader r = new Reader(body);
        Reader list = r.sub24("certificate_list");
        r.expectEnd("Certificate");
        List<X509Certificate> chain = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            while (list.hasRemaining()) {
                byte[] der = list.vector24(1, "ASN.1Cert");
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            }
        } catch (CertificateException | ClassCastException e) {
            throw TlsAlert.error(TlsAlert.BAD_CERTIFICATE, "cannot parse certificate: " + e.getMessage());
        }
        if (chain.isEmpty()) throw TlsAlert.decodeError("server sent no certificate");
        return chain;
    }

    /**
     * An ECDHE ServerKeyExchange: a named curve the client offered and its point, signed with a
     * scheme the client offered, by the certificate's key, over both randoms and the parameters.
     *
     * @return the parameters: curve type, curve, point length and point
     */
    private byte[] parseServerKeyExchange(Reader r, byte[] body, PublicKey key) throws QuicException {
        if (r.u8("curve type") != 3) throw TlsAlert.illegalParameter("ServerKeyExchange is not for a named curve");
        int curve = r.u16("named curve");
        byte[] point = r.vector8(1, "ECDHE point");
        byte[] params = Arrays.copyOf(body, 4 + point.length);
        int schemeCode = r.u16("signature scheme");
        byte[] signature = r.vector16(1, "signature");
        r.expectEnd("ServerKeyExchange");
        byte[] offeredGroups = Extension.find(hello.extensions(), ExtensionType.SUPPORTED_GROUPS);
        boolean groupOffered = offeredGroups != null
                && Arrays.stream(Extensions.decodeU16List(offeredGroups, "supported_groups")).anyMatch(g -> g == curve);
        if (!groupOffered || (curve != X25519 && curve != SECP256R1 && curve != SECP384R1)) {
            throw TlsAlert.illegalParameter("ServerKeyExchange uses a curve that was not offered");
        }
        byte[] offeredSchemes = Extension.find(hello.extensions(), ExtensionType.SIGNATURE_ALGORITHMS);
        boolean schemeOffered = offeredSchemes != null
                && Arrays.stream(Extensions.decodeU16List(offeredSchemes, "signature_algorithms")).anyMatch(c -> c == schemeCode);
        SignatureScheme scheme = SignatureScheme.forCode(schemeCode);
        if (!schemeOffered || scheme == null) {
            throw TlsAlert.illegalParameter("ServerKeyExchange is signed with a scheme that was not offered");
        }
        boolean rsaScheme = scheme.jcaAlgorithm().contains("RSA");
        if (rsaScheme != (key instanceof RSAPublicKey)) {
            throw TlsAlert.illegalParameter("ServerKeyExchange scheme " + scheme + " does not fit the certificate key");
        }
        byte[] signed = Tls12Prf.concat(Tls12Prf.concat(hello.random(), serverHello.random()), params);
        if (!Signatures.verify(scheme, key, signed, signature)) {
            throw TlsAlert.error(TlsAlert.DECRYPT_ERROR, "ServerKeyExchange signature is invalid");
        }
        peerSignatureScheme = scheme;
        return params;
    }

    // --- client certificates ---

    /** A TLS 1.2 CertificateRequest's signature schemes (RFC 5246 section 7.4.4). */
    private static int[] requestedSchemes(byte[] request) throws QuicException {
        Reader r = new Reader(request);
        r.vector8(1, "certificate_types");
        int[] schemes = r.u16List16(1, "supported_signature_algorithms");
        r.vector16(0, "certificate_authorities");
        r.expectEnd("CertificateRequest");
        return schemes;
    }

    private CertifiedKey clientKey;
    private SignatureScheme clientScheme;

    private void sendClientCertificate(byte[] request) throws IOException, QuicException {
        X509KeyManager km = config.keyManager();
        if (km != null) {
            for (int code : requestedSchemes(request)) {
                SignatureScheme candidate = SignatureScheme.forCode(code);
                if (candidate == null) continue;
                String keyType = candidate.jcaAlgorithm().contains("RSA") ? "RSA" : candidate == SignatureScheme.ED25519 ? "EdDSA" : "EC";
                String alias = km.chooseClientAlias(new String[] {keyType}, null, null);
                if (alias == null) continue;
                CertifiedKey k = CertifiedKey.fromKeyManager(km, alias);
                if (k != null && candidate.compatibleWith(k.privateKey())) {
                    clientKey = k;
                    clientScheme = candidate;
                    break;
                }
            }
        }
        Writer w = new Writer();
        int list = w.open(3);
        if (clientKey != null) {
            for (X509Certificate cert : clientKey.chain()) {
                try {
                    w.vector24(cert.getEncoded());
                } catch (java.security.cert.CertificateEncodingException e) {
                    throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot encode client certificate");
                }
            }
            localCertificates = clientKey.chain();
        }
        w.close(list);
        sendHandshake(HandshakeType.CERTIFICATE, w.toByteArray());
    }

    /** CertificateVerify over every handshake message so far (RFC 5246 section 7.4.8). */
    private void sendCertificateVerify(byte[] request) throws IOException, QuicException {
        byte[] signature;
        try {
            signature = Signatures.sign(clientScheme, clientKey.privateKey(), transcript.toByteArray(), config.random());
        } catch (GeneralSecurityException e) {
            throw TlsAlert.error(TlsAlert.INTERNAL_ERROR, "cannot sign CertificateVerify: " + e.getMessage());
        }
        Writer w = new Writer();
        w.u16(clientScheme.code());
        w.vector16(signature);
        sendHandshake(HandshakeType.CERTIFICATE_VERIFY, w.toByteArray());
    }

    // --- handshake messages from records ---

    record Message(int type, byte[] body, byte[] raw) {}

    private static QuicException unexpected(Message m, String expected) {
        return TlsAlert.unexpectedMessage("got " + HandshakeType.name(m.type()) + ", expected " + expected);
    }

    private Message readMessage() throws IOException, QuicException {
        Message m = readMessageOrChangeCipherSpec();
        if (m == null) throw TlsAlert.unexpectedMessage("an unexpected change_cipher_spec");
        return m;
    }

    /** The next handshake message, or null for a ChangeCipherSpec. HelloRequest is ignored. */
    private Message readMessageOrChangeCipherSpec() throws IOException, QuicException {
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
                    if ((raw[0] & 0xff) == HELLO_REQUEST) continue; // RFC 5246 7.4.1.1: ignored during a handshake
                    return new Message(raw[0] & 0xff, Arrays.copyOfRange(raw, 4, raw.length), raw);
                }
            }
            TlsRecordLayer.Record record = records.read();
            if (record == null) throw new EOFException("the server closed the connection during the TLS handshake");
            switch (record.type()) {
                case TlsRecordLayer.HANDSHAKE -> handshakeBuffer.write(record.fragment());
                case TlsRecordLayer.CHANGE_CIPHER_SPEC -> {
                    if (record.fragment().length != 1 || record.fragment()[0] != 1) {
                        throw TlsAlert.unexpectedMessage("a change_cipher_spec that is not the single byte 1");
                    }
                    return null;
                }
                case TlsRecordLayer.ALERT -> throw TlsClientConnection.alertFromServer(record.fragment());
                default -> throw TlsAlert.unexpectedMessage("a record of type " + record.type() + " during the handshake");
            }
        }
    }
}
