// Ported from quinn quinn-proto/src/crypto.rs (the Session trait) and src/crypto/rustls.rs (its
// rustls implementation), and from rustls src/quic.rs (the QUIC connection: handshake bytes per
// encryption level with no record layer, the secrets exported per level, the key update) and
// src/conn.rs (message reassembly and the alignment of messages with key changes) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.EncryptionLevel;
import io.github.mahmoudimus.quic.QuicException;
import io.github.mahmoudimus.quic.Secrets;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * A TLS 1.3 handshake for QUIC (RFC 9001), as a sans-I/O state machine modelled on quinn's {@code
 * crypto::Session}. There is no record layer: handshake messages travel in CRYPTO frames at an
 * {@link EncryptionLevel}, and the traffic secrets for each level are handed to the connection as
 * {@link Secrets}.
 *
 * <p>The connection layer drives a session like this:
 *
 * <ol>
 *   <li>Create it with {@link #client(TlsConfig, byte[])} or {@link #server(TlsConfig, byte[])},
 *       passing the encoded local transport parameters. A client has its ClientHello ready at
 *       once.
 *   <li>Feed each level's in-order CRYPTO stream bytes to {@link #readHandshake}. Messages may
 *       be split or coalesced arbitrarily.
 *   <li>After each call (and after creating a client), install any keys {@link #nextSecrets()}
 *       returns, then send what {@link #writeHandshake(EncryptionLevel)} returns for each level.
 *   <li>When the handshake is complete, use {@link #nextOneRttSecrets()} for key updates.
 * </ol>
 *
 * <p>Secrets arrive in this order. A client gets the {@link EncryptionLevel#HANDSHAKE} secrets
 * after the ServerHello, and the {@link EncryptionLevel#ONE_RTT} secrets once it has checked the
 * server's Finished and queued its own; the handshake is then complete for it. A server gets both
 * as soon as it has processed the ClientHello and queued its whole flight, ending with its
 * Finished: it may send 1-RTT (0.5-RTT) data at once but, as RFC 9001 section 5.7 requires, must
 * not process 1-RTT packets from the client until {@link #isHandshakeComplete()}, which happens
 * when the client's Finished has been verified. Confirming the handshake (HANDSHAKE_DONE) and
 * discarding keys are left to the connection layer.
 *
 * <p>Errors are {@link QuicException}s: TLS alerts become {@code CRYPTO_ERROR} codes ({@code
 * 0x0100 + alert}, see {@link TlsAlert}), a message longer than the configured limit becomes
 * {@code CRYPTO_BUFFER_EXCEEDED}, and a non-empty {@code legacy_session_id} sent to a server
 * becomes {@code PROTOCOL_VIOLATION}. After an error the session is dead and every further
 * {@code readHandshake} throws the same error.
 *
 * <p>A session is not thread-safe and takes no locks: a handshake is a single-threaded state
 * machine, driven by one connection at a time. Its certificate and ALPN selectors run on the
 * thread that calls {@link #readHandshake}.
 *
 * <p><b>Resumption and 0-RTT.</b> A server with a {@link TlsConfig.Builder#sessionTickets ticketer}
 * queues NewSessionTicket messages at {@link EncryptionLevel#ONE_RTT} when its handshake completes,
 * and resumes the sessions they seal. A client hands each ticket it receives out through {@link
 * #pollNewTicket()} and resumes with one passed to {@link #client(TlsConfig, String, byte[],
 * SessionTicket)}. When a client offers early data, its first secrets are the {@link
 * EncryptionLevel#ZERO_RTT} ones, available at once: {@code Secrets(ZERO_RTT, suite,
 * client_early_traffic_secret, empty)}. A server that accepts the early data hands out the same
 * secrets first, before the Handshake ones. Whether it was accepted is known to the client after
 * EncryptedExtensions ({@link #isEarlyDataAccepted()}).
 */
public final class TlsSession {

    private final boolean client;
    final TlsConfig config;
    final byte[] localTransportParameters;
    private Handshake handshake;

    private final Map<EncryptionLevel, byte[]> outgoing = new EnumMap<>(EncryptionLevel.class);
    private final ArrayDeque<Secrets> secrets = new ArrayDeque<>();

    private EncryptionLevel readLevel = EncryptionLevel.INITIAL;
    private byte[] incoming = new byte[1024];
    private int incomingLength;
    private boolean alignmentRequired;
    private QuicException failure;

    private boolean complete;
    private CipherSuite suite;
    private NamedGroup group;
    private String alpn;
    private String serverName;
    private List<X509Certificate> peerCertificates = List.of();
    private SignatureScheme peerSignatureScheme;
    private byte[] peerTransportParameters;
    private boolean helloRetried;
    private KeySchedule applicationKeys;
    private byte[] clientApplicationSecret;
    private byte[] serverApplicationSecret;
    private byte[] exporterMasterSecret;
    private byte[] clientRandom;
    private boolean resumed;
    private boolean earlyDataAccepted;
    private final ArrayDeque<SessionTicket> newTickets = new ArrayDeque<>();
    /** A server's check of the transport parameters a ticket remembers, before accepting 0-RTT. */
    Predicate<byte[]> earlyDataParameters;

    private TlsSession(boolean client, TlsConfig config, byte[] transportParameters) {
        this.client = client;
        this.config = Objects.requireNonNull(config, "config");
        this.localTransportParameters = Objects.requireNonNull(transportParameters, "transportParameters").clone();
        if (localTransportParameters.length > 0xffff) {
            throw new IllegalArgumentException("transport parameters longer than 65535 bytes");
        }
        if (config.alpnProtocols.isEmpty() && (client || config.alpnSelector == null)) {
            throw new IllegalArgumentException("QUIC requires ALPN: configure alpnProtocols"
                    + (client ? "" : " or an alpnSelector"));
        }
    }

    /**
     * Starts a client handshake to the configuration's {@link TlsConfig.Builder#serverName server
     * name}. The ClientHello is queued at {@link EncryptionLevel#INITIAL} before this returns.
     *
     * @param config the configuration, with ALPN protocols
     * @param transportParameters the encoded local QUIC transport parameters
     * @return the session
     * @throws IllegalArgumentException if the configuration has no ALPN protocols, or no server
     *     name while it verifies host names
     */
    public static TlsSession client(TlsConfig config, byte[] transportParameters) {
        return client(config, config.serverName, transportParameters);
    }

    /**
     * Starts a client handshake to a server name. The ClientHello is queued at {@link
     * EncryptionLevel#INITIAL} before this returns.
     *
     * @param config the configuration, with ALPN protocols
     * @param serverName the host name (sent as SNI) or IP literal the certificate must match; may
     *     be null only if the configuration does not verify host names
     * @param transportParameters the encoded local QUIC transport parameters
     * @return the session
     * @throws IllegalArgumentException if the configuration has no ALPN protocols, or no server
     *     name while it verifies host names
     */
    public static TlsSession client(TlsConfig config, String serverName, byte[] transportParameters) {
        return client(config, serverName, transportParameters, null);
    }

    /**
     * Starts a client handshake that offers to resume a session. The ticket is used only if it
     * has not expired, is for the same server name and has a cipher suite the configuration
     * offers; with {@link TlsConfig.Builder#earlyData(boolean) earlyData} and a ticket that allows
     * it, the client also offers 0-RTT, and its {@link EncryptionLevel#ZERO_RTT} secrets are ready
     * at once.
     *
     * @param config the configuration, with ALPN protocols
     * @param serverName the host name (sent as SNI) or IP literal the certificate must match; may
     *     be null only if the configuration does not verify host names
     * @param transportParameters the encoded local QUIC transport parameters
     * @param ticket a ticket from an earlier session with this server, used once; or null
     * @return the session
     * @throws IllegalArgumentException if the configuration has no ALPN protocols, or no server
     *     name while it verifies host names
     */
    public static TlsSession client(TlsConfig config, String serverName, byte[] transportParameters,
            SessionTicket ticket) {
        TlsSession session = new TlsSession(true, config, transportParameters);
        if (serverName == null && config.verifyHostname && !config.trustAllCertificates) {
            throw new IllegalArgumentException("a server name is needed to verify the server's certificate");
        }
        session.serverName = serverName;
        session.handshake = new ClientHandshake(session, serverName, ticket);
        return session;
    }

    /**
     * Starts a server handshake, which waits for a ClientHello.
     *
     * @param config the configuration, with a certificate or certificate selector, and ALPN
     *     protocols or an ALPN selector
     * @param transportParameters the encoded local QUIC transport parameters
     * @return the session
     * @throws IllegalArgumentException if the configuration has no certificate or no ALPN
     */
    public static TlsSession server(TlsConfig config, byte[] transportParameters) {
        return server(config, transportParameters, null);
    }

    /**
     * Starts a server handshake with a check on the QUIC transport parameters a ticket remembers.
     * Before accepting 0-RTT, the handshake passes the encoded parameters the server had when it
     * issued the ticket to {@code earlyDataParameters}; returning false rejects the early data, as
     * RFC 9000 section 7.4.1 requires when the current limits are smaller.
     *
     * @param config the configuration
     * @param transportParameters the encoded local QUIC transport parameters, also sealed in tickets
     * @param earlyDataParameters accepts the remembered parameters, or null to accept any
     * @return the session
     * @throws IllegalArgumentException if the configuration has no certificate or no ALPN
     */
    public static TlsSession server(TlsConfig config, byte[] transportParameters,
            Predicate<byte[]> earlyDataParameters) {
        TlsSession session = new TlsSession(false, config, transportParameters);
        if (config.certificateSelector == null) {
            throw new IllegalArgumentException("a server needs a certificate or a certificate selector");
        }
        session.earlyDataParameters = earlyDataParameters;
        session.handshake = new ServerHandshake(session);
        return session;
    }

    /**
     * Whether this is the client side.
     *
     * @return true for a client session
     */
    public boolean isClient() {
        return client;
    }

    /**
     * Feeds CRYPTO stream bytes received at an encryption level, in stream order. All of {@code
     * data} is consumed. Messages may be split across calls or coalesced in one; each complete
     * message is processed at once, which may queue output and secrets.
     *
     * @param level the encryption level the bytes arrived at
     * @param data the bytes; its position is advanced to its limit
     * @throws QuicException if the bytes are at the wrong level, malformed, or fail the handshake
     */
    public void readHandshake(EncryptionLevel level, ByteBuffer data) throws QuicException {
        Objects.requireNonNull(level, "level");
        Objects.requireNonNull(data, "data");
        if (failure != null) throw failure;
        try {
            while (data.hasRemaining()) {
                if (level != readLevel) {
                    throw TlsAlert.unexpectedMessage("handshake data at " + level + " while reading at " + readLevel);
                }
                int want = incomingLength < 4 ? 4 - incomingLength : 4 + bodyLength() - incomingLength;
                int n = Math.min(want, data.remaining());
                if (incomingLength + n > incoming.length) {
                    incoming = Arrays.copyOf(incoming, Math.max(incoming.length * 2, incomingLength + n));
                }
                data.get(incoming, incomingLength, n);
                incomingLength += n;
                if (incomingLength < 4) continue;
                int length = bodyLength();
                if (length > config.maxHandshakeMessageSize) {
                    throw new QuicException(QuicException.CRYPTO_BUFFER_EXCEEDED, "handshake message of "
                            + length + " bytes exceeds the limit of " + config.maxHandshakeMessageSize);
                }
                if (incomingLength == 4 + length) {
                    byte[] raw = Arrays.copyOf(incoming, incomingLength);
                    incomingLength = 0;
                    if (incoming.length > 4096) incoming = new byte[1024];
                    dispatch(raw);
                    boolean keyChange = readLevel != level;
                    if ((alignmentRequired || keyChange) && data.hasRemaining()) {
                        throw TlsAlert.unexpectedMessage("handshake data follows a message that must end its flight");
                    }
                    alignmentRequired = false;
                }
            }
        } catch (QuicException e) {
            failure = e;
            throw e;
        } catch (RuntimeException e) {
            QuicException internal = TlsAlert.error(TlsAlert.INTERNAL_ERROR, String.valueOf(e));
            internal.initCause(e);
            failure = internal;
            throw internal;
        }
    }

    private int bodyLength() {
        return ((incoming[1] & 0xff) << 16) | ((incoming[2] & 0xff) << 8) | (incoming[3] & 0xff);
    }

    private void dispatch(byte[] raw) throws QuicException {
        int type = raw[0] & 0xff;
        HandshakeMessage message = HandshakeMessage.decode(type, Arrays.copyOfRange(raw, 4, raw.length));
        handshake.handle(message, raw);
    }

    /**
     * Takes the handshake bytes queued for sending at a level, in order.
     *
     * @param level the encryption level
     * @return the bytes for CRYPTO frames at that level; empty if there are none
     */
    public byte[] writeHandshake(EncryptionLevel level) {
        byte[] out = outgoing.remove(Objects.requireNonNull(level, "level"));
        return out != null ? out : new byte[0];
    }

    /**
     * Whether handshake bytes are queued at a level.
     *
     * @param level the encryption level
     * @return true if {@link #writeHandshake(EncryptionLevel)} would return bytes
     */
    public boolean hasHandshakeData(EncryptionLevel level) {
        return outgoing.containsKey(level);
    }

    /**
     * Takes the next newly available secrets, in the order they became available.
     *
     * @return the secrets for one level, or null if there are no new ones
     */
    public Secrets nextSecrets() {
        return secrets.poll();
    }

    /**
     * Derives the next generation of 1-RTT secrets for a key update (RFC 9001 section 6): {@code
     * HKDF-Expand-Label(secret, "quic ku", "", Hash.length)} on both traffic secrets, with the
     * suite's hash. Each call moves one generation on.
     *
     * @return the next 1-RTT secrets
     * @throws IllegalStateException if the 1-RTT secrets are not available yet
     */
    public Secrets nextOneRttSecrets() {
        if (clientApplicationSecret == null) throw new IllegalStateException("no 1-RTT secrets yet");
        clientApplicationSecret = applicationKeys.nextApplicationSecret(clientApplicationSecret);
        serverApplicationSecret = applicationKeys.nextApplicationSecret(serverApplicationSecret);
        return new Secrets(EncryptionLevel.ONE_RTT, suite, clientApplicationSecret.clone(),
                serverApplicationSecret.clone());
    }

    /**
     * Whether the handshake is still in progress: true until it completes, and also after it
     * has failed.
     *
     * @return true until {@link #isHandshakeComplete()}
     */
    public boolean isHandshaking() {
        return !complete;
    }

    /**
     * Whether the handshake is complete (RFC 9001 section 4.1.1): for a client, once it has
     * verified the server's Finished and queued its own; for a server, once it has verified the
     * client's Finished.
     *
     * @return true when complete
     */
    public boolean isHandshakeComplete() {
        return complete;
    }

    /**
     * The peer's encoded QUIC transport parameters, which the connection layer decodes.
     *
     * @return a copy of the parameters, or null until they have been received (a server has them
     *     after the ClientHello, a client after EncryptedExtensions)
     */
    public byte[] peerTransportParameters() {
        return peerTransportParameters != null ? peerTransportParameters.clone() : null;
    }

    /**
     * The application protocol agreed with ALPN.
     *
     * @return the protocol, or null until it has been agreed
     */
    public String negotiatedAlpn() {
        return alpn;
    }

    /**
     * The server name: for a client, the one it connects to; for a server, the client's SNI.
     *
     * @return the name, or null if there is none (yet)
     */
    public String serverName() {
        return serverName;
    }

    /**
     * The peer's certificate chain, end-entity first: the server's for a client, and the
     * client's for a server that asked for one.
     *
     * @return the chain, empty until received or if the peer sent none
     */
    public List<X509Certificate> peerCertificates() {
        return peerCertificates;
    }

    /**
     * The signature scheme of the peer's CertificateVerify.
     *
     * @return the scheme, or null until it has been verified or if the peer signed nothing
     */
    public SignatureScheme peerSignatureScheme() {
        return peerSignatureScheme;
    }

    /**
     * The negotiated cipher suite.
     *
     * @return the suite, or null until it is known
     */
    public CipherSuite cipherSuite() {
        return suite;
    }

    /**
     * The key exchange group used.
     *
     * @return the group, or null until it is known
     */
    public NamedGroup negotiatedGroup() {
        return group;
    }

    /**
     * Whether the server sent a HelloRetryRequest, asking for a key share in another group.
     *
     * @return true after a retry
     */
    public boolean usedHelloRetryRequest() {
        return helloRetried;
    }

    /**
     * Whether the handshake resumed a session with a PSK from a ticket. A client knows after the
     * ServerHello; a server after the ClientHello.
     *
     * @return true if resumed
     */
    public boolean isResumed() {
        return resumed;
    }

    /**
     * Whether the client offered 0-RTT data in its first ClientHello.
     *
     * @return true if offered
     */
    public boolean isEarlyDataOffered() {
        return handshake instanceof ClientHandshake c ? c.earlyDataOffered() : earlyDataAccepted;
    }

    /**
     * Whether the server accepted 0-RTT data. A client knows after EncryptedExtensions; until then,
     * and if the early data was rejected, this is false.
     *
     * @return true if accepted
     */
    public boolean isEarlyDataAccepted() {
        return earlyDataAccepted;
    }

    /**
     * Client: takes the next ticket received in a NewSessionTicket message, to keep for a later
     * connection.
     *
     * @return the ticket, or null if there is none
     */
    public SessionTicket pollNewTicket() {
        return newTickets.poll();
    }

    /**
     * The ClientHello's random value, which names the secrets of this handshake in the {@code
     * SSLKEYLOGFILE} format that packet analyzers read.
     *
     * @return a copy of the 32 bytes, or null until known (a server learns it from the ClientHello)
     */
    public byte[] clientRandom() {
        return clientRandom != null ? clientRandom.clone() : null;
    }

    /**
     * Keying material from the TLS exporter (RFC 8446 section 7.5).
     *
     * @param label the exporter label, ASCII
     * @param context the context; null and empty are the same in TLS 1.3
     * @param length the number of bytes, at most 255 times the suite's hash length
     * @return the keying material
     * @throws IllegalStateException if the 1-RTT secrets are not available yet
     * @throws IllegalArgumentException if the label or length is too long
     */
    public byte[] exportKeyingMaterial(String label, byte[] context, int length) {
        if (exporterMasterSecret == null) throw new IllegalStateException("handshake not far enough");
        return KeySchedule.export(suite, exporterMasterSecret, label, context != null ? context : new byte[0], length);
    }

    // --- for the handshakes ---

    void send(EncryptionLevel level, byte[] message) {
        byte[] queued = outgoing.get(level);
        if (queued == null) {
            outgoing.put(level, message);
        } else {
            byte[] joined = Arrays.copyOf(queued, queued.length + message.length);
            System.arraycopy(message, 0, joined, queued.length, message.length);
            outgoing.put(level, joined);
        }
    }

    void earlySecrets(CipherSuite earlySuite, byte[] clientEarlySecret) {
        secrets.add(new Secrets(EncryptionLevel.ZERO_RTT, earlySuite, clientEarlySecret.clone(), new byte[0]));
    }

    void resumed() {
        this.resumed = true;
    }

    void earlyDataAccepted() {
        this.earlyDataAccepted = true;
    }

    void newTicket(SessionTicket ticket) {
        newTickets.add(ticket);
    }

    void handshakeSecrets(byte[] clientSecret, byte[] serverSecret) {
        secrets.add(new Secrets(EncryptionLevel.HANDSHAKE, suite, clientSecret.clone(), serverSecret.clone()));
    }

    void applicationSecrets(KeySchedule keys, byte[] clientSecret, byte[] serverSecret, byte[] exporterMaster) {
        this.applicationKeys = keys;
        this.clientApplicationSecret = clientSecret.clone();
        this.serverApplicationSecret = serverSecret.clone();
        this.exporterMasterSecret = exporterMaster.clone();
        secrets.add(new Secrets(EncryptionLevel.ONE_RTT, suite, clientSecret.clone(), serverSecret.clone()));
    }

    void clientRandom(byte[] random) {
        this.clientRandom = random.clone();
    }

    void readLevel(EncryptionLevel level) {
        this.readLevel = level;
    }

    /** No more bytes may follow the message being processed in this flight. */
    void requireAligned() {
        this.alignmentRequired = true;
    }

    void completed() {
        this.complete = true;
    }

    void negotiated(CipherSuite suite, NamedGroup group) {
        this.suite = suite;
        this.group = group;
    }

    void alpn(String alpn) {
        this.alpn = alpn;
    }

    void serverName(String serverName) {
        this.serverName = serverName;
    }

    void peerTransportParameters(byte[] parameters) {
        this.peerTransportParameters = parameters.clone();
    }

    void peerCertificates(List<X509Certificate> chain) {
        this.peerCertificates = List.copyOf(chain);
    }

    void peerSignatureScheme(SignatureScheme scheme) {
        this.peerSignatureScheme = scheme;
    }

    void helloRetried() {
        this.helloRetried = true;
    }
}
