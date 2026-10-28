// Ported from rustls src/msgs/persist.rs (Tls13ClientSessionValue and ClientSessionCommon: the
// ticket, the resumption secret, the suite, age_add, lifetime, receipt time, max_early_data_size,
// the ALPN, the server's certificates and the QUIC transport parameters of the session) (Apache-2.0).
package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.CipherSuite;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * A session ticket a client received in a NewSessionTicket message (RFC 8446 section 4.6.1),
 * with what it needs to resume the session: the pre-shared key derived from the resumption master
 * secret, the cipher suite, the ticket age obfuscation, and for 0-RTT the ALPN protocol and the
 * server's QUIC transport parameters, which a client must remember and use for its early data
 * (RFC 9000 section 7.4.1).
 *
 * <p>A ticket is meant to be used once (RFC 8446 appendix C.4): a {@link ClientSessionStore}
 * hands each out once. Tickets hold secrets and live only in memory. Immutable.
 */
public final class SessionTicket {

    /** {@code max_early_data_size} in a ticket that allows QUIC 0-RTT (RFC 9001 section 4.6.1). */
    public static final long QUIC_MAX_EARLY_DATA = 0xffffffffL;

    final String serverName;
    final CipherSuite suite;
    final byte[] ticket;
    final byte[] psk;
    final long ageAdd;
    final long lifetimeSeconds;
    final Instant received;
    final long maxEarlyDataSize;
    final String alpn;
    final byte[] transportParameters;
    final List<X509Certificate> peerCertificates;
    final TlsAcceptancePolicy.Evidence tcpEvidence;

    SessionTicket(String serverName, CipherSuite suite, byte[] ticket, byte[] psk, long ageAdd,
            long lifetimeSeconds, Instant received, long maxEarlyDataSize, String alpn, byte[] transportParameters,
            List<X509Certificate> peerCertificates) {
        this(serverName, suite, ticket, psk, ageAdd, lifetimeSeconds, received, maxEarlyDataSize, alpn,
                transportParameters, peerCertificates, null);
    }

    SessionTicket(String serverName, CipherSuite suite, byte[] ticket, byte[] psk, long ageAdd,
            long lifetimeSeconds, Instant received, long maxEarlyDataSize, String alpn, byte[] transportParameters,
            List<X509Certificate> peerCertificates, TlsAcceptancePolicy.Evidence tcpEvidence) {
        this.tcpEvidence = tcpEvidence;
        this.serverName = serverName;
        this.suite = Objects.requireNonNull(suite);
        this.ticket = ticket.clone();
        this.psk = psk.clone();
        this.ageAdd = ageAdd;
        this.lifetimeSeconds = lifetimeSeconds;
        this.received = Objects.requireNonNull(received);
        this.maxEarlyDataSize = maxEarlyDataSize;
        this.alpn = alpn;
        this.transportParameters = transportParameters != null ? transportParameters.clone() : null;
        this.peerCertificates = List.copyOf(peerCertificates);
    }

    /**
     * The server name the ticket is for, as the client sent it in SNI.
     *
     * @return the name, or null if the client sent none
     */
    public String serverName() {
        return serverName;
    }

    /**
     * The cipher suite of the session; a resumption must use one with the same hash, and 0-RTT this
     * very suite.
     *
     * @return the suite
     */
    public CipherSuite cipherSuite() {
        return suite;
    }

    /**
     * The application protocol of the session, which 0-RTT data is sent for.
     *
     * @return the protocol
     */
    public String alpn() {
        return alpn;
    }

    /**
     * Whether the ticket allows 0-RTT data.
     *
     * @return true if the server sent {@code early_data} with QUIC's {@code max_early_data_size}
     */
    public boolean allowsEarlyData() {
        return maxEarlyDataSize == QUIC_MAX_EARLY_DATA;
    }

    /**
     * The server's encoded QUIC transport parameters from the session the ticket came from. A client
     * sending 0-RTT data must keep within their limits.
     *
     * @return a copy, or null if unknown
     */
    public byte[] transportParameters() {
        return transportParameters != null ? transportParameters.clone() : null;
    }

    /**
     * The server's certificate chain from the full handshake the session started with.
     *
     * @return the chain, end-entity first
     */
    public List<X509Certificate> peerCertificates() {
        return peerCertificates;
    }

    /**
     * When the client received the ticket.
     *
     * @return the time
     */
    public Instant received() {
        return received;
    }

    /**
     * How long the server said the ticket may be used.
     *
     * @return the lifetime, at most 7 days
     */
    public Duration lifetime() {
        return Duration.ofSeconds(lifetimeSeconds);
    }

    /**
     * Whether the ticket has outlived its lifetime.
     *
     * @param now the current time
     * @return true once it must no longer be offered
     */
    public boolean isExpired(Instant now) {
        return now.isAfter(received.plusSeconds(lifetimeSeconds)) || now.isBefore(received);
    }

    /** {@code obfuscated_ticket_age}: the ticket's age in milliseconds plus {@code ticket_age_add}, mod 2^32. */
    long obfuscatedAge(Instant now) {
        long ageMillis = Math.max(0, Duration.between(received, now).toMillis());
        return (ageMillis + ageAdd) & 0xffffffffL;
    }

    @Override
    public String toString() {
        return "SessionTicket[" + serverName + " " + suite + " " + alpn + " received " + received
                + (allowsEarlyData() ? " 0-RTT" : "") + "]";
    }
}
