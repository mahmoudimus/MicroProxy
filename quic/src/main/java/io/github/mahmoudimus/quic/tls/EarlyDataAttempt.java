package io.github.mahmoudimus.quic.tls;

import java.time.Duration;
import java.time.Instant;

/**
 * A resuming client's offer of 0-RTT data, as an {@link EarlyDataPolicy} sees it.
 *
 * @param serverName the server name of the ClientHello (and of the ticket), or null
 * @param alpn the application protocol selected for this connection, which the ticket's matches
 * @param ticketId a random identifier of the ticket, unique per ticket the server issued
 * @param issued when the server issued the ticket
 * @param clientTicketAge the ticket's age the client reports, de-obfuscated
 * @param serverTicketAge the ticket's age by the server's clock
 */
public record EarlyDataAttempt(String serverName, String alpn, byte[] ticketId, Instant issued,
        Duration clientTicketAge, Duration serverTicketAge) {

    /**
     * An attempt.
     *
     * @param serverName the server name, or null
     * @param alpn the selected application protocol
     * @param ticketId the ticket's identifier, copied
     * @param issued when the ticket was issued
     * @param clientTicketAge the client's ticket age
     * @param serverTicketAge the server's ticket age
     */
    public EarlyDataAttempt {
        ticketId = ticketId.clone();
    }

    /**
     * The ticket's identifier.
     *
     * @return a copy
     */
    @Override
    public byte[] ticketId() {
        return ticketId.clone();
    }

    /**
     * How far the two ticket ages differ: a replay of an old first flight shows up as a large
     * difference, since the client's reported age is frozen in it.
     *
     * @return the absolute difference
     */
    public Duration ageSkew() {
        return clientTicketAge.minus(serverTicketAge).abs();
    }
}
