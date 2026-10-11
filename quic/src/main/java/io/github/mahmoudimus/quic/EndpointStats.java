package io.github.mahmoudimus.quic;

/**
 * What a QUIC endpoint answered itself, without a connection: from {@link
 * QuicServer#endpointStats()} and {@link QuicClient#endpointStats()}.
 *
 * @param versionNegotiationsSent Version Negotiation packets sent, to clients that offered no
 *     version the endpoint supports
 * @param retriesSent Retry packets sent, to validate clients' addresses
 * @param statelessResetsSent stateless resets sent, for packets of connections the endpoint does
 *     not know
 * @param connectionsRefused connections refused before they started (server busy, an invalid token
 *     or connection ID)
 */
public record EndpointStats(long versionNegotiationsSent, long retriesSent, long statelessResetsSent,
        long connectionsRefused) {}
