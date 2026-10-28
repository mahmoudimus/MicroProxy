package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.EndpointConfig;
import io.github.mahmoudimus.quic.connection.InitialPacketShape;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.params.TransportParameterProfile;
import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.CertificateDecompressor;
import io.github.mahmoudimus.quic.tls.ClientHelloProfile;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.time.Duration;
import java.util.Map;

/**
 * What a browser's QUIC connections look like, as settings for a client: its ClientHello, its
 * transport parameters and the transport limits behind them, its connection ID lengths and the
 * shape of its Initial packets. Apply it to the builders of a client's configuration; the
 * connection then advertises the browser's limits and holds itself to them.
 *
 * <p>A client with an empty source connection ID ({@link #localCidLength()} 0) needs a UDP socket
 * of its own per connection, as a browser has: its datagrams are told apart by address only.
 */
public final class QuicClientProfile {

    private final String name;
    private final ClientHelloProfile hello;
    private final TransportParameterProfile parameters;
    private final InitialPacketShape initials;
    private final int initialDcidLength;
    private final int localCidLength;
    private final Duration idleTimeout;
    private final long bidiStreams;
    private final long uniStreams;
    private final long receiveWindow;
    private final long streamReceiveWindow;
    private final int maxUdpPayloadSize;
    private final int initialMtu;
    private final int initialMtuIpv6;
    private final int datagramReceiveBufferSize;
    private final Duration maxAckDelay;
    private final int activeConnectionIdLimit;

    private QuicClientProfile(String name, ClientHelloProfile hello, TransportParameterProfile parameters,
            InitialPacketShape initials, int initialDcidLength, int localCidLength, Duration idleTimeout, long bidiStreams,
            long uniStreams, long receiveWindow, long streamReceiveWindow, int maxUdpPayloadSize, int initialMtu,
            int datagramReceiveBufferSize) {
        this(name, hello, parameters, initials, initialDcidLength, localCidLength, idleTimeout, bidiStreams, uniStreams,
                receiveWindow, streamReceiveWindow, maxUdpPayloadSize, initialMtu, initialMtu, datagramReceiveBufferSize,
                null, 0);
    }

    private QuicClientProfile(String name, ClientHelloProfile hello, TransportParameterProfile parameters,
            InitialPacketShape initials, int initialDcidLength, int localCidLength, Duration idleTimeout, long bidiStreams,
            long uniStreams, long receiveWindow, long streamReceiveWindow, int maxUdpPayloadSize, int initialMtu,
            int initialMtuIpv6, int datagramReceiveBufferSize, Duration maxAckDelay, int activeConnectionIdLimit) {
        this.initialMtuIpv6 = initialMtuIpv6;
        this.maxAckDelay = maxAckDelay;
        this.activeConnectionIdLimit = activeConnectionIdLimit;
        this.name = name;
        this.hello = hello;
        this.parameters = parameters;
        this.initials = initials;
        this.initialDcidLength = initialDcidLength;
        this.localCidLength = localCidLength;
        this.idleTimeout = idleTimeout;
        this.bidiStreams = bidiStreams;
        this.uniStreams = uniStreams;
        this.receiveWindow = receiveWindow;
        this.streamReceiveWindow = streamReceiveWindow;
        this.maxUdpPayloadSize = maxUdpPayloadSize;
        this.initialMtu = initialMtu;
        this.datagramReceiveBufferSize = datagramReceiveBufferSize;
    }

    /**
     * Chrome 156's, as captured over HTTP/3: {@link BrowserProfiles#chrome156Quic()}, {@link
     * TransportParameterProfile#chrome156()} with an idle timeout of 30 s, 100 bidirectional and 103
     * unidirectional streams, a 15 MiB connection and 6 MiB stream window and a 1472-byte UDP
     * payload; an 8-byte initial destination and an empty source connection ID; 1250-byte Initial
     * datagrams shaped as {@link InitialPacketShape#CHROME}.
     *
     * @return the profile
     */
    public static QuicClientProfile chrome156() {
        return new QuicClientProfile("chrome-156", BrowserProfiles.chrome156Quic(), TransportParameterProfile.chrome156(),
                InitialPacketShape.CHROME, 8, 0, Duration.ofSeconds(30), 100, 103, 15_728_640, 6_291_456, 1472, 1250,
                65_536);
    }

    /**
     * Firefox 159's (neqo), as captured over HTTP/3: {@link BrowserProfiles#firefox159Quic()},
     * {@link TransportParameterProfile#firefox159()} with an idle timeout of 30 s, 100 streams each
     * way, a 24 MiB connection and 12 MiB stream window, a 20 ms {@code max_ack_delay} and 8
     * connection IDs; an 8-byte initial destination and a 3-byte source connection ID; Initial
     * datagrams of 1252 bytes over IPv4 and 1232 over IPv6, shaped as {@link InitialPacketShape#FIREFOX}.
     *
     * @return the profile
     */
    public static QuicClientProfile firefox159() {
        return new QuicClientProfile("firefox-159", BrowserProfiles.firefox159Quic(), TransportParameterProfile.firefox159(),
                InitialPacketShape.FIREFOX, 8, 3, Duration.ofSeconds(30), 100, 100, 25_165_824, 12_582_912, 65_527, 1252,
                1232, 65_535, Duration.ofMillis(20), 8);
    }

    /** {@return the profile's name} */
    public String name() {
        return name;
    }

    /** {@return the length of the client's own connection IDs: 0 for none} */
    public int localCidLength() {
        return localCidLength;
    }

    /**
     * The browser's ClientHello, with the ALPS settings it answers a server's with (empty, for its
     * protocols) and {@code decompressor} for the certificates it offers to take compressed.
     */
    public TlsConfig.Builder applyTo(TlsConfig.Builder tls, CertificateDecompressor decompressor) {
        return tls.clientHelloProfile(hello)
                .applicationSettings(Map.of("h3", new byte[0]))
                .certificateDecompressor(decompressor);
    }

    /** The browser's transport limits, which its transport parameters advertise, for a server on IPv4. */
    public TransportConfig.Builder applyTo(TransportConfig.Builder transport) {
        return applyTo(transport, false);
    }

    /**
     * The browser's transport limits, which its transport parameters advertise.
     *
     * @param transport the builder
     * @param ipv6 whether the server is on IPv6, where a browser may send smaller datagrams
     * @return the builder
     */
    public TransportConfig.Builder applyTo(TransportConfig.Builder transport, boolean ipv6) {
        transport.maxIdleTimeout(idleTimeout)
                .maxConcurrentBidiStreams(bidiStreams)
                .maxConcurrentUniStreams(uniStreams)
                .receiveWindow(receiveWindow)
                .streamReceiveWindow(streamReceiveWindow)
                .maxUdpPayloadSize(maxUdpPayloadSize)
                .initialMtu(ipv6 ? initialMtuIpv6 : initialMtu)
                .datagramReceiveBufferSize(datagramReceiveBufferSize);
        if (maxAckDelay != null) transport.maxAckDelay(maxAckDelay);
        if (activeConnectionIdLimit > 0) transport.activeConnectionIdLimit(activeConnectionIdLimit);
        return transport;
    }

    /** The browser's transport parameters, connection IDs and Initial packets. */
    public ClientConfig.Builder applyTo(ClientConfig.Builder client) {
        return client.initialDcidLength(initialDcidLength)
                .activeMigration(true)
                .transportParameterProfile(parameters)
                .initialPacketShape(initials);
    }

    /** {@return an endpoint configuration with the browser's connection ID length} */
    public EndpointConfig endpointConfig() {
        return EndpointConfig.builder().cidLength(localCidLength).build();
    }

    @Override
    public String toString() {
        return "QuicClientProfile[" + name + "]";
    }
}
