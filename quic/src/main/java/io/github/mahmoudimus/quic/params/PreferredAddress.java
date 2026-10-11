/*
 * Ported from quinn-proto src/transport_parameters.rs (PreferredAddress) (Apache-2.0).
 */
package io.github.mahmoudimus.quic.params;

import io.github.mahmoudimus.quic.ConnectionId;
import io.github.mahmoudimus.quic.StatelessResetToken;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * The server's {@code preferred_address} transport parameter (RFC 9000 section 18.2): an address
 * to migrate to after the handshake, with a connection ID and reset token for it. At least one of
 * the two addresses is present.
 *
 * @param ipv4 the IPv4 address and port, or null
 * @param ipv6 the IPv6 address and port, or null
 * @param connectionId the connection ID to use at the new address, 1 to 20 bytes
 * @param statelessResetToken the reset token for that connection ID
 */
public record PreferredAddress(InetSocketAddress ipv4, InetSocketAddress ipv6, ConnectionId connectionId,
        StatelessResetToken statelessResetToken) {

    /**
     * A preferred address.
     *
     * @param ipv4 the IPv4 address and port, or null
     * @param ipv6 the IPv6 address and port, or null
     * @param connectionId the connection ID to use at the new address
     * @param statelessResetToken the reset token for that connection ID
     */
    public PreferredAddress {
        Objects.requireNonNull(connectionId, "connectionId");
        Objects.requireNonNull(statelessResetToken, "statelessResetToken");
        if (ipv4 != null && !(ipv4.getAddress() instanceof Inet4Address)) {
            throw new IllegalArgumentException("not an IPv4 address: " + ipv4);
        }
        if (ipv6 != null && !(ipv6.getAddress() instanceof Inet6Address)) {
            throw new IllegalArgumentException("not an IPv6 address: " + ipv6);
        }
    }

    int encodedLength() {
        return 4 + 2 + 16 + 2 + 1 + connectionId.length() + StatelessResetToken.LENGTH;
    }

    void encode(ByteBuffer out) {
        out.put(ipv4 == null ? new byte[4] : ipv4.getAddress().getAddress());
        out.putShort((short) (ipv4 == null ? 0 : ipv4.getPort()));
        out.put(ipv6 == null ? new byte[16] : ipv6.getAddress().getAddress());
        out.putShort((short) (ipv6 == null ? 0 : ipv6.getPort()));
        out.put((byte) connectionId.length());
        connectionId.writeTo(out);
        statelessResetToken.writeTo(out);
    }

    /**
     * Reads the parameter value.
     *
     * @return the address, or null if neither address is present
     * @throws IllegalArgumentException if the connection ID length is out of range
     * @throws BufferUnderflowException if the value is truncated
     */
    static PreferredAddress decode(ByteBuffer in) {
        byte[] v4 = new byte[4];
        in.get(v4);
        int port4 = in.getShort() & 0xffff;
        byte[] v6 = new byte[16];
        in.get(v6);
        int port6 = in.getShort() & 0xffff;
        int cidLength = in.get() & 0xff;
        ConnectionId cid = ConnectionId.read(in, cidLength);
        StatelessResetToken token = StatelessResetToken.read(in);
        try {
            InetSocketAddress a4 = isZero(v4) && port4 == 0 ? null
                    : new InetSocketAddress(InetAddress.getByAddress(v4), port4);
            InetSocketAddress a6 = isZero(v6) && port6 == 0 ? null
                    : new InetSocketAddress(Inet6Address.getByAddress(null, v6, -1), port6);
            if (a4 == null && a6 == null) {
                return null;
            }
            return new PreferredAddress(a4, a6, cid, token);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static boolean isZero(byte[] b) {
        for (byte x : b) {
            if (x != 0) return false;
        }
        return true;
    }
}
