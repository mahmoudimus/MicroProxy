package io.github.mahmoudimus.quic.tls;

/**
 * Where a client finds a server's Encrypted Client Hello configurations (RFC 9849): typically the
 * {@code ech} parameter of the server's DNS HTTPS record (RFC 9848), looked up however the
 * application resolves names. Nothing here makes DNS queries.
 *
 * <p>With a list, the ClientHello the server's name is in is encrypted to one of its
 * configurations and an outer ClientHello names the configuration's public name; without one, the
 * client sends the profile's GREASE ECH extension, if it has one, as a browser does.
 */
@FunctionalInterface
public interface EchConfigProvider {

    /**
     * The server's ECHConfigList.
     *
     * @param serverName the name the client is connecting to, as sent in the inner ClientHello
     * @return the serialized ECHConfigList (RFC 9849 section 4), with its two-byte length prefix;
     *     null to offer no ECH to this server
     */
    byte[] echConfigList(String serverName);
}
