package io.github.mahmoudimus.quic.tls;

import javax.net.ssl.SSLHandshakeException;

/**
 * A handshake that offered Encrypted Client Hello and that the server completed without it
 * (RFC 9849 section 6.1.6): the server authenticated as the configuration's public name, and the
 * client then ended the connection with the {@code ech_required} alert. The connection carried no
 * application data.
 *
 * <p>The server's retry configurations, if it sent any, are a securely replaced ECHConfigList to
 * retry with on a new connection; without them the server has securely disabled ECH and a retry
 * would go without it. Whether to retry is the caller's choice: nothing here retries.
 */
public final class EchRejectedException extends SSLHandshakeException {

    private static final long serialVersionUID = 1L;

    private final byte[] retryConfigs;

    EchRejectedException(String message, byte[] retryConfigs) {
        super(message);
        this.retryConfigs = retryConfigs == null ? null : retryConfigs.clone();
    }

    /**
     * The server's {@code retry_configs}.
     *
     * @return the ECHConfigList, with its two-byte length prefix, as the server sent it; null if
     *     it sent none
     */
    public byte[] retryConfigs() {
        return retryConfigs == null ? null : retryConfigs.clone();
    }
}
