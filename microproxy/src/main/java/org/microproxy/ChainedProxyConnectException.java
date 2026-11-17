package org.microproxy;

import java.io.IOException;
import java.net.ConnectException;
import java.util.OptionalInt;

/**
 * A chained HTTP proxy did not open the tunnel the proxy's {@code CONNECT} asked it for: it
 * answered with a status other than {@code 2xx} ({@link Outcome#REFUSED}, with {@link #status()}),
 * or ended the connection before it answered ({@link Outcome#CLOSED}, {@link Outcome#RESET}). It
 * is the {@link ProxyFailure.ConnectFailed#cause()} of such an attempt (the last one's, with
 * several routes), and what {@link ChainedProxy#connectionFailed} gets; {@link
 * ProxyFailure.ConnectFailed#reason()} and {@link ProxyFailure.ConnectFailed#chainedProxyStatus()}
 * read it.
 *
 * <p>Its message is the one such a failure always had: {@code "chained proxy refused CONNECT: 407
 * Proxy Authentication Required"}, {@code "chained proxy refused CONNECT: connection closed"}, or,
 * for a reset, the socket's own ({@code "Connection reset"}), whose exception is then the cause.
 */
public final class ChainedProxyConnectException extends ConnectException {

    /** How the chained proxy's {@code CONNECT} failed. */
    public enum Outcome {
        /** It answered with a status other than {@code 2xx} ({@link #status()}). */
        REFUSED,
        /** It closed the connection before its answer was complete. */
        CLOSED,
        /** The connection was reset (or failed otherwise) before its answer was complete. */
        RESET;

        /** {@return the outcome's name in lower case: {@code refused}, {@code closed}, {@code reset}} */
        public String code() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    private final Outcome outcome;
    private final int status;

    private ChainedProxyConnectException(String message, Outcome outcome, int status, Throwable cause) {
        super(message);
        this.outcome = outcome;
        this.status = status;
        if (cause != null) initCause(cause);
    }

    /**
     * The chained proxy answered the {@code CONNECT} with {@code status}, not {@code 2xx}.
     *
     * @param status the status code
     * @param reasonPhrase the status line's reason phrase, as the proxy sent it
     * @return the exception
     */
    public static ChainedProxyConnectException refused(int status, String reasonPhrase) {
        String line = reasonPhrase == null || reasonPhrase.isEmpty() ? String.valueOf(status) : status + " " + reasonPhrase;
        return new ChainedProxyConnectException("chained proxy refused CONNECT: " + line, Outcome.REFUSED, status, null);
    }

    /**
     * The chained proxy closed the connection before its answer to the {@code CONNECT} was complete.
     *
     * @param cause what reading the answer failed with, or null when it just ended
     * @return the exception
     */
    public static ChainedProxyConnectException closed(IOException cause) {
        return new ChainedProxyConnectException("chained proxy refused CONNECT: connection closed", Outcome.CLOSED, -1,
                cause);
    }

    /**
     * The connection to the chained proxy was reset (or failed otherwise) before its answer to the
     * {@code CONNECT} was complete.
     *
     * @param cause the socket's exception, whose message this one keeps
     * @return the exception
     */
    public static ChainedProxyConnectException reset(IOException cause) {
        return new ChainedProxyConnectException(cause.getMessage(), Outcome.RESET, -1, cause);
    }

    /** {@return how the {@code CONNECT} failed} */
    public Outcome outcome() {
        return outcome;
    }

    /** {@return the status the chained proxy answered the {@code CONNECT} with, empty when it answered none} */
    public OptionalInt status() {
        return status < 0 ? OptionalInt.empty() : OptionalInt.of(status);
    }
}
