package io.github.mahmoudimus.quic;

import io.github.mahmoudimus.quic.connection.ConnectionError;
import java.io.IOException;
import java.io.Serial;
import java.util.Objects;

/**
 * A blocking operation failed because its connection ended, or could not be established.
 */
public class QuicConnectionException extends IOException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Why the connection ended; not serialized. */
    private final transient ConnectionError error;

    /**
     * An exception for a connection that ended.
     *
     * @param error why it ended
     */
    public QuicConnectionException(ConnectionError error) {
        super(String.valueOf(error));
        this.error = Objects.requireNonNull(error, "error");
    }

    /**
     * Why the connection ended.
     *
     * @return the reason; null after deserialization
     */
    public ConnectionError error() {
        return error;
    }
}
