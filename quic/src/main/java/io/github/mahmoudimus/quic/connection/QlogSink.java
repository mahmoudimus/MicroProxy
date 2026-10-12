package io.github.mahmoudimus.quic.connection;

import java.util.Objects;

/**
 * Receives qlog-style connection events, for debugging: packets sent, received and lost, recovery
 * metrics, key updates and state changes. Event names follow the qlog schema ({@code
 * transport:packet_sent}, {@code recovery:packet_lost}, ...); the data is a small JSON object.
 *
 * <p>Implementations must be thread-safe: connections report from their own threads. Events are
 * only built when a sink is configured, so an absent sink costs nothing.
 */
@FunctionalInterface
public interface QlogSink {

    /**
     * Records one event.
     *
     * @param connection the connection's original Destination Connection ID, in hexadecimal
     * @param timeNanos the time of the event on the connection's clock
     * @param name the qlog event name, such as {@code transport:packet_sent}
     * @param data the event data as a JSON object
     */
    void event(String connection, long timeNanos, String name, String data);

    /**
     * A sink that writes each event as one JSON line to a {@link System.Logger} at {@code DEBUG}.
     *
     * @param logger the logger
     * @return the sink
     */
    static QlogSink logger(System.Logger logger) {
        Objects.requireNonNull(logger, "logger");
        return (connection, time, name, data) -> {
            if (logger.isLoggable(System.Logger.Level.DEBUG)) {
                logger.log(System.Logger.Level.DEBUG, "{\"group_id\":\"" + connection + "\",\"time\":"
                        + time / 1_000 + ",\"name\":\"" + name + "\",\"data\":" + data + "}");
            }
        };
    }
}
