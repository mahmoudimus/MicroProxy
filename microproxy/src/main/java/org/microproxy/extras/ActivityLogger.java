package org.microproxy.extras;

import java.lang.System.Logger.Level;
import java.util.Objects;
import java.util.function.Consumer;
import org.microproxy.ActivityTrackerAdapter;
import org.microproxy.FlowRecord;

/**
 * An {@link org.microproxy.ActivityTracker} that writes one access-log line per finished exchange
 * or flow ({@link org.microproxy.ActivityTracker#flowEnded}), in an {@link AccessLogFormat}: one of
 * the {@link LogFormat} presets, or an Envoy-compatible format string or JSON dictionary. An
 * {@link AccessLogFilter} may leave records out. Add it with {@code
 * bootstrap.plusActivityTracker(new ActivityLogger(LogFormat.CLF))}, or build one:
 *
 * <pre>{@code
 * ActivityLogger.builder()
 *         .format(LogFormat.envoy("%START_TIME% %REQ(:METHOD)% %RESPONSE_CODE% %RESPONSE_FLAGS%"))
 *         .filter(AccessLogFilter.parse("status>=400 || response_flag"))
 *         .sink(lines::add)
 *         .build();
 * }</pre>
 *
 * <p>A line is written when the exchange is over: once its response has been written, or when it
 * was abandoned (with the flags that say why); for a {@code CONNECT} tunnel, a SOCKS client, a
 * WebSocket session, a CONNECT-UDP flow or a relayed QUIC flow, when it closes. Lines go to the
 * {@code System.Logger} named after this class at INFO, or to the sink.
 */
public class ActivityLogger extends ActivityTrackerAdapter {

    private static final System.Logger LOG = System.getLogger(ActivityLogger.class.getName());

    private final LogFormat logFormat;
    private final AccessLogFormat format;
    private final AccessLogFilter filter;
    private final Consumer<String> sink;

    /**
     * Logs in a preset format to the {@code System.Logger} named {@code
     * org.microproxy.extras.ActivityLogger}.
     *
     * @param logFormat the access log format
     */
    public ActivityLogger(LogFormat logFormat) {
        this(logFormat, null);
    }

    /**
     * Logs each line in a preset format to {@code sink}, e.g. a file writer.
     *
     * @param logFormat the access log format
     * @param sink the consumer receiving each formatted log entry
     */
    public ActivityLogger(LogFormat logFormat, Consumer<String> sink) {
        this(logFormat, logFormat.formatter(), AccessLogFilter.ALL, sink);
    }

    /**
     * Logs each line in {@code format} to {@code sink}.
     *
     * @param format the access log format
     * @param sink the consumer receiving each formatted log entry, or {@code null} for the {@code System.Logger}
     */
    public ActivityLogger(AccessLogFormat format, Consumer<String> sink) {
        this(null, format, AccessLogFilter.ALL, sink);
    }

    private ActivityLogger(LogFormat logFormat, AccessLogFormat format, AccessLogFilter filter, Consumer<String> sink) {
        this.logFormat = logFormat;
        this.format = Objects.requireNonNull(format);
        this.filter = Objects.requireNonNull(filter);
        this.sink = sink;
    }

    /** {@return a builder of an access logger} */
    public static Builder builder() {
        return new Builder();
    }

    /** {@return the preset this logger writes, or {@code null} for a custom format} */
    public LogFormat getLogFormat() {
        return logFormat;
    }

    /** {@return the format of the lines} */
    public AccessLogFormat format() {
        return format;
    }

    /** {@return the filter that decides which records are written} */
    public AccessLogFilter filter() {
        return filter;
    }

    @Override
    public void flowEnded(FlowRecord record) {
        boolean wanted;
        try {
            wanted = filter.test(record);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "access-log filter threw; logging the record", e);
            wanted = true;
        }
        if (wanted) log(format.format(record));
    }

    /**
     * Writes a finished line. Override to send lines elsewhere.
     *
     * @param line the formatted log entry
     */
    protected void log(String line) {
        if (sink != null) {
            sink.accept(line);
        } else {
            LOG.log(Level.INFO, line);
        }
    }

    /** Escapes a string for inclusion in a JSON string literal. */
    static String json(String s) {
        return Json.escape(s);
    }

    /** Quotes a CSV field per RFC 4180. */
    static String csv(String s) {
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    /** Builds an {@link ActivityLogger}. */
    public static final class Builder {
        private LogFormat preset = LogFormat.ENVOY;
        private AccessLogFormat format;
        private AccessLogFilter filter = AccessLogFilter.ALL;
        private Consumer<String> sink;

        private Builder() {}

        /**
         * Writes lines in a preset format (default: {@link LogFormat#ENVOY}).
         *
         * @param preset the preset
         * @return this builder
         */
        public Builder format(LogFormat preset) {
            this.preset = Objects.requireNonNull(preset);
            this.format = null;
            return this;
        }

        /**
         * Writes lines in {@code format}.
         *
         * @param format the format
         * @return this builder
         */
        public Builder format(AccessLogFormat format) {
            this.format = Objects.requireNonNull(format);
            this.preset = null;
            return this;
        }

        /**
         * Writes only the records {@code filter} passes (default: all). Several calls combine
         * their filters: a record must pass them all.
         *
         * @param filter the filter
         * @return this builder
         */
        public Builder filter(AccessLogFilter filter) {
            Objects.requireNonNull(filter);
            this.filter = this.filter == AccessLogFilter.ALL ? filter : this.filter.and(filter);
            return this;
        }

        /**
         * Sends lines to {@code sink} instead of the {@code System.Logger}.
         *
         * @param sink the consumer receiving each line
         * @return this builder
         */
        public Builder sink(Consumer<String> sink) {
            this.sink = sink;
            return this;
        }

        /** {@return the logger} */
        public ActivityLogger build() {
            return new ActivityLogger(preset, format != null ? format : preset.formatter(), filter, sink);
        }
    }
}
