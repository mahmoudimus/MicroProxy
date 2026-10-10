/*
 * Ported from mitmproxy's mitmproxy/addons/blocklist.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * Blocks requests, as mitmproxy's {@code block_list}: the first rule whose filter matches answers
 * the request with an empty response of its status, without contacting the server. Status {@link
 * #NO_RESPONSE} ({@code 444}) closes the connection without any response instead (on HTTP/2, the
 * stream is reset).
 *
 * <pre>{@code
 * BlockList.of("|~d ads\\.example\\.com|404", "|~u /tracking/|444")
 * }</pre>
 *
 * <p>Specs are {@code |flow-filter|status}, the separator being the first character. Only heads
 * are read, unless a filter looks at the request body ({@code ~bq}).
 */
public final class BlockList implements HttpFiltersSource {

    /** The status that means "close the connection without a response", as in mitmproxy and nginx. */
    public static final int NO_RESPONSE = 444;

    private final List<Rule> rules;
    private final int maxBodySize;

    private BlockList(List<Rule> rules, int maxBodySize) {
        this.rules = List.copyOf(rules);
        this.maxBodySize = maxBodySize;
    }

    /**
     * Block rules from specs.
     *
     * @param specs specs of the form {@code |flow-filter|status}
     * @return the addon
     * @throws IllegalArgumentException if a spec is invalid
     */
    public static BlockList of(String... specs) {
        Builder b = builder();
        for (String spec : specs) b.add(spec);
        return b.build();
    }

    /**
     * Starts a builder with no rules.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /** {@return the rules, in order} */
    public List<Rule> rules() {
        return rules;
    }

    /**
     * One rule: requests the filter matches get an empty response with {@code status}, or none.
     *
     * @param filter the requests to block
     * @param status the status to answer with, or {@link #NO_RESPONSE} to close the connection
     */
    public record Rule(FlowFilter filter, int status) {

        /** Checks the parts. */
        public Rule {
            Objects.requireNonNull(filter, "filter");
            if (status < 100 || status > 999) throw new IllegalArgumentException("invalid HTTP status code: " + status);
        }

        /**
         * Parses a spec of the form {@code |flow-filter|status}.
         *
         * @param spec the spec, starting with its separator
         * @return the rule
         * @throws IllegalArgumentException if the spec, its filter or its status is invalid
         */
        public static Rule parse(String spec) {
            if (spec == null || spec.length() < 2) throw new IllegalArgumentException("invalid block_list spec: " + spec);
            String sep = spec.substring(0, 1);
            String[] parts = spec.substring(1).split(java.util.regex.Pattern.quote(sep), 3);
            if (parts.length != 2) {
                throw new IllegalArgumentException("invalid block_list spec " + spec + ": expected |flow-filter|status");
            }
            int status;
            try {
                status = Integer.parseInt(parts[1].strip());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid HTTP status code: " + parts[1], e);
            }
            return new Rule(FlowFilter.parse(parts[0]), status);
        }
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (rules.isEmpty() || HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new Filters(originalRequest, flowContext);
    }

    private final class Filters extends AddonFilters {
        /** The placeholder answer for 444: never written, the connection is closed instead. */
        private HttpResponse kill;

        Filters(HttpRequest original, FlowContext ctx) {
            super(original, ctx);
        }

        @Override
        public int requestBufferSizeInBytes(HttpRequest head) {
            int max = 0;
            for (Rule rule : rules) max = Math.max(max, requestBufferFor(rule.filter(), head, maxBodySize));
            return max;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (!(httpObject instanceof HttpRequest r)) return null;
            request = r;
            for (Rule rule : rules) {
                if (!rule.filter().matches(flow(null))) continue;
                HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.valueOf(rule.status()));
                if (rule.status() == NO_RESPONSE) kill = response;
                return response;
            }
            return null;
        }

        @Override
        public HttpObject proxyToClientResponse(HttpObject httpObject) {
            // Returning null makes the proxy close the connection (or reset the stream) unanswered.
            return httpObject == kill ? null : httpObject;
        }
    }

    /** Builds {@link BlockList}. */
    public static final class Builder {
        private final List<Rule> rules = new ArrayList<>();
        private int maxBodySize = 10 << 20;

        private Builder() {}

        /**
         * Adds a rule from a spec.
         *
         * @param spec a spec of the form {@code |flow-filter|status}
         * @return this builder
         * @throws IllegalArgumentException if the spec is invalid
         */
        public Builder add(String spec) {
            return add(Rule.parse(spec));
        }

        /**
         * Adds a rule.
         *
         * @param rule the rule to append
         * @return this builder
         */
        public Builder add(Rule rule) {
            rules.add(Objects.requireNonNull(rule));
            return this;
        }

        /**
         * Largest request body buffered for filters that look at it ({@code ~bq}); default 10 MiB.
         *
         * @param bytes the buffer limit in bytes
         * @return this builder
         */
        public Builder maxBodySize(int bytes) {
            if (bytes <= 0) throw new IllegalArgumentException("must be positive");
            this.maxBodySize = bytes;
            return this;
        }

        /**
         * Creates the addon.
         *
         * @return the configured addon
         */
        public BlockList build() {
            return new BlockList(rules, maxBodySize);
        }
    }
}
