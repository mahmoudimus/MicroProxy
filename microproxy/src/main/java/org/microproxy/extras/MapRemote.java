/*
 * Ported from mitmproxy's mitmproxy/addons/mapremote.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Sends requests to another URL, as mitmproxy's {@code map_remote}: each rule replaces every match
 * of a regular expression in the request's absolute URL, and the request goes to the result. The
 * {@code Host} header follows the new URL. Inside an intercepted session the request leaves the
 * session's server for the new one, over TLS for {@code https://}.
 *
 * <pre>{@code
 * MapRemote.of("|https://api\\.example\\.com/v1/|http://localhost:8000/v1/",
 *              "|~m GET|example\\.org|example.net")
 * }</pre>
 *
 * <p>Specs are {@code [|flow-filter]|url-regex|replacement}, the separator being the first
 * character. Every matching rule applies, in order, each to the URL the previous ones left.
 * Replacements may use groups as Python does ({@code \1}, {@code \g<name>}) or as Java does
 * ({@code $1}). Only heads are read, unless a rule's filter looks at the request body ({@code
 * ~bq}), which is then buffered (see {@link Builder#maxBodySize}).
 */
public final class MapRemote implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(MapRemote.class.getName());

    private final List<Rule> rules;
    private final int maxBodySize;

    private MapRemote(List<Rule> rules, int maxBodySize) {
        this.rules = List.copyOf(rules);
        this.maxBodySize = maxBodySize;
    }

    /**
     * Map remote rules from specs, with default settings.
     *
     * @param specs specs of the form {@code [|flow-filter]|url-regex|replacement}
     * @return the addon
     * @throws IllegalArgumentException if a spec is invalid
     */
    public static MapRemote of(String... specs) {
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
     * One rule: requests the filter matches have every match of {@code pattern} in their URL
     * replaced.
     *
     * @param filter the requests the rule applies to
     * @param pattern the regular expression replaced in the URL
     * @param replacement the replacement, in {@link java.util.regex.Matcher#replaceAll} syntax
     */
    public record Rule(FlowFilter filter, Pattern pattern, String replacement) {

        /** Checks that every part is present. */
        public Rule {
            Objects.requireNonNull(filter, "filter");
            Objects.requireNonNull(pattern, "pattern");
            Objects.requireNonNull(replacement, "replacement");
        }

        /**
         * Parses a spec of the form {@code [|flow-filter]|url-regex|replacement}.
         *
         * @param spec the spec, starting with its separator
         * @return the rule
         * @throws IllegalArgumentException if the spec or its filter or regex is invalid
         */
        public static Rule parse(String spec) {
            Specs.Spec s = Specs.parse(spec, 2, "map_remote");
            return new Rule(s.filter(), Specs.regex(s.parts().get(0), 0, "map_remote"),
                    Specs.javaReplacement(s.parts().get(1)));
        }
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (rules.isEmpty() || HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new Filters(originalRequest, flowContext);
    }

    private final class Filters extends AddonFilters {
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
                String url = Specs.url(r, ctx);
                String mapped = rule.pattern().matcher(url).replaceAll(rule.replacement());
                if (mapped.equals(url)) continue;
                String scheme = Specs.scheme(mapped);
                String host = FlowFilter.urlHost(mapped);
                if (!(scheme.equals("http") || scheme.equals("https")) || host.isEmpty()) {
                    LOG.log(Level.WARNING, "map_remote: ignoring " + mapped + " (from " + url
                            + "): not an absolute http(s) URL");
                    continue;
                }
                setUrl(r, mapped);
            }
            return null;
        }
    }

    /** Points {@code request} at {@code url}, with a {@code Host} header to match. */
    static void setUrl(HttpRequest request, String url) {
        request.setUri(url);
        int start = url.indexOf("://") + 3;
        int end = start;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) end++;
        String authority = url.substring(start, end);
        int at = authority.lastIndexOf('@');
        request.headers().set(HttpHeaderNames.HOST, at >= 0 ? authority.substring(at + 1) : authority);
    }

    /** Builds {@link MapRemote}. */
    public static final class Builder {
        private final List<Rule> rules = new ArrayList<>();
        private int maxBodySize = 10 << 20;

        private Builder() {}

        /**
         * Adds a rule from a spec.
         *
         * @param spec a spec of the form {@code [|flow-filter]|url-regex|replacement}
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
         * A larger body is answered with {@code 413}, as for any filter that buffers requests.
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
        public MapRemote build() {
            return new MapRemote(rules, maxBodySize);
        }
    }
}
