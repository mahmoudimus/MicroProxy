/*
 * Ported from mitmproxy's mitmproxy/addons/modifyheaders.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Sets and removes headers, as mitmproxy's {@code modify_headers}. Each rule names a header and a
 * value; on every request head, and every response head from a server, the rules whose filter
 * matches first remove that header, then add the value (an empty value only removes it). Filters
 * are checked against the message before any rule changes it, and see no bodies.
 *
 * <pre>{@code
 * ModifyHeaders.of("|~q|User-Agent|MicroProxy",          // requests only (~q: no response yet)
 *                  "|~s & ~d example.com|Server|",       // responses only: remove Server
 *                  "|X-Debug|@/etc/debug-token")          // both, the value read from a file
 * }</pre>
 *
 * <p>Specs are {@code [|flow-filter]|header-name|[@]header-value}, the separator being the first
 * character. The value takes Python's backslash escapes; {@code @path} reads it from a file, again
 * for each message. Without a filter a rule applies to requests and responses alike, as in
 * mitmproxy. {@link RewriteRules} offers the same edits from Java with URL regexes.
 */
public final class ModifyHeaders implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(ModifyHeaders.class.getName());

    private final List<Rule> rules;

    private ModifyHeaders(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    /**
     * Header rules from specs.
     *
     * @param specs specs of the form {@code [|flow-filter]|header-name|[@]header-value}
     * @return the addon
     * @throws IllegalArgumentException if a spec is invalid, or names a file that cannot be read
     */
    public static ModifyHeaders of(String... specs) {
        List<Rule> rules = new ArrayList<>();
        for (String spec : specs) rules.add(Rule.parse(spec));
        return new ModifyHeaders(rules);
    }

    /**
     * Header rules.
     *
     * @param rules the rules, in order
     * @return the addon
     */
    public static ModifyHeaders of(List<Rule> rules) {
        return new ModifyHeaders(rules);
    }

    /** {@return the rules, in order} */
    public List<Rule> rules() {
        return rules;
    }

    /** One rule: a header to replace on the messages a filter matches. */
    public static final class Rule {
        private final FlowFilter filter;
        private final String name;
        private final Supplier<byte[]> value;

        private Rule(FlowFilter filter, String name, Supplier<byte[]> value) {
            this.filter = Objects.requireNonNull(filter, "filter");
            this.name = Objects.requireNonNull(name, "name");
            this.value = value;
        }

        /**
         * A rule that sets {@code name} to {@code value}, or removes it when {@code value} is empty.
         *
         * @param filter the messages to change
         * @param name the header name
         * @param value the new value; empty to remove the header
         * @return the rule
         */
        public static Rule of(FlowFilter filter, String name, String value) {
            byte[] bytes = value.getBytes(ISO_8859_1);
            return new Rule(filter, name, () -> bytes);
        }

        /**
         * Parses a spec of the form {@code [|flow-filter]|header-name|[@]header-value}.
         *
         * @param spec the spec, starting with its separator
         * @return the rule
         * @throws IllegalArgumentException if the spec is invalid or its file cannot be read
         */
        public static Rule parse(String spec) {
            Specs.Spec s = Specs.parse(spec, 2, "modify_headers");
            if (s.parts().get(0).isEmpty()) throw new IllegalArgumentException("modify_headers spec without a header name: " + spec);
            try {
                return new Rule(s.filter(), s.parts().get(0), Specs.replacementSource(s.parts().get(1)));
            } catch (java.io.UncheckedIOException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }

        /** {@return the messages this rule changes} */
        public FlowFilter filter() {
            return filter;
        }

        /** {@return the header name} */
        public String name() {
            return name;
        }
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (rules.isEmpty() || HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new AddonFilters(originalRequest, flowContext) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                if (httpObject instanceof HttpRequest r) {
                    request = r;
                    apply(flow(null), r.headers());
                }
                return null;
            }

            @Override
            public HttpObject serverToProxyResponse(HttpObject httpObject) {
                if (httpObject instanceof HttpResponse r) apply(flow(r), r.headers());
                return httpObject;
            }
        };
    }

    private void apply(FlowFilter.Flow flow, HttpHeaders headers) {
        // Every filter sees the message as it was, before any rule changed it.
        boolean[] matched = new boolean[rules.size()];
        for (int i = 0; i < matched.length; i++) matched[i] = rules.get(i).filter.matches(flow);
        for (int i = 0; i < matched.length; i++) {
            if (matched[i]) headers.remove(rules.get(i).name);
        }
        for (int i = 0; i < matched.length; i++) {
            if (!matched[i]) continue;
            byte[] value = rules.get(i).value.get();
            if (value.length == 0) continue;
            try {
                headers.add(rules.get(i).name, new String(value, ISO_8859_1));
            } catch (IllegalArgumentException e) {
                // A value with CR or LF (or an invalid name) would let the header inject others.
                LOG.log(System.Logger.Level.WARNING, "modify_headers: not setting " + rules.get(i).name + ": "
                        + e.getMessage());
            }
        }
    }
}
