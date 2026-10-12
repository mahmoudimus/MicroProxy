/*
 * Ported from mitmproxy's mitmproxy/addons/modifybody.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Replaces text in request and response bodies, as mitmproxy's {@code modify_body}: every match of
 * a regular expression in the decoded body becomes the replacement, in the messages a rule's filter
 * selects. Request bodies are edited before the request goes on, response bodies before the
 * response reaches the client.
 *
 * <pre>{@code
 * ModifyBody.of("|~bs Example|Example Domain|Rewritten Domain",   // responses mentioning Example
 *               "|~q & ~d api.example.com|\"debug\":false|\"debug\":true")   // request bodies
 * }</pre>
 *
 * <p>Specs are {@code [|flow-filter]|regex|[@]replacement}, the separator being the first
 * character. The regex runs over the body's bytes ({@code .} matches line ends too), and the
 * replacement is inserted literally, with Python's backslash escapes decoded; {@code @path} reads
 * it from a file. Without a filter a rule edits requests and responses alike; {@code ~q} limits it
 * to requests (no response yet) and {@code ~s} to responses.
 *
 * <p>Only messages a rule might select are buffered: the decision is made from the heads, and a
 * filter that also looks at bodies ({@code ~b}) gets the body buffered and then checked. Messages
 * whose codings cannot be decoded and event streams are never buffered. A response body larger
 * than {@link Builder#maxBodySize} streams through unchanged; a request body that large is
 * answered with {@code 413}, as for any filter that buffers requests. The proxy narrows {@code
 * Accept-Encoding} to codings it can decode, re-applies the body's coding after editing (Brotli
 * and zstd become gzip) and fixes {@code Content-Length}.
 */
public final class ModifyBody implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(ModifyBody.class.getName());

    private final List<Rule> rules;
    private final int maxBodySize;

    private ModifyBody(List<Rule> rules, int maxBodySize) {
        this.rules = List.copyOf(rules);
        this.maxBodySize = maxBodySize;
    }

    /**
     * Body rules from specs.
     *
     * @param specs specs of the form {@code [|flow-filter]|regex|[@]replacement}
     * @return the addon
     * @throws IllegalArgumentException if a spec is invalid, or names a file that cannot be read
     */
    public static ModifyBody of(String... specs) {
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

    /** One rule: a regular expression to replace in the bodies a filter selects. */
    public static final class Rule {
        private final FlowFilter filter;
        private final Pattern pattern;
        private final Supplier<byte[]> replacement;

        private Rule(FlowFilter filter, String regex, Supplier<byte[]> replacement) {
            this.filter = Objects.requireNonNull(filter, "filter");
            // Over bytes: the regex's UTF-8 bytes, one char per byte, like the bodies it searches.
            this.pattern = Specs.regex(new String(regex.getBytes(UTF_8), ISO_8859_1), Pattern.DOTALL, "modify_body");
            this.replacement = replacement;
        }

        /**
         * A rule that replaces {@code regex} with the literal {@code replacement}.
         *
         * @param filter the messages to edit
         * @param regex the regular expression, matched against the decoded body's bytes
         * @param replacement the replacement text, inserted as UTF-8
         * @return the rule
         * @throws IllegalArgumentException if the regular expression is invalid
         */
        public static Rule of(FlowFilter filter, String regex, String replacement) {
            byte[] bytes = replacement.getBytes(UTF_8);
            return new Rule(filter, regex, () -> bytes);
        }

        /**
         * Parses a spec of the form {@code [|flow-filter]|regex|[@]replacement}.
         *
         * @param spec the spec, starting with its separator
         * @return the rule
         * @throws IllegalArgumentException if the spec is invalid or its file cannot be read
         */
        public static Rule parse(String spec) {
            Specs.Spec s = Specs.parse(spec, 2, "modify_body");
            try {
                return new Rule(s.filter(), s.parts().get(0), Specs.replacementSource(s.parts().get(1)));
            } catch (UncheckedIOException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }

        /** {@return the messages this rule edits} */
        public FlowFilter filter() {
            return filter;
        }

        /** {@return the regular expression, over the body's bytes as ISO-8859-1 characters} */
        public Pattern pattern() {
            return pattern;
        }

        byte[] apply(byte[] body) {
            String quoted = Matcher.quoteReplacement(new String(replacement.get(), ISO_8859_1));
            return pattern.matcher(new String(body, ISO_8859_1)).replaceAll(quoted).getBytes(ISO_8859_1);
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
            request = head;
            if (!unbufferedBody(head) || !Bodies.editable(head)) return 0;
            FlowFilter.Flow flow = flow(null);
            return rules.stream().anyMatch(r -> r.filter.mayMatch(flow)) ? maxBodySize : 0;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (!(httpObject instanceof HttpRequest r)) return null;
            request = r;
            // The server must answer in a coding the proxy can decode, should a response rule apply.
            HttpBodies.restrictAcceptEncoding(r);
            if (r instanceof FullHttpRequest full && full.content().length > 0) edit(full, flow(null));
            return null;
        }

        @Override
        public int responseBufferSizeInBytes(HttpResponse response) {
            if (!mayHaveBody(response) || !Bodies.editable(response)) return 0;
            FlowFilter.Flow flow = flow(response);
            return rules.stream().anyMatch(r -> r.filter.mayMatch(flow)) ? maxBodySize : 0;
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            if (httpObject instanceof FullHttpResponse full && mayHaveBody(full)) edit(full, flow(full));
            return httpObject;
        }

        private boolean mayHaveBody(HttpResponse response) {
            int code = response.status().code();
            return code >= 200 && code != 204 && code != 304 && !HttpMethod.HEAD.equals(request.method());
        }

        private void edit(FullHttpMessage message, FlowFilter.Flow flow) {
            if (!HttpBodies.canDecode(message)) return;
            List<Rule> matching = rules.stream().filter(r -> r.filter.matches(flow)).toList();
            if (matching.isEmpty()) return;
            try {
                Bodies.edit(message, body -> {
                    byte[] b = body;
                    for (Rule rule : matching) b = rule.apply(b);
                    return b;
                });
            } catch (IOException e) {
                LOG.log(Level.DEBUG, "modify_body: leaving an undecodable body unmodified", e);
            }
        }
    }

    /** Builds {@link ModifyBody}. */
    public static final class Builder {
        private final List<Rule> rules = new ArrayList<>();
        private int maxBodySize = 10 << 20;

        private Builder() {}

        /**
         * Adds a rule from a spec.
         *
         * @param spec a spec of the form {@code [|flow-filter]|regex|[@]replacement}
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
         * Largest body (as received) buffered for editing; default 10 MiB.
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
        public ModifyBody build() {
            return new ModifyBody(rules, maxBodySize);
        }
    }
}
