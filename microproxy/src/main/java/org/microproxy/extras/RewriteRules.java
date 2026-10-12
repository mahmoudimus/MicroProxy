package org.microproxy.extras;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Declarative request/response rewriting: an ordered list of {@link Rule}s, each matching URLs by
 * regular expression and editing headers and textual response bodies. Every matching rule
 * applies, in order.
 *
 * <pre>{@code
 * bootstrap.withFiltersSource(RewriteRules.builder()
 *         .add(RewriteRules.Rule.matching("https?://example\\.com/.*")
 *                 .replaceInBody("Example Domain", "Rewritten Domain")
 *                 .removeResponseHeader("Content-Security-Policy")
 *                 .setRequestHeader("X-Debug", "1"))
 *         .build());
 * }</pre>
 *
 * <p>URLs are matched in absolute form: as sent by the client, or rebuilt from the {@code Host}
 * header ({@code https://} inside an intercepted TLS session). Body edits apply to textual
 * responses ({@link HttpBodies#isText}, except event streams) whose content coding can be decoded
 * (gzip, deflate); only those responses are buffered, everything else streams. {@link
 * ModifyBody} edits request and response bodies of any type with mitmproxy's spec syntax and
 * filter expressions. Responses larger than {@link
 * Builder#maxBodySize} also stream through unmodified.
 */
public final class RewriteRules implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(RewriteRules.class.getName());

    private final List<Rule> rules;
    private final int maxBodySize;

    private RewriteRules(List<Rule> rules, int maxBodySize) {
        this.rules = List.copyOf(rules);
        this.maxBodySize = maxBodySize;
    }

    /**
     * Starts a builder with the default settings.
     *
     * @return a new builder with default settings
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (HttpMethod.CONNECT.equals(originalRequest.method())) {
            return null;
        }
        String url = absoluteUrl(originalRequest, flowContext);
        List<Rule> matched = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.matches(originalRequest.method(), url)) {
                matched.add(rule);
            }
        }
        return matched.isEmpty() ? null : new Filters(matched, maxBodySize);
    }

    static String absoluteUrl(HttpRequest request, FlowContext ctx) {
        String uri = request.uri();
        String lower = uri.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            return uri;
        }
        String host = request.headers().get(HttpHeaderNames.HOST, "");
        String scheme = ctx != null && ctx.getClientSslSession() != null ? "https" : "http";
        return scheme + "://" + host + (uri.startsWith("/") ? uri : "/" + uri);
    }

    /** The filters applied to one matched request. */
    private static final class Filters implements HttpFilters {
        private final List<Rule> rules;
        private final int maxBodySize;
        private final boolean editsBody;

        Filters(List<Rule> rules, int maxBodySize) {
            this.rules = rules;
            this.maxBodySize = maxBodySize;
            this.editsBody = rules.stream().anyMatch(r -> !r.bodyEdits.isEmpty());
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (httpObject instanceof HttpRequest request) {
                for (Rule rule : rules) {
                    rule.requestHeaderEdits.forEach(edit -> edit.apply(request.headers()));
                }
                if (editsBody) {
                    // Keep the server from picking a coding (dcb, ...) we could not rewrite.
                    HttpBodies.restrictAcceptEncoding(request);
                }
            }
            return null;
        }

        @Override
        public int responseBufferSizeInBytes(HttpResponse response) {
            return editsBody && HttpBodies.isText(response) && Bodies.editable(response) ? maxBodySize : 0;
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            if (httpObject instanceof HttpResponse response) {
                for (Rule rule : rules) {
                    rule.responseHeaderEdits.forEach(edit -> edit.apply(response.headers()));
                }
                if (editsBody && response instanceof FullHttpMessage full && HttpBodies.isText(response)
                        && HttpBodies.canDecode(response)) {
                    try {
                        Bodies.editText(full, original -> {
                            String text = original;
                            for (Rule rule : rules) {
                                for (UnaryOperator<String> edit : rule.bodyEdits) {
                                    text = edit.apply(text);
                                }
                            }
                            return text;
                        });
                    } catch (IOException e) {
                        LOG.log(Level.DEBUG, "leaving undecodable body unmodified", e);
                    }
                }
            }
            return httpObject;
        }
    }

    /** One rewrite rule: a URL pattern plus edits. */
    public static final class Rule {
        private final Pattern url;
        private boolean ignoreQuery;
        private Set<String> methods = Set.of();
        private final List<UnaryOperator<String>> bodyEdits = new ArrayList<>();
        private final List<HeaderEdit> requestHeaderEdits = new ArrayList<>();
        private final List<HeaderEdit> responseHeaderEdits = new ArrayList<>();

        private Rule(Pattern url) {
            this.url = url;
        }

        /**
         * A rule for URLs that fully match {@code urlRegex}.
         *
         * @param urlRegex the regular expression matched against the whole URL
         * @return a rule matching the complete URL against the expression
         */
        public static Rule matching(String urlRegex) {
            return new Rule(Pattern.compile(urlRegex));
        }

        /**
         * A rule for URLs that start with {@code prefix} (matched literally).
         *
         * @param prefix the literal URL prefix to match
         * @return a rule matching the literal URL prefix
         */
        public static Rule prefix(String prefix) {
            return new Rule(Pattern.compile(Pattern.quote(prefix) + ".*"));
        }

        /**
         * Matches the URL without its query string.
         *
         * @return this rule
         */
        public Rule ignoringQuery() {
            this.ignoreQuery = true;
            return this;
        }

        /**
         * Restricts the rule to these methods.
         *
         * @param methods the HTTP methods to match
         * @return this rule
         */
        public Rule methods(String... methods) {
            this.methods = Set.of(methods);
            return this;
        }

        /**
         * Replaces every match of {@code regex} in textual response bodies ({@link Matcher#replaceAll}).
         *
         * @param regex the regular expression to replace
         * @param replacement the replacement text
         * @return this rule
         */
        public Rule replaceInBody(String regex, String replacement) {
            Pattern p = Pattern.compile(regex);
            bodyEdits.add(text -> p.matcher(text).replaceAll(replacement));
            return this;
        }

        /**
         * Replaces every occurrence of {@code target} literally in textual response bodies.
         *
         * @param target the literal text to replace
         * @param replacement the replacement text
         * @return this rule
         */
        public Rule replaceLiteralInBody(String target, String replacement) {
            bodyEdits.add(text -> text.replace(target, replacement));
            return this;
        }

        /**
         * Sets a header on matching requests.
         *
         * @param name the request header name
         * @param value the replacement header value
         * @return this rule
         */
        public Rule setRequestHeader(String name, String value) {
            requestHeaderEdits.add(headers -> headers.set(name, value));
            return this;
        }

        /**
         * Removes a header from matching requests.
         *
         * @param name the request header name to remove
         * @return this rule
         */
        public Rule removeRequestHeader(String name) {
            requestHeaderEdits.add(headers -> headers.remove(name));
            return this;
        }

        /**
         * Sets a header on matching responses.
         *
         * @param name the response header name
         * @param value the replacement header value
         * @return this rule
         */
        public Rule setResponseHeader(String name, String value) {
            responseHeaderEdits.add(headers -> headers.set(name, value));
            return this;
        }

        /**
         * Removes a header from matching responses.
         *
         * @param name the response header name to remove
         * @return this rule
         */
        public Rule removeResponseHeader(String name) {
            responseHeaderEdits.add(headers -> headers.remove(name));
            return this;
        }

        boolean matches(HttpMethod method, String absoluteUrl) {
            if (!methods.isEmpty() && !methods.contains(method.name())) return false;
            String candidate = absoluteUrl;
            if (ignoreQuery) {
                int q = candidate.indexOf('?');
                if (q >= 0) candidate = candidate.substring(0, q);
            }
            return url.matcher(candidate).matches();
        }

        @FunctionalInterface
        private interface HeaderEdit {
            void apply(HttpHeaders headers);
        }
    }

    /** Builds {@link RewriteRules}. */
    public static final class Builder {
        private final List<Rule> rules = new ArrayList<>();
        private int maxBodySize = 10 << 20;

        private Builder() {}

        /**
         * Appends a rule to this rewrite configuration.
         *
         * @param rule the rewrite rule to append
         * @return this builder
         */
        public Builder add(Rule rule) {
            rules.add(Objects.requireNonNull(rule));
            return this;
        }

        /**
         * Largest response body (as received) that is buffered for editing; default 10 MiB.
         *
         * @param bytes the maximum response body size buffered for rewriting
         * @return this builder
         */
        public Builder maxBodySize(int bytes) {
            if (bytes <= 0) throw new IllegalArgumentException("must be positive");
            this.maxBodySize = bytes;
            return this;
        }

        /**
         * Creates the configured response rewrite rules.
         *
         * @return the configured rewrite rules
         */
        public RewriteRules build() {
            return new RewriteRules(rules, maxBodySize);
        }
    }
}
