/*
 * Ported from mitmproxy's mitmproxy/addons/maplocal.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt. MicroProxy changes: candidates that would leave the mapped
 * directory (also through symbolic links) are answered with 404 instead of being sent on.
 */
package org.microproxy.extras;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * Answers requests from local files, as mitmproxy's {@code map_local}. A rule maps URLs matching a
 * regular expression to a file, served for every match, or to a directory, where the part of the
 * URL after the match (or the regex's first group) names the file:
 *
 * <pre>{@code
 * MapLocal.of("|example.com/static/|/srv/static",        // example.com/static/app.js -> /srv/static/app.js
 *             "|~m GET|example.com/favicon.ico|/srv/icon.ico")
 * }</pre>
 *
 * <p>Specs are {@code [|flow-filter]|url-regex|file-or-directory}, the separator being the first
 * character; the path must exist. For a directory, the URL's remaining path (without its query)
 * is percent-decoded, and {@code name}, then {@code name/index.html} are tried, then the same with
 * characters outside {@code [0-9a-zA-Z-_.=(),/]} replaced by {@code _}; an empty remainder serves
 * {@code index.html}. The response is {@code 200} with a {@code Content-Type} guessed from the file
 * name. When a rule matched but none of its candidates exists, the answer is {@code 404}. Paths
 * that would leave the directory ({@code ..}, absolute parts, or symbolic links pointing outside)
 * are never served, and get {@code 404} too. Files are read whole for each response.
 */
public final class MapLocal implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(MapLocal.class.getName());
    private static final Pattern UNSAFE = Pattern.compile("[^0-9a-zA-Z\\-_.=(),/]");
    private static final Map<String, String> TYPES = Map.ofEntries(
            Map.entry("html", "text/html"), Map.entry("htm", "text/html"), Map.entry("css", "text/css"),
            Map.entry("js", "text/javascript"), Map.entry("mjs", "text/javascript"),
            Map.entry("json", "application/json"), Map.entry("map", "application/json"),
            Map.entry("txt", "text/plain"), Map.entry("csv", "text/csv"), Map.entry("xml", "application/xml"),
            Map.entry("svg", "image/svg+xml"), Map.entry("png", "image/png"), Map.entry("jpg", "image/jpeg"),
            Map.entry("jpeg", "image/jpeg"), Map.entry("gif", "image/gif"), Map.entry("webp", "image/webp"),
            Map.entry("avif", "image/avif"), Map.entry("ico", "image/x-icon"), Map.entry("woff", "font/woff"),
            Map.entry("woff2", "font/woff2"), Map.entry("ttf", "font/ttf"), Map.entry("otf", "font/otf"),
            Map.entry("pdf", "application/pdf"), Map.entry("wasm", "application/wasm"),
            Map.entry("mp4", "video/mp4"), Map.entry("webm", "video/webm"), Map.entry("mp3", "audio/mpeg"),
            Map.entry("wav", "audio/wav"), Map.entry("zip", "application/zip"), Map.entry("gz", "application/gzip"));

    private final List<Rule> rules;
    private final int maxBodySize;

    private MapLocal(List<Rule> rules, int maxBodySize) {
        this.rules = List.copyOf(rules);
        this.maxBodySize = maxBodySize;
    }

    /**
     * Map local rules from specs.
     *
     * @param specs specs of the form {@code [|flow-filter]|url-regex|file-or-directory}
     * @return the addon
     * @throws IllegalArgumentException if a spec is invalid or its path does not exist
     */
    public static MapLocal of(String... specs) {
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
     * One rule: requests the filter selects whose URL contains a match of {@code pattern} are
     * answered from {@code path}.
     *
     * @param filter the requests the rule applies to
     * @param pattern the regular expression searched for in the URL
     * @param path the file, or the directory files are looked up in (absolute and real)
     */
    public record Rule(FlowFilter filter, Pattern pattern, Path path) {

        /** Checks that every part is present. */
        public Rule {
            Objects.requireNonNull(filter, "filter");
            Objects.requireNonNull(pattern, "pattern");
            Objects.requireNonNull(path, "path");
        }

        /**
         * Parses a spec of the form {@code [|flow-filter]|url-regex|file-or-directory}.
         *
         * @param spec the spec, starting with its separator
         * @return the rule
         * @throws IllegalArgumentException if the spec is invalid or the path does not exist
         */
        public static Rule parse(String spec) {
            Specs.Spec s = Specs.parse(spec, 2, "map_local");
            Path path;
            try {
                path = Path.of(Specs.expandHome(s.parts().get(1))).toRealPath();
            } catch (IOException | InvalidPathException e) {
                throw new IllegalArgumentException("invalid map_local path: " + s.parts().get(1) + " (" + e + ")", e);
            }
            return new Rule(s.filter(), Specs.regex(s.parts().get(0), 0, "map_local"), path);
        }

        /**
         * The files to try for {@code url}, best first, which this rule's pattern matches; empty if
         * the URL names a path outside the directory.
         */
        List<Path> candidates(String url) {
            if (Files.isRegularFile(path)) return List.of(path);
            Matcher m = pattern.matcher(url);
            if (!m.find()) return List.of();
            String suffix;
            if (m.groupCount() > 0 && m.group(1) != null) {
                suffix = m.group(1);
            } else {
                suffix = url.substring(m.end());
                int q = suffix.indexOf('?');
                if (q >= 0) suffix = suffix.substring(0, q);
                suffix = strip(suffix, '/');
            }
            if (suffix.isEmpty()) return List.of(path.resolve("index.html"));
            String decoded;
            try {
                decoded = URLDecoder.decode(suffix.replace("+", "%2B"), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                decoded = suffix;
            }
            List<String> names = new ArrayList<>(List.of(decoded, decoded + "/index.html"));
            String escaped = UNSAFE.matcher(decoded).replaceAll("_");
            if (!escaped.equals(decoded)) {
                names.add(escaped);
                names.add(escaped + "/index.html");
            }
            List<Path> out = new ArrayList<>();
            for (String name : names) {
                Path p = safeJoin(path, name);
                if (p == null) return List.of();
                out.add(p);
            }
            return out;
        }
    }

    /**
     * {@code root} joined with the untrusted relative {@code name}, or null if a part of it is
     * {@code ..} or could escape {@code root} in another way.
     */
    static Path safeJoin(Path root, String name) {
        Path p = root;
        for (String part : name.split("/")) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (part.equals("..") || part.indexOf('\\') >= 0 || part.indexOf('\0') >= 0 || part.indexOf(':') >= 0) {
                return null;
            }
            try {
                p = p.resolve(part);
            } catch (InvalidPathException e) {
                return null;
            }
        }
        p = p.normalize();
        return p.startsWith(root) ? p : null;
    }

    private static String strip(String s, char c) {
        int start = 0;
        int end = s.length();
        while (start < end && s.charAt(start) == c) start++;
        while (end > start && s.charAt(end - 1) == c) end--;
        return s.substring(start, end);
    }

    /** The media type for a file name, or null. */
    static String contentType(Path file) {
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String type = dot < 0 ? null : TYPES.get(name.substring(dot + 1).toLowerCase(Locale.ROOT));
        return type != null ? type : URLConnection.guessContentTypeFromName(name);
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
            String url = Specs.url(r, ctx);
            boolean matched = false;
            List<Path> tried = new ArrayList<>();
            for (Rule rule : rules) {
                if (!rule.filter().matches(flow(null)) || !rule.pattern().matcher(url).find()) continue;
                matched = true;
                List<Path> candidates = rule.candidates(url);
                tried.addAll(candidates);
                for (Path candidate : candidates) {
                    if (!Files.isRegularFile(candidate) || !inside(rule.path(), candidate)) continue;
                    try {
                        return serve(candidate);
                    } catch (IOException e) {
                        LOG.log(Level.WARNING, "map_local: cannot read " + candidate + ": " + e.getMessage());
                    }
                }
            }
            if (!matched) return null;
            if (LOG.isLoggable(Level.DEBUG)) {
                LOG.log(Level.DEBUG, "map_local: no file for " + url + " among " + tried);
            }
            return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND);
        }
    }

    /** Whether {@code file}'s real path is {@code root} or inside it (no link points outside). */
    private static boolean inside(Path root, Path file) {
        if (Files.isRegularFile(root)) return true;
        try {
            return file.toRealPath().startsWith(root);
        } catch (IOException e) {
            return false;
        }
    }

    private static FullHttpResponse serve(Path file) throws IOException {
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                Files.readAllBytes(file));
        String type = contentType(file);
        if (type != null) response.headers().set(HttpHeaderNames.CONTENT_TYPE, type);
        return response;
    }

    /** Builds {@link MapLocal}. */
    public static final class Builder {
        private final List<Rule> rules = new ArrayList<>();
        private int maxBodySize = 10 << 20;

        private Builder() {}

        /**
         * Adds a rule from a spec.
         *
         * @param spec a spec of the form {@code [|flow-filter]|url-regex|file-or-directory}
         * @return this builder
         * @throws IllegalArgumentException if the spec is invalid or its path does not exist
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
        public MapLocal build() {
            return new MapLocal(rules, maxBodySize);
        }
    }
}
