/*
 * Ported from mitmproxy's mitmproxy/addons/stickycookie.py (https://github.com/mitmproxy/mitmproxy),
 * Copyright (c) 2013, Aldo Cortesi. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy.txt. MicroProxy changes: the jar follows RFC 6265 for Domain, Path,
 * Max-Age, Expires and Secure, and keeps the cookies a client sends itself.
 */
package org.microproxy.extras;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Remembers the cookies servers set and sends them with later requests, as mitmproxy's {@code
 * stickycookie}, so that a session started in one client carries over to others (a browser and a
 * command-line tool, or replayed requests).
 *
 * <pre>{@code
 * bootstrap.plusFiltersSource(StickyCookie.matching(FlowFilter.parse("~d example.com")));
 * }</pre>
 *
 * <p>Every {@code Set-Cookie} from a server goes into one jar shared by all clients, following RFC
 * 6265: a {@code Domain} attribute must cover the server's host (else the cookie is ignored) and
 * makes the cookie apply to its subdomains too, otherwise it applies to that host only; {@code
 * Path} defaults to the directory of the request path; {@code Max-Age} wins over {@code Expires},
 * and a cookie set to expire is removed from the jar; {@code Secure} cookies only go to {@code
 * https} URLs. Requests the filter matches get the jar's unexpired cookies for their host and
 * path, longest paths first, added to their {@code Cookie} header; a cookie the client sends
 * itself is kept rather than overridden. Ports are not told apart, as RFC 6265 says (mitmproxy
 * does). Domains are not checked against the public suffix list, beyond refusing a {@code Domain}
 * with no dot. Reads heads only.
 */
public final class StickyCookie implements HttpFiltersSource {

    private final FlowFilter filter;
    private final Clock clock;
    private final ReentrantLock lock = new ReentrantLock();
    /** Cookies by (domain, path, name), in the order they were first set. */
    private final Map<Key, Stored> jar = new LinkedHashMap<>();

    private StickyCookie(FlowFilter filter, Clock clock) {
        this.filter = Objects.requireNonNull(filter, "filter");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Sticky cookies for the requests {@code filter} matches (body matchers do not match).
     *
     * @param filter the requests that get remembered cookies
     * @return the addon
     */
    public static StickyCookie matching(FlowFilter filter) {
        return new StickyCookie(filter, Clock.systemUTC());
    }

    /**
     * Sticky cookies for the requests the expression matches, as {@code --stickycookie} takes it.
     *
     * @param filterExpression a flow filter expression
     * @return the addon
     * @throws IllegalArgumentException if the expression is invalid
     */
    public static StickyCookie of(String filterExpression) {
        return matching(FlowFilter.parse(filterExpression));
    }

    /** For tests: a jar that reads the time from {@code clock}. */
    static StickyCookie matching(FlowFilter filter, Clock clock) {
        return new StickyCookie(filter, clock);
    }

    private record Key(String domain, String path, String name) {}

    private record Stored(String value, boolean hostOnly, boolean secure, Instant expiry) {}

    /**
     * The cookies the jar holds and has not seen expire, as {@code name=value} strings by {@code
     * domain path}; for inspection.
     *
     * @return a snapshot of the jar
     */
    public Map<String, List<String>> cookies() {
        Instant now = clock.instant();
        Map<String, List<String>> out = new LinkedHashMap<>();
        lock.lock();
        try {
            for (Map.Entry<Key, Stored> e : jar.entrySet()) {
                if (expired(e.getValue(), now)) continue;
                out.computeIfAbsent(e.getKey().domain + " " + e.getKey().path, k -> new ArrayList<>())
                        .add(e.getKey().name + "=" + e.getValue().value);
            }
        } finally {
            lock.unlock();
        }
        return out;
    }

    private static boolean expired(Stored s, Instant now) {
        return s.expiry != null && !s.expiry.isAfter(now);
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new AddonFilters(originalRequest, flowContext) {
            @Override
            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                if (httpObject instanceof HttpRequest r) {
                    request = r;
                    if (filter == FlowFilter.ALL || filter.matches(flow(null))) addCookies(r, Specs.url(r, ctx));
                }
                return null;
            }

            @Override
            public HttpObject serverToProxyResponse(HttpObject httpObject) {
                if (httpObject instanceof HttpResponse r) remember(Specs.url(request, ctx), r);
                return httpObject;
            }
        };
    }

    /** Stores the response's cookies set for {@code url}. */
    void remember(String url, HttpResponse response) {
        List<String> headers = response.headers().getAll("Set-Cookie");
        if (headers.isEmpty()) return;
        String host = FlowFilter.urlHost(url);
        String path = path(url);
        Instant now = clock.instant();
        lock.lock();
        try {
            for (String header : headers) {
                Cookies.SetCookie c = Cookies.parseSetCookie(header);
                if (c == null) continue;
                String domainAttr = c.attribute("domain");
                boolean hostOnly = domainAttr == null || domainAttr.isBlank();
                String domain = host;
                if (!hostOnly) {
                    domain = domainAttr.strip().toLowerCase(Locale.ROOT);
                    if (domain.startsWith(".")) domain = domain.substring(1);
                    // The domain must cover the server, and be more than a top-level name.
                    if (!Cookies.domainMatches(host, domain) || (domain.indexOf('.') < 0 && !domain.equals(host))) {
                        continue;
                    }
                    if (domain.equals(host)) hostOnly = Cookies.isIpAddress(host);
                }
                String pathAttr = c.attribute("path");
                String cookiePath = pathAttr == null || !pathAttr.startsWith("/") ? Cookies.defaultPath(path) : pathAttr;
                Key key = new Key(domain, cookiePath, c.name());
                Instant expiry = Cookies.expiry(c, now);
                if (expiry != null && !expiry.isAfter(now)) {
                    jar.remove(key);
                } else {
                    jar.put(key, new Stored(c.value(), hostOnly, c.attributes().containsKey("secure"), expiry));
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /** Adds the jar's cookies for {@code url} to {@code request}, keeping the client's own. */
    void addCookies(HttpRequest request, String url) {
        String host = FlowFilter.urlHost(url);
        String path = path(url);
        boolean secure = Specs.scheme(url).equals("https");
        Instant now = clock.instant();
        List<Map.Entry<Key, Stored>> matching = new ArrayList<>();
        lock.lock();
        try {
            for (Iterator<Map.Entry<Key, Stored>> it = jar.entrySet().iterator(); it.hasNext(); ) {
                Map.Entry<Key, Stored> e = it.next();
                Key k = e.getKey();
                Stored s = e.getValue();
                if (expired(s, now)) {
                    it.remove();
                    continue;
                }
                boolean domainOk = s.hostOnly ? host.equals(k.domain) : Cookies.domainMatches(host, k.domain);
                if (domainOk && Cookies.pathMatches(path, k.path) && (secure || !s.secure)) matching.add(e);
            }
        } finally {
            lock.unlock();
        }
        if (matching.isEmpty()) return;
        // RFC 6265 5.4: longer paths first; otherwise in the order they were set.
        matching.sort(Comparator.comparingInt((Map.Entry<Key, Stored> e) -> -e.getKey().path.length()));
        List<String> existing = request.headers().getAll("Cookie");
        Set<String> sent = new HashSet<>();
        for (String header : existing) {
            for (Map.Entry<String, String> pair : Cookies.parseCookieHeader(header)) sent.add(pair.getKey());
        }
        StringBuilder cookie = new StringBuilder(String.join("; ", existing));
        for (Map.Entry<Key, Stored> e : matching) {
            if (!sent.add(e.getKey().name)) continue;
            if (!cookie.isEmpty()) cookie.append("; ");
            cookie.append(e.getKey().name).append('=').append(e.getValue().value);
        }
        request.headers().set("Cookie", cookie.toString());
    }

    /** The path of an absolute URL, without query or fragment. */
    private static String path(String url) {
        int start = url.indexOf("://");
        start = start < 0 ? 0 : url.indexOf('/', start + 3);
        if (start < 0) return "/";
        int end = start;
        while (end < url.length() && url.charAt(end) != '?' && url.charAt(end) != '#') end++;
        return url.substring(start, end);
    }
}
