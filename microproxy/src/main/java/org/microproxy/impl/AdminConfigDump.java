package org.microproxy.impl;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.microproxy.ActivityTracker;
import org.microproxy.FlowTracer;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.stats.StatsRegistry;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * The admin listener's {@code /config_dump} and {@code /server_info}'s command line: the
 * configuration a proxy runs with, as JSON, with every secret replaced by {@value #REDACTED}: key
 * store passwords, the admin token, proxy authentication credentials (the authenticator's and
 * chained proxies'), and the interception CA's private key. Objects the proxy was given (filters,
 * trackers, resolvers) show as their class names, never their contents.
 */
final class AdminConfigDump {

    static final String REDACTED = "[redacted]";
    /** The user information of a URL: {@code //user:password@}. */
    private static final Pattern USER_INFO = Pattern.compile("//[^@/\\s]*@");
    /** Command-line options whose values are secrets. */
    private static final Pattern SECRET_OPTION = Pattern.compile("(?i).*(password|token|secret|credential).*");

    private AdminConfigDump() {}

    /** {@code s} without the user information of the URLs in it. */
    static String redactUrls(String s) {
        return s == null ? null : USER_INFO.matcher(s).replaceAll("//" + REDACTED + "@");
    }

    /** {@return {@code server}'s configuration, as Envoy's {@code /config_dump} gives its own: a list of typed parts} */
    static Map<String, Object> dump(DefaultHttpProxyServer server, InetSocketAddress adminAddress) {
        DefaultHttpProxyServerBootstrap b = server.config;
        Map<String, Object> boot = new LinkedHashMap<>();
        boot.put("name", b.name);
        boot.put("address", AdminServer.hostPort(server.getListenAddress()));
        boot.put("mode", b.reverseProxy != null ? "reverse" : b.socksServer ? "socks5" : b.transparent ? "transparent" : "regular");
        boot.put("reverse_proxy", b.reverseProxy == null ? null : b.reverseProxy.toString());
        boot.put("keep_host_header", b.keepHostHeader);
        boot.put("transparent", b.transparent);
        boot.put("transparent_tls_port", b.transparentTlsPort);
        boot.put("transparent_quic_port", b.transparentQuicPort < 0 ? null : b.transparentQuicPort);
        boot.put("socks", Map.of("server", b.socksServer, "detection", b.socksDetection));
        Map<String, Object> hosts = new LinkedHashMap<>();
        hosts.put("ignore", b.ignoreHosts);
        hosts.put("allow", b.allowHosts);
        hosts.put("tcp", b.tcpHosts);
        hosts.put("quic", b.quicHosts);
        boot.put("hosts", hosts);
        Map<String, Object> timeouts = new LinkedHashMap<>();
        timeouts.put("idle_connection", duration(server.getIdleConnectionTimeout()));
        timeouts.put("connect", duration(Duration.ofMillis(server.getConnectTimeout())));
        timeouts.put("tls_handshake", duration(b.tlsHandshakeTimeout));
        boot.put("timeouts", timeouts);
        boot.put("tls_protocols", b.tlsProtocols);
        boot.put("tls_retry_without_sni", b.retriesTlsWithoutSni());
        Map<String, Object> policies = new LinkedHashMap<>();
        for (int version = 1; version <= 3; version++) {
            org.microproxy.ProtocolPolicy p = b.effectivePolicy(version);
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("resolve_before_proxy_to_server_request", p.resolveBeforeProxyToServerRequest().orElse(null));
            fields.put("filter_connect_answer", p.filterConnectAnswer().orElse(null));
            fields.put("serve_plain_http_after_connect", p.servePlainHttpAfterConnect().orElse(null));
            fields.put("proxy_protocol_destination", p.proxyProtocolDestination()
                    .map(d -> d.name().toLowerCase(java.util.Locale.ROOT)).orElse(null));
            fields.put("tls_retry_without_sni", p.tlsRetryWithoutSni().orElse(null));
            fields.put("generated_responses", p.generatedResponses().map(v -> v.name().toLowerCase(java.util.Locale.ROOT)).orElse(null));
            fields.put("mitm_server_handshake", p.mitmServerHandshake()
                    .map(v -> v.name().toLowerCase(java.util.Locale.ROOT)).orElse(null));
            if (version == 1) fields.put("allow_chunked_length", p.allowChunkedLength().orElse(false));
            policies.put("http" + version, fields);
        }
        boot.put("protocol_policies", policies);
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("max_initial_line_length", b.maxInitialLineLength);
        limits.put("max_header_size", b.maxHeaderSize);
        limits.put("max_chunk_size", b.maxChunkSize);
        limits.put("max_websocket_frame_buffer_size", b.maxWebSocketFrameBufferSize);
        limits.put("max_websocket_message_size", b.maxWebSocketMessageSize);
        boot.put("limits", limits);
        boot.put("network_interface", AdminServer.hostPort(b.localAddress));
        boot.put("proxy_alias", server.proxyAlias);
        boot.put("allow_requests_to_origin_server", b.allowRequestToOriginServer);
        boot.put("allow_chunked_length", b.allowChunkedLength);
        boot.put("originate_tls", b.tlsOrigination);
        boot.put("littleproxy_compatibility", b.littleProxyCompatibility);
        Map<String, Object> proxyProtocol = new LinkedHashMap<>();
        proxyProtocol.put("accept", b.proxyProtocolMode != org.microproxy.ProxyProtocolMode.OFF);
        proxyProtocol.put("mode", b.proxyProtocolMode.name().toLowerCase(java.util.Locale.ROOT));
        proxyProtocol.put("trusted_sources", b.proxyProtocolTrustedSources.entries());
        proxyProtocol.put("send", b.sendProxyProtocol);
        boot.put("proxy_protocol", proxyProtocol);
        boot.put("throttle", Map.of("read_bytes_per_second", server.readLimiter.rate(),
                "write_bytes_per_second", server.writeLimiter.rate()));
        Map<String, Object> pool = new LinkedHashMap<>();
        pool.put("shared", b.sharedServerConnectionPool);
        pool.put("type", b.serverConnectionPoolType.name());
        pool.put("max_connections_per_host", b.maxConnectionsPerHost);
        pool.put("max_connections", b.maxConnections);
        pool.put("idle_timeout", duration(b.poolIdleTimeout));
        pool.put("shared_mitm_connections", b.poolSharedMitmConnections);
        pool.put("per_request_in_mitm", b.poolPerRequestInMitm);
        boot.put("connection_pool", pool);
        Map<String, Object> chained = null;
        if (b.chainProxyManager != null) {
            chained = new LinkedHashMap<>();
            chained.put("manager", b.chainProxyManager.getClass().getName());
            // UpstreamProxyManager says which proxies, credentials masked; a custom manager's
            // toString is its own, so only its class shows.
            if (b.chainProxyManager instanceof org.microproxy.UpstreamProxyManager) {
                chained.put("proxies", redactUrls(b.chainProxyManager.toString()).replace("***@", REDACTED + "@"));
            }
            boolean backoff = !b.chainedProxyBackoff.isNone();
            chained.put("backoff_initial", backoff ? duration(b.chainedProxyBackoff.initial()) : null);
            chained.put("backoff_max", backoff ? duration(b.chainedProxyBackoff.max()) : null);
            chained.put("backoff_jitter", backoff ? b.chainedProxyBackoff.jittered() : null);
            // "default": the connect timeout, at most 30 s.
            chained.put("backoff_budget", !backoff ? null : b.chainedProxyBackoff.isUnbudgeted() ? "unlimited"
                    : b.chainedProxyBackoff.budget().map(AdminConfigDump::duration).orElse("default"));
        }
        boot.put("chained_proxy", chained);
        boot.put("stripped_request_headers", List.copyOf(b.strippedRequestHeaders.values()));
        boot.put("strip_alt_svc_h3", b.stripsAltSvcH3());
        Map<String, Object> h2 = new LinkedHashMap<>();
        // In effect: on by default with the codec, off without it.
        h2.put("downstream", b.offersHttp2());
        h2.put("upstream", b.offersHttp2Upstream());
        h2.put("cleartext", b.http2Cleartext || b.http2CleartextOnly);
        h2.put("cleartext_only", b.http2CleartextOnly);
        h2.put("options", b.http2Options.toString());
        boot.put("http2", h2);
        Map<String, Object> h3 = new LinkedHashMap<>();
        h3.put("downstream", b.http3);
        h3.put("upstream", b.http3Upstream);
        h3.put("upstream_hosts", b.http3UpstreamHosts);
        h3.put("options", b.http3Options.toString());
        boot.put("http3", h3);
        Map<String, Object> tls = null;
        if (b.sslContextSource != null) {
            tls = new LinkedHashMap<>();
            tls.put("source", b.sslContextSource.getClass().getName());
            tls.put("authenticate_clients", b.authenticateSslClients);
            tls.put("key_store_password", REDACTED);
        }
        boot.put("listener_tls", tls);
        Map<String, Object> auth = null;
        if (b.proxyAuthenticator != null) {
            auth = new LinkedHashMap<>();
            auth.put("authenticator", b.proxyAuthenticator.getClass().getName());
            auth.put("realm", b.proxyAuthenticator.getRealm());
            auth.put("credentials", REDACTED);
        }
        boot.put("proxy_authentication", auth);
        Map<String, Object> mitm = null;
        if (b.mitmManager != null) {
            mitm = new LinkedHashMap<>();
            mitm.put("manager", b.mitmManager.getClass().getName());
            if (b.mitmManager instanceof CertificateAuthorityMitmManager ca) {
                X509Certificate cert = ca.getCertificateAuthority().getCertificate();
                mitm.put("ca_subject", cert.getSubjectX500Principal().getName());
                mitm.put("ca_not_after", cert.getNotAfter().toInstant().toString());
                mitm.put("ca_private_key", REDACTED);
                mitm.put("ca_key_store_password", REDACTED);
            }
        }
        boot.put("mitm", mitm);
        boot.put("filters", filters(server.filtersSource));
        List<String> trackers = new ArrayList<>();
        for (ActivityTracker t : b.activityTrackers) trackers.add(t.getClass().getName());
        boot.put("activity_trackers", trackers);
        boot.put("tracer", b.tracer == FlowTracer.NOOP ? null : b.tracer.getClass().getName());
        boot.put("cache", b.httpCache == null ? null : b.httpCache.getClass().getName());
        boot.put("server_resolver", b.serverResolver.getClass().getName());
        Map<String, Object> hooks = new LinkedHashMap<>();
        hooks.put("frame", className(b.frameInterceptor));
        hooks.put("tcp", className(b.tcpInterceptor));
        hooks.put("udp", className(b.udpInterceptor));
        hooks.put("quic", className(b.quicInterceptor));
        boot.put("interceptors", hooks);
        StatsRegistry registry = server.stats.registry;
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("enabled", registry.enabled());
        stats.put("prefix", registry.prefix());
        stats.put("max_clusters", registry.maxClusters());
        stats.put("cluster_overflow", registry.clusterOverflow().name());
        stats.put("per_host_clusters", registry.perHostClusters());
        boot.put("stats", stats);
        boot.put("drain", Map.of("time", duration(b.drainTime), "strategy", b.drainStrategy.name().toLowerCase(Locale.ROOT)));
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("path", b.healthCheckPath);
        health.put("pass_through", b.healthCheckPassThrough);
        boot.put("health_check", health);

        Map<String, Object> admin = new LinkedHashMap<>();
        admin.put("address", AdminServer.hostPort(adminAddress));
        admin.put("token", b.adminToken == null ? null : REDACTED);

        Map<String, Object> bootstrapPart = new LinkedHashMap<>();
        bootstrapPart.put("@type", "type.microproxy/BootstrapConfigDump");
        bootstrapPart.put("bootstrap", boot);
        Map<String, Object> adminPart = new LinkedHashMap<>();
        adminPart.put("@type", "type.microproxy/AdminConfigDump");
        adminPart.put("admin", admin);
        Map<String, Object> commandLinePart = new LinkedHashMap<>();
        commandLinePart.put("@type", "type.microproxy/CommandLineConfigDump");
        commandLinePart.put("command_line_options", commandLine(b.commandLineOptions));
        return Map.of("configs", List.of(bootstrapPart, adminPart, commandLinePart));
    }

    private static String duration(Duration d) {
        return d == null ? null : d.toString();
    }

    private static String className(Object o) {
        return o == null ? null : o.getClass().getName();
    }

    /** The filters sources, by class name, chains flattened, in order. */
    private static List<String> filters(HttpFiltersSource source) {
        List<String> names = new ArrayList<>();
        addFilters(source, names);
        return names;
    }

    private static void addFilters(HttpFiltersSource source, List<String> names) {
        if (source == null) return;
        if (source instanceof HttpFiltersChain chain) {
            for (HttpFiltersSource s : chain.sources()) addFilters(s, names);
        } else if (source.getClass() != org.microproxy.HttpFiltersSourceAdapter.class) {
            names.add(source.getClass().getName());
        }
    }

    /**
     * A command line as an object, Envoy's way: each {@code --option} with its value, its values
     * (a list) or {@code true} for a flag, repeated options as lists; values of options named for
     * secrets (passwords, tokens, credentials) redacted, as are the values of {@code --script-var}
     * ({@code NAME=[redacted]}) and the user information of URLs.
     */
    static Map<String, Object> commandLine(List<String> args) {
        Map<String, List<Object>> occurrences = new LinkedHashMap<>();
        List<String> loose = new ArrayList<>();
        int i = 0;
        while (i < args.size()) {
            String option = args.get(i++);
            if (!option.startsWith("-")) {
                loose.add(redactUrls(option));
                continue;
            }
            List<String> values = new ArrayList<>();
            while (i < args.size() && !args.get(i).startsWith("--")) values.add(redactValue(option, args.get(i++)));
            Object value = values.isEmpty() ? Boolean.TRUE : values.size() == 1 ? values.getFirst() : values;
            occurrences.computeIfAbsent(option, k -> new ArrayList<>()).add(value);
        }
        Map<String, Object> options = new LinkedHashMap<>();
        occurrences.forEach((option, values) -> options.put(option, values.size() == 1 ? values.getFirst() : values));
        if (!loose.isEmpty()) options.put("arguments", loose);
        return options;
    }

    private static String redactValue(String option, String value) {
        if (SECRET_OPTION.matcher(option).matches()) return REDACTED;
        if (option.equals("--script-var")) {
            int eq = value.indexOf('=');
            return eq < 0 ? REDACTED : value.substring(0, eq + 1) + REDACTED;
        }
        return redactUrls(value);
    }
}
