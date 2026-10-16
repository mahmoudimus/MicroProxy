package org.microproxy.dns;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Sends a DNS query message to a recursive resolver and returns the raw response. The resolver
 * only needs to pass DNSSEC records through; all validation happens locally.
 */
@FunctionalInterface
public interface DnsTransport {

    /**
     * Sends a wire-format DNS query and reads its response.
     *
     * @param query the wire-format DNS query message
     * @return the wire-format DNS response
     * @throws IOException if the query fails or no DNS response can be read
     */
    byte[] exchange(byte[] query) throws IOException;

    /**
     * UDP to each server in turn, retrying over TCP when a response is truncated.
     *
     * @param servers the recursive DNS server addresses
     * @param timeout the per-attempt UDP/TCP query timeout
     * @return the UDP transport with TCP fallback
     */
    static DnsTransport udp(List<InetSocketAddress> servers, Duration timeout) {
        return new UdpDnsTransport(List.copyOf(servers), (int) Math.max(1, timeout.toMillis()));
    }

    /**
     * DNS over HTTPS (RFC 8484) to a resolver such as {@code https://cloudflare-dns.com/dns-query}
     * or {@code https://dns.google/dns-query}. The connection uses the JVM's default proxy settings.
     *
     * @param endpoint the DNS-over-HTTPS endpoint
     * @param timeout the HTTP connection and query timeout
     * @return the DNS-over-HTTPS transport
     */
    static DnsTransport https(URI endpoint, Duration timeout) {
        java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(timeout)
                .proxy(ProxySelector.getDefault() != null
                        ? ProxySelector.getDefault() : java.net.http.HttpClient.Builder.NO_PROXY)
                .build();
        return query -> {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(endpoint)
                    .timeout(timeout)
                    .header("Content-Type", "application/dns-message")
                    .header("Accept", "application/dns-message")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(query))
                    .build();
            try {
                java.net.http.HttpResponse<byte[]> response =
                        client.send(request, java.net.http.HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() != 200) {
                    throw new IOException("DoH server returned HTTP " + response.statusCode());
                }
                return response.body();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted during DoH query");
            }
        };
    }

    /**
     * Each of {@code transports} in turn: a query that fails with an {@link IOException} (a
     * resolver that cannot be reached, times out or answers with an HTTP error) is sent to the
     * next, and only when every one has failed does the query fail, with the last failure and the
     * earlier ones suppressed in it. Each query starts at the transport that answered last, so a
     * resolver that is down costs its timeout once rather than on every query; one that answers
     * again is used again once the others fail. Responses are validated locally either way, so
     * mixing resolvers within a lookup is safe.
     *
     * @param transports the transports to try, in order; at least one
     * @return the failover transport
     */
    static DnsTransport failover(List<DnsTransport> transports) {
        List<DnsTransport> all = List.copyOf(transports);
        if (all.isEmpty()) throw new IllegalArgumentException("no transports");
        if (all.size() == 1) return all.get(0);
        java.util.concurrent.atomic.AtomicInteger preferred = new java.util.concurrent.atomic.AtomicInteger();
        return query -> {
            int start = preferred.get();
            IOException failure = null;
            for (int i = 0; i < all.size(); i++) {
                int index = (start + i) % all.size();
                try {
                    byte[] response = all.get(index).exchange(query);
                    preferred.set(index);
                    return response;
                } catch (InterruptedIOException e) {
                    throw e;
                } catch (IOException e) {
                    if (failure != null) e.addSuppressed(failure);
                    failure = e;
                }
            }
            throw failure;
        };
    }

    /**
     * The {@code nameserver}s of {@code /etc/resolv.conf}, or Google and Cloudflare public
     * resolvers when that file is unavailable.
     *
     * @return the {@code nameserver}s of {@code /etc/resolv.conf}, or Google and Cloudflare public resolvers when that file is unavailable
     */
    static List<InetSocketAddress> systemServers() {
        List<InetSocketAddress> servers = new ArrayList<>();
        Path resolvConf = Path.of("/etc/resolv.conf");
        try {
            if (Files.isReadable(resolvConf)) {
                for (String line : Files.readAllLines(resolvConf)) {
                    String[] parts = line.strip().split("\\s+");
                    if (parts.length >= 2 && parts[0].equals("nameserver")) {
                        servers.add(new InetSocketAddress(InetAddress.getByName(parts[1]), 53));
                    }
                }
            }
        } catch (IOException ignored) {
            // fall through to defaults
        }
        if (servers.isEmpty()) {
            try {
                servers.add(new InetSocketAddress(InetAddress.getByAddress(new byte[] {8, 8, 8, 8}), 53));
                servers.add(new InetSocketAddress(InetAddress.getByAddress(new byte[] {1, 1, 1, 1}), 53));
            } catch (UnknownHostException e) {
                throw new IllegalStateException(e);
            }
        }
        return servers;
    }
}
