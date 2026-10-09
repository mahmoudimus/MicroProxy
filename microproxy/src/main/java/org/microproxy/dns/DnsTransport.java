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

    byte[] exchange(byte[] query) throws IOException;

    /** UDP to each server in turn, retrying over TCP when a response is truncated. */
    static DnsTransport udp(List<InetSocketAddress> servers, Duration timeout) {
        return new UdpDnsTransport(List.copyOf(servers), (int) Math.max(1, timeout.toMillis()));
    }

    /**
     * DNS over HTTPS (RFC 8484) to a resolver such as {@code https://cloudflare-dns.com/dns-query}
     * or {@code https://dns.google/dns-query}. The connection uses the JVM's default proxy settings.
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
     * The {@code nameserver}s of {@code /etc/resolv.conf}, or Google and Cloudflare public
     * resolvers when that file is unavailable.
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
