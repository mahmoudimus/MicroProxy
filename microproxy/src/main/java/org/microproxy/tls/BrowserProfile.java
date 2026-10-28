package org.microproxy.tls;

import io.github.mahmoudimus.http2.Http2ClientProfile;
import io.github.mahmoudimus.quic.tls.BrowserProfiles;
import io.github.mahmoudimus.quic.tls.CertificateDecompressor;
import io.github.mahmoudimus.quic.tls.ClientHelloProfile;
import io.github.mahmoudimus.quic.tls.FingerprintSslContext;
import io.github.mahmoudimus.quic.tls.ProfileExtensions;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersAdapter;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.thirdparty.jaybrotli.Brotli;
import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.Limits;

/**
 * What one browser looks like to a server, as one thing to give the proxy: its TLS ClientHello,
 * its HTTP/2 connection preface and request framing, its QUIC and HTTP/3 connections ({@link
 * org.microproxy.Http3Options.Builder#upstreamProfile}), and its request headers.
 *
 * <pre>{@code
 * BrowserProfile chrome = BrowserProfile.chrome156();
 * HttpProxyServer proxy = MicroProxy.bootstrap()
 *         .withManInTheMiddle(new CertificateAuthorityMitmManager(ca, chrome.sslContext(null)))
 *         .withFiltersSource(chrome.filtersSource(true))
 *         .start();
 * }</pre>
 *
 * <p>The context's sockets carry the HTTP/2 profile ({@link FingerprintSslContext.Builder#attach}),
 * so HTTP/2 connections over them open as the browser's do without {@link
 * org.microproxy.Http2Options.Builder#upstreamProfile}; different servers can get different
 * browsers by returning different contexts from a {@link org.microproxy.MitmManager}.
 */
public final class BrowserProfile {

    /** The longest certificate chain decompressed (RFC 8879 caps it at 2^24 bytes; real chains are a few KiB). */
    private static final int MAX_CERTIFICATE_CHAIN = 1 << 20;

    private final String name;
    private final ClientHelloProfile tls;
    private final Http2ClientProfile http2;
    private final List<Map.Entry<String, String>> requestHeaders;
    private final io.github.mahmoudimus.quic.QuicClientProfile quic;
    private final io.github.mahmoudimus.http3.Http3ClientProfile http3;

    private BrowserProfile(String name, ClientHelloProfile tls, Http2ClientProfile http2,
            List<Map.Entry<String, String>> requestHeaders, io.github.mahmoudimus.quic.QuicClientProfile quic,
            io.github.mahmoudimus.http3.Http3ClientProfile http3) {
        this.name = name;
        this.tls = tls;
        this.http2 = http2;
        this.requestHeaders = List.copyOf(requestHeaders);
        this.quic = quic;
        this.http3 = http3;
    }

    /**
     * Chrome 156 on macOS, as captured from 156.0.8078.48: {@link BrowserProfiles#chrome156()},
     * {@link Http2ClientProfile#chrome156()}, and the headers of a navigation, in Chrome's order.
     * The capture was of headless Chrome, whose User-Agent says {@code HeadlessChrome}; the
     * profile's says {@code Chrome}, as a browser window's does.
     *
     * @return the profile
     */
    public static BrowserProfile chrome156() {
        return new BrowserProfile("chrome-156", BrowserProfiles.chrome156(), Http2ClientProfile.chrome156(), List.of(
                Map.entry("sec-ch-ua", "\"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"156\", \"Google Chrome\";v=\"156\""),
                Map.entry("sec-ch-ua-mobile", "?0"),
                Map.entry("sec-ch-ua-platform", "\"macOS\""),
                Map.entry("upgrade-insecure-requests", "1"),
                Map.entry("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                        + "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"),
                Map.entry("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,"
                        + "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                Map.entry("sec-fetch-site", "none"),
                Map.entry("sec-fetch-mode", "navigate"),
                Map.entry("sec-fetch-user", "?1"),
                Map.entry("sec-fetch-dest", "document"),
                Map.entry("accept-encoding", "gzip, deflate, br, zstd"),
                Map.entry("accept-language", "en-US,en;q=0.9"),
                Map.entry("priority", "u=0, i")),
                io.github.mahmoudimus.quic.QuicClientProfile.chrome156(),
                io.github.mahmoudimus.http3.Http3ClientProfile.chrome156());
    }

    /** {@return the profile's name, such as {@code chrome-156}} */
    public String name() {
        return name;
    }

    /** {@return the TLS ClientHello profile} */
    public ClientHelloProfile tlsProfile() {
        return tls;
    }

    /** {@return the HTTP/2 profile} */
    public Http2ClientProfile http2Profile() {
        return http2;
    }

    /** {@return the QUIC client profile: its QUIC hello, transport parameters and Initial packets} */
    public io.github.mahmoudimus.quic.QuicClientProfile quicProfile() {
        return quic;
    }

    /** {@return the HTTP/3 profile} */
    public io.github.mahmoudimus.http3.Http3ClientProfile http3Profile() {
        return http3;
    }

    /** {@return the browser's request headers, in its order} */
    public List<Map.Entry<String, String>> requestHeaders() {
        return requestHeaders;
    }

    /**
     * A client context with the browser's TLS fingerprint, whose sockets carry its HTTP/2 profile,
     * that decompresses certificates with Brotli, zlib and (when the {@code zstd-decoder} module is
     * on the class path) zstd.
     *
     * @param trustManager the servers to trust, or null for the JDK's default trust store
     * @return the context
     */
    public SSLContext sslContext(X509TrustManager trustManager) {
        return sslContext(trustManager, null);
    }

    /**
     * {@link #sslContext(X509TrustManager)}, encrypting the ClientHello (RFC 9849) to servers whose
     * ECHConfigList {@code ech} gives; to the others, and with {@code ech} null, the browser's
     * GREASE ECH alone, as a browser sends when it has no ECHConfig. No DNS lookups are made here:
     * {@code ech} decides where configs come from (such as the server's DNS HTTPS record, from the
     * resolver the deployment trusts).
     *
     * @param trustManager the servers to trust, or null for the JDK's default trust store
     * @param ech the source of servers' ECHConfigLists, or null for none
     * @return the context
     */
    public SSLContext sslContext(X509TrustManager trustManager, io.github.mahmoudimus.quic.tls.EchConfigProvider ech) {
        X509TrustManager trust = trustManager;
        if (trust == null) {
            try {
                trust = SslContexts.defaultTrustManager();
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException("no default trust manager", e);
            }
        }
        SSLContext context = FingerprintSslContext.builder(tls)
                .trustManager(trust)
                .certificateDecompressor(certificateDecompressor())
                .attach(http2)
                .echConfigProvider(ech)
                .build();
        // so that what needs the trust behind a context (HTTP/3 to servers, name checks) finds it
        SslContexts.remember(context, trust);
        return context;
    }

    /**
     * Decompresses certificate chains (RFC 8879) with Brotli, zlib and, when the {@code zstd-decoder}
     * module is on the class path, zstd; each bounded to 1 MiB of output.
     *
     * @return the decompressor
     */
    public static CertificateDecompressor certificateDecompressor() {
        CertificateDecompressor brotli = (algorithm, data, length) -> {
            if (algorithm != ProfileExtensions.BROTLI) return null;
            if (length > MAX_CERTIFICATE_CHAIN) throw new IOException("a certificate chain of " + length + " bytes");
            try {
                return Brotli.decompress(data, DecoderOptions.defaults().withLimits(Limits.defaults().withMaxTotalOutput(length)));
            } catch (Exception e) {
                throw new IOException("Brotli certificate does not decompress: " + e.getMessage(), e);
            }
        };
        CertificateDecompressor all = brotli.or(CertificateDecompressor.ZLIB);
        return Zstd.AVAILABLE ? all.or(Zstd::decompress) : all;
    }

    /** zstd, used only when the optional {@code zstd-decoder} module is on the class path. */
    private static final class Zstd {
        static final boolean AVAILABLE = available();

        private static boolean available() {
            try {
                Class.forName("io.github.mahmoudimus.zstd.ZstdDecompressor");
                return true;
            } catch (ClassNotFoundException e) {
                return false;
            }
        }

        static byte[] decompress(int algorithm, byte[] data, int length) throws IOException {
            if (algorithm != ProfileExtensions.ZSTD) return null;
            if (length > MAX_CERTIFICATE_CHAIN) throw new IOException("a certificate chain of " + length + " bytes");
            try {
                return io.github.mahmoudimus.zstd.ZstdDecompressor.create().decompress(data, length);
            } catch (Exception e) {
                throw new IOException("zstd certificate does not decompress: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Gives a request the browser's headers, in the browser's order:
     * <ul>
     *   <li>the browser's {@code user-agent} in place of the client's when {@code replaceUserAgent}
     *       is set, or when the client sent none;</li>
     *   <li>the browser's headers the client did not send, except {@code accept-encoding}, since
     *       a client that did not ask for an encoding could not read a body in it;</li>
     *   <li>no {@code via}, which says a proxy is there.</li>
     * </ul>
     * The headers the browser sends come first, in its order; the client's others follow in theirs.
     *
     * @param headers the request's headers, changed in place
     * @param replaceUserAgent whether the browser's User-Agent replaces the client's
     */
    public void applyHeaders(HttpHeaders headers, boolean replaceUserAgent) {
        Objects.requireNonNull(headers, "headers");
        headers.remove(HttpHeaderNames.VIA);
        List<Map.Entry<String, String>> original = new ArrayList<>(headers.entries());
        List<Map.Entry<String, String>> out = new ArrayList<>(original.size() + requestHeaders.size());
        for (Map.Entry<String, String> browser : requestHeaders) {
            String name = browser.getKey();
            boolean sent = original.stream().anyMatch(e -> e.getKey().equalsIgnoreCase(name));
            boolean userAgent = name.equals("user-agent");
            if (sent && !(userAgent && replaceUserAgent)) {
                for (Map.Entry<String, String> e : original) {
                    if (e.getKey().equalsIgnoreCase(name)) out.add(e);
                }
            } else if (!name.equals("accept-encoding")) {
                out.add(browser);
            }
        }
        for (Map.Entry<String, String> e : original) {
            boolean browsers = requestHeaders.stream().anyMatch(b -> b.getKey().equalsIgnoreCase(e.getKey()));
            if (!browsers) out.add(e);
        }
        headers.clear();
        for (Map.Entry<String, String> e : out) headers.add(e.getKey(), e.getValue());
    }

    /**
     * Filters that {@link #applyHeaders apply the browser's headers} to every request on its way
     * to the server.
     *
     * @param replaceUserAgent whether the browser's User-Agent replaces the client's
     * @return the filters' source
     */
    public HttpFiltersSource filtersSource(boolean replaceUserAgent) {
        return new HttpFiltersSource() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
                return new HttpFiltersAdapter(originalRequest, flowContext) {
                    @Override
                    public HttpResponse proxyToServerRequest(HttpObject httpObject) {
                        if (httpObject instanceof HttpRequest request) applyHeaders(request.headers(), replaceUserAgent);
                        return null;
                    }
                };
            }
        };
    }

    @Override
    public String toString() {
        return "BrowserProfile[" + name + "]";
    }
}
