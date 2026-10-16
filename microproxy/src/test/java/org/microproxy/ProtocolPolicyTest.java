package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.time.Duration;
import java.util.Optional;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.microproxy.impl.BootstrapView;

/**
 * {@link ProtocolPolicy}: its presets, how its builders and layers combine, and how the
 * bootstrap, a properties file and the command line configure it.
 */
class ProtocolPolicyTest {

    private static ProtocolPolicy policy(HttpProxyServerBootstrap bootstrap, int version) {
        return BootstrapView.protocolPolicy(bootstrap, version);
    }

    private static HttpProxyServerBootstrap parse(String... args) throws IOException {
        return Launcher.parse(args, new PrintStream(OutputStream.nullOutputStream())).bootstrap();
    }

    @Test
    void thePresetsSetEveryField() {
        ProtocolPolicy defaults = ProtocolPolicy.defaults();
        assertEquals(Optional.of(false), defaults.resolveBeforeProxyToServerRequest());
        assertEquals(Optional.of(true), defaults.filterConnectAnswer());
        assertEquals(Optional.of(true), defaults.servePlainHttpAfterConnect());
        assertEquals(Optional.of(ProxyProtocolDestination.LOCAL_ADDRESS), defaults.proxyProtocolDestination());
        assertEquals(Optional.of(false), defaults.tlsRetryWithoutSni());
        assertEquals(Optional.of(Duration.ofSeconds(30)), defaults.requestHeadTimeout());
        assertEquals(Optional.empty(), defaults.allowChunkedLength(), "decided by withAllowChunkedLength");
        assertEquals(Optional.of(GeneratedResponses.REPLACEABLE), defaults.generatedResponses());
        assertEquals(Optional.of(MitmServerHandshake.DEFERRED), defaults.mitmServerHandshake());

        ProtocolPolicy littleProxy = ProtocolPolicy.littleProxy();
        assertEquals(Optional.of(true), littleProxy.resolveBeforeProxyToServerRequest());
        assertEquals(Optional.of(false), littleProxy.filterConnectAnswer());
        assertEquals(Optional.of(false), littleProxy.servePlainHttpAfterConnect());
        assertEquals(Optional.of(ProxyProtocolDestination.SERVER_ADDRESS), littleProxy.proxyProtocolDestination());
        assertEquals(Optional.of(true), littleProxy.tlsRetryWithoutSni());
        assertEquals(Optional.of(Duration.ofSeconds(30)), littleProxy.requestHeadTimeout());
        assertEquals(Optional.empty(), littleProxy.allowChunkedLength());
        assertEquals(Optional.of(GeneratedResponses.REPLACEABLE), littleProxy.generatedResponses(), "as LittleProxy 2.x");
        assertEquals(Optional.of(MitmServerHandshake.EAGER), littleProxy.mitmServerHandshake());

        assertEquals(littleProxy, ProtocolPolicy.preset("LittleProxy"));
        assertEquals(defaults, ProtocolPolicy.preset("microproxy"));
        assertThrows(IllegalArgumentException.class, () -> ProtocolPolicy.preset("netty"));
    }

    @Test
    void buildersSetFieldsOverAPresetAndLeaveTheRestUnset() {
        ProtocolPolicy p = ProtocolPolicy.builder().preset(ProtocolPolicy.littleProxy()).filterConnectAnswer(true).build();
        assertEquals(Optional.of(true), p.filterConnectAnswer());
        assertEquals(Optional.of(true), p.resolveBeforeProxyToServerRequest());

        ProtocolPolicy partial = ProtocolPolicy.builder().tlsRetryWithoutSni(true).build();
        assertEquals(Optional.empty(), partial.filterConnectAnswer());
        assertEquals("ProtocolPolicy[tls_retry_without_sni=true]", partial.toString());
        assertEquals(ProtocolPolicy.empty(), ProtocolPolicy.builder().build());

        ProtocolPolicy merged = partial.orElse(ProtocolPolicy.defaults());
        assertEquals(Optional.of(true), merged.tlsRetryWithoutSni());
        assertEquals(Optional.of(true), merged.filterConnectAnswer());
        assertNotEquals(ProtocolPolicy.defaults(), merged);

        // A preset applied after a field overwrites it.
        assertEquals(Optional.of(false), ProtocolPolicy.builder().filterConnectAnswer(true)
                .preset(ProtocolPolicy.littleProxy()).build().filterConnectAnswer());
    }

    @Test
    void fieldsAreSetByTheirConfigurationNames() {
        ProtocolPolicy p = ProtocolPolicy.builder().set("preset", "littleproxy")
                .set("filter-connect-answer", "TRUE").set("proxy_protocol_destination", "local_address").build();
        assertEquals(Optional.of(true), p.filterConnectAnswer());
        assertEquals(Optional.of(ProxyProtocolDestination.LOCAL_ADDRESS), p.proxyProtocolDestination());
        assertEquals(Optional.of(true), p.tlsRetryWithoutSni());
        assertEquals(Optional.of(GeneratedResponses.IN_PLACE),
                ProtocolPolicy.builder().set("generated_responses", "in-place").build().generatedResponses());
        assertEquals(Optional.of(MitmServerHandshake.EAGER),
                ProtocolPolicy.builder().set("mitm_server_handshake", "EAGER").build().mitmServerHandshake());
        assertThrows(IllegalArgumentException.class, () -> ProtocolPolicy.builder().set("mitm_server_handshake", "now"));
        assertThrows(IllegalArgumentException.class, () -> ProtocolPolicy.builder().set("no_such_field", "true"));
        assertThrows(IllegalArgumentException.class, () -> ProtocolPolicy.builder().set("tls_retry_without_sni", "yes"));
        assertEquals(Optional.of(Duration.ofMillis(1234)), ProtocolPolicy.builder()
                .set("request_head_timeout", "1234").build().requestHeadTimeout());
        assertThrows(IllegalArgumentException.class, () -> ProtocolPolicy.builder().set("request_head_timeout", "-1"));
        assertThrows(IllegalArgumentException.class,
                () -> ProtocolPolicy.builder().set("allow_chunked_length", "true"), "HTTP/1 only");
        assertEquals(Optional.of(true), new Http1PolicyBuilder().set("allow_chunked_length", "true").build()
                .allowChunkedLength());
        assertEquals(9, ProtocolPolicy.configurationNames().size());
    }

    @Test
    void compatibilityMakesLittleProxyHttp1sDefaultsOnly() {
        HttpProxyServerBootstrap compat = MicroProxy.bootstrap().withLittleProxyCompatibility();
        assertEquals(ProtocolPolicy.littleProxy().orElse(policy(compat, 1)), policy(compat, 1));
        assertEquals(Optional.of(true), policy(compat, 1).resolveBeforeProxyToServerRequest());
        assertEquals(ProtocolPolicy.defaults(), policy(compat, 2));
        assertEquals(ProtocolPolicy.defaults(), policy(compat, 3));
        assertEquals(Optional.of(false), policy(MicroProxy.bootstrap(), 1).resolveBeforeProxyToServerRequest());
        assertEquals(Optional.of(false), policy(compat, 1).allowChunkedLength());
    }

    @Test
    void explicitFieldsWinOverTheProtocolsDefaultsAndTheProtocolsOwnOverAllProtocols() {
        HttpProxyServerBootstrap b = MicroProxy.bootstrap().withLittleProxyCompatibility()
                .withTlsRetryWithoutSni(false)
                .onAllProtocols(p -> p.filterConnectAnswer(true).servePlainHttpAfterConnect(false))
                .onHttp2(p -> p.servePlainHttpAfterConnect(true))
                .onHttp3(p -> p.preset(ProtocolPolicy.littleProxy()));
        // HTTP/1: LittleProxy's defaults, under every explicit field.
        assertEquals(Optional.of(false), policy(b, 1).tlsRetryWithoutSni());
        assertEquals(Optional.of(true), policy(b, 1).filterConnectAnswer());
        assertEquals(Optional.of(true), policy(b, 1).resolveBeforeProxyToServerRequest());
        // HTTP/2: MicroProxy's defaults, all protocols' fields, its own over them.
        assertEquals(Optional.of(false), policy(b, 2).resolveBeforeProxyToServerRequest());
        assertEquals(Optional.of(true), policy(b, 2).servePlainHttpAfterConnect());
        // HTTP/3: the preset set as its own policy wins over all protocols'.
        assertEquals(Optional.of(false), policy(b, 3).filterConnectAnswer());
        assertEquals(Optional.of(true), policy(b, 3).tlsRetryWithoutSni());

        // HTTP/1's own fields win over all protocols', in whatever order they were set.
        HttpProxyServerBootstrap order = MicroProxy.bootstrap().onHttp1(p -> p.tlsRetryWithoutSni(true))
                .withTlsRetryWithoutSni(false);
        assertEquals(Optional.of(true), policy(order, 1).tlsRetryWithoutSni());
        assertEquals(Optional.of(false), policy(order, 2).tlsRetryWithoutSni());

        // HTTP/1's chunked-length field over the server's.
        HttpProxyServerBootstrap chunked = MicroProxy.bootstrap().withAllowChunkedLength(true);
        assertEquals(Optional.of(true), policy(chunked, 1).allowChunkedLength());
        chunked.onHttp1(p -> p.allowChunkedLength(false));
        assertEquals(Optional.of(false), policy(chunked, 1).allowChunkedLength());
    }

    @Test
    void aClonedBootstrapKeepsItsPolicies() {
        HttpProxyServer server = MicroProxy.bootstrap().withPort(0)
                .onHttp2(p -> p.tlsRetryWithoutSni(true)).onHttp1(p -> p.allowChunkedLength(true)).start();
        try {
            assertEquals(Optional.of(true), server.getProtocolPolicy(org.microproxy.http.HttpVersion.HTTP_2_0)
                    .tlsRetryWithoutSni());
            assertEquals(Optional.of(false), server.getProtocolPolicy(org.microproxy.http.HttpVersion.HTTP_1_1)
                    .tlsRetryWithoutSni());
            HttpProxyServerBootstrap clone = server.clone();
            assertEquals(Optional.of(true), policy(clone, 2).tlsRetryWithoutSni());
            assertEquals(Optional.of(true), policy(clone, 1).allowChunkedLength());
            // The clone's layers are its own.
            clone.onHttp2(p -> p.tlsRetryWithoutSni(false));
            assertEquals(Optional.of(true), server.getProtocolPolicy(org.microproxy.http.HttpVersion.HTTP_2_0)
                    .tlsRetryWithoutSni());
        } finally {
            server.abort();
        }
    }

    @Test
    void propertiesConfigureEachLayer() {
        Properties p = new Properties();
        p.setProperty("request_head_timeout", "1200");
        p.setProperty("policy.tls_retry_without_sni", "true");
        p.setProperty("policy.http1.preset", "littleproxy");
        p.setProperty("policy.http1.request_head_timeout", "250");
        p.setProperty("policy.http1.filter_connect_answer", "true");
        p.setProperty("policy.http1.allow_chunked_length", "true");
        p.setProperty("policy.http2.proxy_protocol_destination", "server_address");
        p.setProperty("policy.http3.serve_plain_http_after_connect", "false");
        HttpProxyServerBootstrap b = BootstrapView.fromProperties(p);
        assertEquals(Optional.of(true), policy(b, 1).resolveBeforeProxyToServerRequest());
        assertEquals(Optional.of(true), policy(b, 1).filterConnectAnswer(), "the layer's own fields over its preset");
        assertEquals(Optional.of(true), policy(b, 1).allowChunkedLength());
        assertEquals(Optional.of(ProxyProtocolDestination.SERVER_ADDRESS), policy(b, 2).proxyProtocolDestination());
        assertEquals(Optional.of(true), policy(b, 2).tlsRetryWithoutSni());
        assertEquals(Optional.of(false), policy(b, 3).servePlainHttpAfterConnect());
        assertEquals(Optional.of(Duration.ofMillis(250)), policy(b, 1).requestHeadTimeout());
        assertEquals(Optional.of(Duration.ofMillis(1200)), policy(b, 2).requestHeadTimeout());

        Properties compat = new Properties();
        compat.setProperty("littleproxy_compatibility", "true");
        assertEquals(Optional.of(false), policy(BootstrapView.fromProperties(compat), 1).filterConnectAnswer());
        assertEquals(Optional.of(true), policy(BootstrapView.fromProperties(compat), 2).filterConnectAnswer());

        Properties bad = new Properties();
        bad.setProperty("policy.http2.allow_chunked_length", "true");
        assertThrows(IllegalArgumentException.class, () -> BootstrapView.fromProperties(bad));
    }

    @Test
    void theCommandLineConfiguresEachLayer() throws IOException {
        HttpProxyServerBootstrap b = parse("--request-head-timeout", "1000", "--policy", "tls_retry_without_sni=true",
                "--http1-policy", "preset=littleproxy,filter_connect_answer=true,allow_chunked_length=true,request_head_timeout=250",
                "--http2-policy", "proxy_protocol_destination=server_address",
                "--http3-policy", "serve-plain-http-after-connect=false");
        assertEquals(Optional.of(true), policy(b, 1).resolveBeforeProxyToServerRequest());
        assertEquals(Optional.of(true), policy(b, 1).filterConnectAnswer());
        assertEquals(Optional.of(true), policy(b, 1).allowChunkedLength());
        assertEquals(Optional.of(ProxyProtocolDestination.SERVER_ADDRESS), policy(b, 2).proxyProtocolDestination());
        assertEquals(Optional.of(true), policy(b, 3).tlsRetryWithoutSni());
        assertEquals(Optional.of(false), policy(b, 3).servePlainHttpAfterConnect());
        assertEquals(Optional.of(Duration.ofMillis(250)), policy(b, 1).requestHeadTimeout());
        assertEquals(Optional.of(Duration.ofMillis(1000)), policy(b, 2).requestHeadTimeout());

        HttpProxyServerBootstrap compat = parse("--littleproxy-compat");
        assertEquals(Optional.of(false), policy(compat, 1).filterConnectAnswer());
        assertEquals(Optional.of(true), policy(compat, 2).filterConnectAnswer());

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parse("--http2-policy", "allow_chunked_length=true"));
        assertTrue(e.getMessage().contains("--http2-policy"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> parse("--policy", "preset"));
    }
}
