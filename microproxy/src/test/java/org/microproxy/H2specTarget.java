package org.microproxy;

import java.nio.charset.StandardCharsets;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/**
 * The proxy as a target for h2spec (an HTTP/2 conformance tester), run by CI: h2c with prior
 * knowledge on the plain listener, with a filter that reads each request and answers it with 200
 * itself, so h2spec's requests (origin-form, {@code :authority} naming the proxy) succeed without
 * an origin server.
 *
 * <pre>{@code java -cp <classes> org.microproxy.H2specTarget [port]}</pre>
 */
public final class H2specTarget {

    private H2specTarget() {}

    public static void main(String[] args) {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpProxyServer server = start(port);
        System.out.println("h2spec target listening on " + server.getListenAddress());
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "h2spec-target-shutdown"));
    }

    static HttpProxyServer start(int port) {
        return MicroProxy.bootstrap()
                .withPort(port)
                .withHttp2Cleartext(true)
                // Requests name the proxy itself as the authority (h2spec's -h/-p): answer them here.
                .withAllowRequestToOriginServer(true)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public int getMaximumRequestBufferSizeInBytes() {
                        // Read the whole request first, so malformed bodies are seen before the answer.
                        return 1 << 20;
                    }

                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                        return new HttpFiltersAdapter(originalRequest, ctx) {
                            @Override
                            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                                // Large enough for the flow-control cases, which need more DATA than a window.
                                byte[] body = "ok\n".repeat(400).getBytes(StandardCharsets.US_ASCII);
                                HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                        HttpResponseStatus.OK, body);
                                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain");
                                return response;
                            }
                        };
                    }
                })
                .start();
    }
}
