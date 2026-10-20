# Your first filter

Write a Java filter that answers some requests itself and lets the rest through, then the same
filter with lambdas. Use this page to learn the filter API; [Filters and failure
responses](../guides/filters.md) covers every hook.

## A filter class

Filters keep LittleProxy's shape: an `HttpFiltersSource` makes an `HttpFilters` per request, and
the `HttpFilters` overrides the hooks it needs. Returning a response from
`clientToProxyRequest` answers the request without contacting the server; returning `null` lets
it through.

```java
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersAdapter;
import org.microproxy.HttpFiltersSourceAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

public class BlockingProxy {
    public static void main(String[] args) {
        HttpProxyServer proxy = MicroProxy.bootstrap()
                .withPort(8080)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                        return new HttpFiltersAdapter(originalRequest, ctx) {
                            @Override
                            public HttpResponse clientToProxyRequest(HttpObject httpObject) {
                                if (httpObject instanceof HttpRequest r && r.uri().contains("/blocked")) {
                                    return new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                            HttpResponseStatus.FORBIDDEN, "blocked by proxy");
                                }
                                return null; // continue proxying
                            }
                        };
                    }
                })
                .start();
        System.out.println("listening on " + proxy.getListenAddress());
    }
}
```

Run it with the `microproxy` jar on the class path, and try it:

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.6.1-SNAPSHOT
java -cp microproxy/target/microproxy-${MICROPROXY_VERSION}.jar BlockingProxy.java
```
<!-- x-release-please-end -->

```console
$ curl -s -i -x http://127.0.0.1:8080 http://example.com/blocked
HTTP/1.1 403 Forbidden
...

blocked by proxy
```

Any other URL is fetched from the server as usual.

## The same filter with lambdas

For small filters, `HttpFilters.builder()` takes one lambda per hook, and `HttpFiltersSource` is a
functional interface. The built filters are also a filters source that returns them for every
request (`org.microproxy.HttpFiltersBuilder`):

```java
HttpFiltersBuilder.Built filters = HttpFilters.builder()
        .onRequest(req -> req.uri().contains("/blocked")
                ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN, "blocked by proxy")
                : null)
        .build();
MicroProxy.bootstrap().withPort(8080).withFiltersSource(filters).start();
```

See [Filters from lambdas](../guides/filters.md#filters-from-lambdas) for every builder hook.

## Next steps

- [Filters and failure responses](../guides/filters.md): every hook, buffering, failure answers.
- [Rewriting bodies](../guides/rewriting-bodies.md): decode, edit and re-encode bodies.
- [Addons, HAR and replay](../guides/addons.md): ready-made filters (`MapRemote`, `BlockList`, ...).
- [MITM, certificates and TLS](../guides/mitm.md): see inside HTTPS.
- [Migrating from LittleProxy](../migrating-from-littleproxy.md), if you have LittleProxy filters.
