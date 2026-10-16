# Protocol policies

Where MicroProxy can behave in more than one way (the order of the filter hooks, how the answer to
a `CONNECT` is written, how the proxy talks TLS to servers), a protocol policy chooses, separately
for HTTP/1.x, HTTP/2 and HTTP/3 clients. Use this page to give some clients LittleProxy's
behaviour while others keep MicroProxy's, or to change one such behaviour on its own.

## The fields of a policy

| Field (Java / configuration name) | MicroProxy's default | LittleProxy's (`ProtocolPolicy.littleProxy()`) |
|---|---|---|
| `resolveBeforeProxyToServerRequest` / `resolve_before_proxy_to_server_request`: whether the server's name is resolved before `proxyToServerRequest` runs (a name that does not resolve is then answered `502` without that hook) | `false`: the hook can answer or redirect a request without a DNS lookup | `true` |
| `filterConnectAnswer` / `filter_connect_answer`: whether the `200 Connection established` answer to a client's `CONNECT` goes through `serverToProxyResponse` and `proxyToClientResponse` (trackers, `proxyToClientResponseSent` and `exchangeEnded` see it either way) | `true`: a filter can see it or turn it into a refusal | `false`: written straight to the client |
| `servePlainHttpAfterConnect` / `serve_plain_http_after_connect`: whether plain HTTP sent after a `CONNECT` that could be intercepted (a `ws://` WebSocket, say) is served as HTTP, through the filters | `true` | `false`: relayed as raw bytes |
| `proxyProtocolDestination` / `proxy_protocol_destination`: the destination a PROXY header sent to a server names, when the client brought none ([PROXY protocol](forward-proxy.md#proxy-protocol)) | `LOCAL_ADDRESS` (`local_address`): the address the client connected to | `SERVER_ADDRESS` (`server_address`): the server connection's remote address, and no header when the families differ |
| `generatedResponses` / `generated_responses`: what `proxyToClientResponse` may do with the responses the proxy answers with itself, its error responses and filters' short-circuit responses ([The proxy's responses in proxyToClientResponse](filters.md#the-proxys-responses-in-proxytoclientresponse)) | `REPLACEABLE` (`replaceable`): replace them | `REPLACEABLE`, as LittleProxy 2.x; LittleProxy 1.x and its forks: `IN_PLACE` (`in_place`), change them in place only. `SKIP` (`skip`) keeps them from the hook |
| `mitmServerHandshake` / `mitm_server_handshake`: when the proxy runs its TLS handshake with the server for an intercepted `CONNECT` ([Server TLS failures](mitm.md#server-tls-failures)); `HttpFilters.proxyToServerMitmHandshake()` overrides it per request | `DEFERRED` (`deferred`): after the `CONNECT` is answered and the ClientHello read, mirroring it; a failure answers the session's first request `502` | `EAGER` (`eager`): before answering, so a failure answers the `CONNECT` `502` |
| `tlsRetryWithoutSni` / `tls_retry_without_sni`: whether a server that rejects the server name with an `unrecognized_name` alert is tried once more without SNI ([Server TLS failures](mitm.md#server-tls-failures)) | `false` | `true` |
| HTTP/1 request-head deadline: `requestHeadTimeout` / `request_head_timeout`, measured from its first byte to the end of its headers; zero disables it | 30 seconds: an incomplete head receives `408` and the connection closes | 30 seconds (MicroProxy hardening; LittleProxy has no corresponding setting) |
| HTTP/1 only: `allowChunkedLength` / `allow_chunked_length`: whether a request with both `Transfer-Encoding` and `Content-Length` is accepted ([Security](../security.md#request-parsing)) | `withAllowChunkedLength` (`false`) | not part of the preset: LittleProxy refuses such requests too |

Each field and the LittleProxy 2.9.1 code that behaves so are listed in
[Migrating from LittleProxy](../migrating-from-littleproxy.md#behaviour-differences).

## Configuring policies

On the bootstrap, `onHttp1`, `onHttp2` and `onHttp3` set fields of one protocol's policy, and
`onAllProtocols` of every protocol's. Each takes a lambda that sets fields on a builder; `preset`
copies every field of a preset, and the fields set after it win over it:

```java
MicroProxy.bootstrap()
        .onHttp1(p -> p.preset(ProtocolPolicy.littleProxy())   // LittleProxy's behaviour for HTTP/1 clients
                       .filterConnectAnswer(true))              // ... but filters see the CONNECT's 200
        .onAllProtocols(p -> p.tlsRetryWithoutSni(true))
        .start();
```

`withLittleProxyCompatibility()` (`--littleproxy-compat`, `littleproxy_compatibility=true`) makes
the LittleProxy preset HTTP/1's defaults; HTTP/2 and HTTP/3 clients, which LittleProxy never
served, keep MicroProxy's. `allowChunkedLength` is only available on HTTP/1's builder
(`Http1PolicyBuilder`); `requestHeadTimeout` is available in every policy but only applies to
HTTP/1.

Set the timeout for every protocol with `withRequestHeadTimeout(Duration)` or
`--request-head-timeout` / `request_head_timeout`. The HTTP/1 policy can override it with
`onHttp1(p -> p.requestHeadTimeout(Duration))`, `--http1-policy request_head_timeout=<millis>` or
`policy.http1.request_head_timeout=<millis>`. The default is 30 seconds; zero disables the deadline.
HTTP/2 and HTTP/3 do not use this field.

In a properties file, `policy.<field>` sets a field for every protocol and `policy.http1.<field>`,
`policy.http2.<field>` and `policy.http3.<field>` for one; `preset` names a preset (`littleproxy`
or `microproxy`) and is applied before the other fields of its scope. On the command line,
`--policy`, `--http1-policy`, `--http2-policy` and `--http3-policy` take comma-separated
`field=value` pairs, applied left to right:

```properties
policy.http1.preset=littleproxy
policy.http1.filter_connect_answer=true
policy.tls_retry_without_sni=true
```

```bash
java -jar microproxy.jar --mitm --http1-policy preset=littleproxy,filter_connect_answer=true \
    --policy tls_retry_without_sni=true
```

## Which policy applies

A field's value for an exchange is, from the first that sets it:

1. the request's filters, for a field a hook decides per request (`mitm_server_handshake`:
   `proxyToServerMitmHandshake()`);
2. the policy of the client's protocol (`onHttp1`, `policy.http1.*`, ...);
3. the policy of every protocol (`onAllProtocols`, `policy.*`, and the bootstrap's own setters
   for those fields, such as `withTlsRetryWithoutSni`);
4. the protocol's defaults: `ProtocolPolicy.defaults()`, or for HTTP/1 with
   `withLittleProxyCompatibility()`, `ProtocolPolicy.littleProxy()`.

The client's protocol is the one it speaks to the proxy, `FlowContext.getHttpVersion()` (and
`ctx.protocol` in Starlark), whatever the proxy speaks to the server:

- An HTTP/1.x connection's requests, its `CONNECT`s included, take HTTP/1's policy; an HTTP/2
  connection's streams (`h2` and `h2c`, their `CONNECT`s and extended `CONNECT`s included) take
  HTTP/2's; an HTTP/3 connection's streams take HTTP/3's.
- Inside a tunnel the proxy intercepts, the requests take the policy of what the client speaks
  inside it. The `CONNECT` stream of an HTTP/2 client is HTTP/2's (its answer, and what is done
  with plain HTTP after it), while the HTTP/1.1 requests the client then sends inside the stream's
  TLS are HTTP/1's.
- SOCKS clients and transparent TLS connections, whose `CONNECT` the proxy makes up, are HTTP/1
  connections until the intercepted TLS negotiates HTTP/2. A reverse proxy's clients take the
  policy of the protocol they speak to it. Transparent QUIC, and the QUIC inside a CONNECT-UDP
  flow, is HTTP/3.

`HttpProxyServer.getProtocolPolicy(HttpVersion)` returns a protocol's policy with every field
resolved, and the admin [`/config_dump`](../reference/admin-api.md) shows them under
`protocol_policies`. The policies are resolved once, when the server starts: choosing one costs an
exchange nothing.
