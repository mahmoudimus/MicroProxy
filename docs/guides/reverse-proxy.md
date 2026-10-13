# Reverse proxy

Serve one upstream server, over HTTP, HTTPS, HTTP/2, HTTP/3 or raw TCP, so that clients talk to
MicroProxy as if it were that server. Use this page to put MicroProxy in front of a backend; HTTP/3
to clients is described in [Serving HTTP/3 in reverse
mode](http3.md#serving-http3-in-reverse-mode).

## Reverse proxy mode

`--mode reverse:https://example.com` (or `--reverse https://example.com`,
`withReverseProxy("https://example.com")`, `mode=reverse:https://example.com`) makes the proxy a
server for one upstream, in mitmproxy's specification syntax: `[scheme://]host[:port]`, the
scheme `https` by default, the port 443 for `https` and 80 for `http`.

- Every request goes to the upstream, whatever it names. Origin-form requests (`GET /path`) are
  accepted, and absolute-form ones are made origin-form. As in an intercepted session, a filter
  that gives a request an absolute URI of its own (`MapRemote`, a script assigning `req.uri`)
  sends it to that URI's server instead.
- **The client never picks the server.** Nothing a client sends chooses where its request goes,
  so a reverse proxy cannot be used to reach other hosts (server-side request forgery): an
  absolute-form URI (`GET http://127.0.0.1:6379/`) is made origin-form for the upstream before
  any filter sees it, as mitmproxy's reverse mode sets the upstream's address on every request,
  and its authority survives only as the `Host` that `--keep-host-header` keeps; an HTTP/2
  `:authority` chooses nothing either; and `CONNECT` is refused with `400`, with or without a
  MITM manager, as mitmproxy refuses it outside its regular and upstream modes. Only filters and
  scripts may send a request elsewhere: an absolute URI that a filter sets is followed, the one
  the client sent never is.
- `Host` is set to the upstream's (`example.com`, with the port unless it is the scheme's
  default) before any filter sees the request, unless `--keep-host-header` (`keep_host_header`,
  `withKeepHostHeader(true)`) keeps the client's.
- `https://` upstreams are reached over TLS, validated with the MITM manager's server context
  when one is configured (`--mitm-trust-all` works too) and the JVM's trust store otherwise, and
  over HTTP/2 when the upstream offers it (unless `--no-http2-upstream`). `http://` upstreams get plain HTTP.
  An upstream named by its IP address (`reverse:https://10.0.0.7`) gets no SNI and its
  certificate is checked against that address; a filter's `proxyToServerTlsIdentity` can send the
  service's name and check the certificate against it instead
  ([Server name and verification host](mitm.md#server-name-and-verification-host)).
- `tcp://host:port` relays each client connection to the upstream as raw bytes.
- With a TLS listener (`withSslContextSource`, `--listener-keystore`), the proxy terminates TLS,
  and serves HTTP/2 to clients that offer it (unless `--no-http2`). With `--http3`, it serves HTTP/3 on
  the UDP port with the same number, and advertises it with `Alt-Svc` (see
  [HTTP/3 and QUIC](http3.md)); with `--http3-upstream`, it speaks HTTP/3 to an upstream
  that offers it.
- Filters, scripts, the cache, logging and failure answers work as for any request.
