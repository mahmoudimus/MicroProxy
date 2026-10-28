# SOCKS

Serve SOCKS5, SOCKS4 and SOCKS4a clients, on a listener of their own or next to HTTP clients on the
regular one; their connections go through the same filters, routing and interception as a
`CONNECT`. Use this page for clients that speak SOCKS (curl, browsers, SSH); chaining to an
upstream SOCKS proxy is in [Chained proxies](chained-proxies.md).

## SOCKS5 mode

`--mode socks5` (`withSocksServer(true)`, `mode=socks5`) makes the listener a SOCKS server, as
mitmproxy's `socks5` mode does: SOCKS5 ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)), and
SOCKS4 and 4a as well. `--socks` (`withSocksDetection(true)`, `socks=true`) serves SOCKS clients on
the regular listener besides HTTP ones, told apart by their first byte: `0x05` for SOCKS5, `0x04`
for SOCKS4 and 4a, which no HTTP request, TLS record or HTTP/2 preface starts with.

```bash
java -jar microproxy.jar --port 1080 --mode socks5 --mitm
curl --socks5-hostname 127.0.0.1:1080 http://example.com/              # the proxy resolves the name
curl --proxy socks5h://127.0.0.1:1080 --cacert microproxy-ca.pem https://example.com/   # intercepted
curl --socks5 127.0.0.1:1080 http://example.com/                       # curl resolves, sends an address
curl --socks4a 127.0.0.1:1080 http://example.com/

java -jar microproxy.jar --port 8080 --socks --mitm   # HTTP and SOCKS clients on one port
curl --proxy socks5h://127.0.0.1:8080 https://example.com/ --cacert microproxy-ca.pem
curl --proxy http://127.0.0.1:8080 https://example.com/ --cacert microproxy-ca.pem
```

With proxy authentication, SOCKS5 clients give a username and password:

```java
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.MessageDigest;

byte[] expectedUser = "alice".getBytes(UTF_8);
byte[] expectedPassword = System.getenv("PROXY_PASSWORD").getBytes(UTF_8);
MicroProxy.bootstrap()
        .withPort(1080)
        .withSocksServer(true)
        .withProxyAuthenticator((user, password) -> {
            boolean userMatches = MessageDigest.isEqual(expectedUser,
                    user == null ? new byte[0] : user.getBytes(UTF_8));
            boolean passwordMatches = MessageDigest.isEqual(expectedPassword,
                    password == null ? new byte[0] : password.getBytes(UTF_8));
            return userMatches & passwordMatches;
        })
        .start();
```

```bash
curl --proxy socks5h://127.0.0.1:1080 --proxy-user "alice:${PROXY_PASSWORD}" http://example.com/
```

Set `PROXY_PASSWORD` before starting this example. For stored passwords, use a password-hash
verifier with a timing-safe verification API; see [Proxy authentication](authentication.md).

| Flag | Property | Bootstrap | |
|---|---|---|---|
| `--mode socks5` | `mode=socks5` | `withSocksServer(true)` | the listener serves SOCKS clients only; others are closed |
| `--socks` | `socks=true` | `withSocksDetection(true)` | the regular listener serves SOCKS clients too |
| `--tls-handshake-timeout` | `tls_handshake_timeout` | `withTlsHandshakeTimeout` | also bounds the SOCKS handshake, up to the request |

### One request, one `CONNECT`

Only the `CONNECT` command is served; `BIND` and `UDP ASSOCIATE`
are answered "command not supported". The destination (an IPv4 or IPv6 address, or a host name,
which the proxy resolves) becomes a `CONNECT` the proxy makes up, which then goes exactly where an
HTTP client's `CONNECT` goes:

- the filters see it (`clientToProxyRequest`, `proxyToServerRequest`, `proxyToServerAllowMitm`,
  ...), and so do `ActivityTracker`s, the access and request logs, `FlowContext.timings()` and
  scripts; its answer is the `200` the client would have got, or the failure;
- routing: the `ChainedProxyManager`, chained HTTP and SOCKS proxies, `NO_PROXY` rules, backoff;
- then the client's first bytes decide, as after a `CONNECT`
  ([Deciding what to intercept](mitm.md#deciding-what-to-intercept-the-clienthello)): a ClientHello is
  intercepted with the MITM manager unless the [host rules](mitm.md#ignoring-and-allowing-hosts), its SNI
  and ALPN, the manager or a filter decline it; plain HTTP is served as HTTP, its requests going to
  the destination through the filters; anything else is tunnelled;
- the [TCP hooks](tcp-hooks.md#raw-tcp-streams) see its tunnels as they see a `CONNECT`'s, and an intercepted
  TLS session that does not carry HTTP (or one with a [TCP host](tcp-hooks.md#raw-tcp-streams)) is relayed
  decrypted through them.

A SOCKS client has no other way to send plain HTTP through the proxy, so its first bytes are read
even without `--mitm`: its HTTP requests are filtered and logged, and its TLS is tunnelled.
`FlowContext.socksVersion()` (5, or 4 for SOCKS4 and 4a; empty for HTTP clients) and Starlark's
`ctx.socks_version` tell SOCKS clients apart.

### Connected, then answered

As mitmproxy does, the proxy connects to the server (or through its
chained proxy) before it answers the request, so the client learns why a connection failed. The
ClientHello is read only after the answer, since a client sends it only then; this is the order of
an HTTP `CONNECT`, whose `200` is written once the server is connected and whose server handshake
waits for the ClientHello (ALPN mirroring included).

| Failure | SOCKS5 reply |
|---|---|
| The host name does not resolve (`UnresolvedHost`) | `0x04` host unreachable |
| The connection is refused | `0x05` connection refused |
| No route to the host / the network | `0x04` host unreachable / `0x03` network unreachable |
| The connect timeout passed | `0x06` TTL expired |
| The authenticator (checking every request), a filter or the `ChainedProxyManager` refused it | `0x02` not allowed by ruleset |
| Anything else (a chained proxy failed, the pool is exhausted, a filter answered with a `5xx`) | `0x01` general failure |

SOCKS4 replies have only "granted" (90) and "rejected" (91).

### Authentication

Without a [proxy authenticator](authentication.md), SOCKS5 clients must
offer "no authentication". With one, they authenticate with a username and password
([RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)), which the authenticator sees as
`Proxy-Authorization: Basic` on a made-up `CONNECT` whose target is not known yet (`0.0.0.0:0`),
so `authenticate(user, password)`, request-aware authenticators and a script's `authenticate` hook
all work, and the accepted user is `ClientDetails.getUserName()`. A client that offers no
credentials, SOCKS4's included (its user id is not a credential), is let in only if the
authenticator accepts that request without them; otherwise SOCKS5 clients get "no acceptable
methods" (`0xFF`) and SOCKS4 clients a rejection. With `authenticateEveryRequest()`, the request's
own `CONNECT`, with its destination and the same credentials, is authenticated again.

### Hardening

The handshake, from the first byte to the request, must finish within the TLS
handshake timeout (`--tls-handshake-timeout`, 10 seconds by default; with `0`, each read within the
idle timeout). SOCKS5 fields are bounded by their one-byte lengths, SOCKS4's user id and host name
by 255 bytes; host names may hold only letters, digits, `.`, `-` and `_` (or an IP literal).

Not supported: `BIND`, `UDP ASSOCIATE` (and so DNS or QUIC through SOCKS), GSSAPI authentication,
SOCKS on a TLS listener or together with a reverse proxy, and mitmproxy's `@port` listen suffix
(use `--port`).
