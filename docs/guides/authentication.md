# Proxy authentication

Make clients authenticate to the proxy with Basic credentials, Bearer tokens or any scheme of your
own, per connection or per request. Use this page to protect a proxy that other machines can reach;
SOCKS5 clients authenticate the same way ([SOCKS](socks.md#authentication)), and a Starlark script
can be the authenticator ([Authenticating clients](scripting.md#authenticating-clients)).

`withProxyAuthenticator` makes clients authenticate. A `ProxyAuthenticator` that only implements
`authenticate(user, password)` checks `Proxy-Authorization: Basic` and answers failures with
`407` and `Proxy-Authenticate: Basic realm="..."` (`getRealm()`). For other schemes, override
`authenticate(HttpRequest, FlowContext)`, which sees the whole request and the client connection
and returns an `AuthResult`:

- `AuthResult.accept(user)`: the request proceeds, and `user` (which may be `null`) becomes
  `ClientDetails.getUserName()` for filters, trackers, access logs, the `ChainedProxyManager`,
  MITM decisions and Starlark's `ctx.user`.
- `AuthResult.reject(response)`: the client gets `response`, for instance a `407` with your own
  `Proxy-Authenticate` header and body, or a `403`. `AuthResult.reject()` sends the default
  Basic `407`.

```java
MicroProxy.bootstrap()
        .withProxyAuthenticator(new ProxyAuthenticator() {
            @Override
            public AuthResult authenticate(HttpRequest request, FlowContext flow) {
                String value = request.headers().get(HttpHeaderNames.PROXY_AUTHORIZATION);
                if (value != null && value.startsWith("Bearer ")) {
                    String user = tokens.userFor(value.substring(7));   // your token check
                    if (user != null) return AuthResult.accept(user);
                }
                FullHttpResponse challenge = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                        HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED, "{\"error\":\"invalid_token\"}");
                challenge.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE, "Bearer realm=\"proxy\"");
                return AuthResult.reject(challenge);
            }

            @Override
            public boolean authenticate(String userName, String password) {
                return false;   // no Basic credentials
            }

            @Override
            public boolean authenticateEveryRequest() {
                return true;    // tokens expire
            }
        })
        .start();
```

Your authenticator owns credential verification. Use the password-hash or identity provider's
timing-safe verification API for stored passwords. For a configured secret or bearer token,
compare its expected bytes first with `MessageDigest.isEqual(expectedBytes, presentedBytes)`;
cache the expected UTF-8 bytes rather than calling `String.equals` on a secret. This comparison
does not hide input lengths, parsing, allocation, provider behavior, or account lookups. Where
username enumeration matters, evaluate the password check even when the username does not match
and return a uniform failure; avoid `userMatches && passwordMatches` around a password verifier.
Starlark authenticators can use `digest.equal(expected, presented)` or `hmac.compare_digest`.
See the [comparison and timing audit](../security-timing-audit.md) for the scope and local checks.

- **Once per connection:** by default the first accepted request authenticates its client
  connection, and later requests on it are not checked. `authenticateEveryRequest()` checks every
  request instead. When the accepted user changes on a connection, the server connections made
  for the previous user are given up, so routing is decided again.
- **CONNECT and interception:** a `CONNECT` is authenticated like any request. The requests inside
  an intercepted session carry no proxy credentials and are covered by their `CONNECT`, even with
  `authenticateEveryRequest()`.
- **Credentials stay here:** whatever the scheme, `Proxy-Authorization` is removed from every
  request before filters see it, so it is never forwarded, even by a transparent proxy.
- To accept Basic as well, fall back to `ProxyAuthenticator.super.authenticate(request, flow)`.
- A Starlark script can be the authenticator, with an `authenticate` hook (see
  [Scripting with Starlark](scripting.md)).
