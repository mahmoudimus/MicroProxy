# HTTP cache

Cache responses in memory or on disk as an RFC 9111 shared cache, with revalidation, `Vary`, stale
answers when servers are unreachable and an offline mode. Use this page to speed up repeated
fetches or to browse recorded pages without a network.

`org.microproxy.cache.HttpCache` is a shared cache following RFC 9111. Put it on disk to keep
cached pages across restarts and to browse them offline:

```bash
java -jar microproxy.jar --cache-dir ~/.microproxy-cache --cache-size 2048
java -jar microproxy.jar --cache-dir ~/.microproxy-cache --offline   # never contact servers
```

```java
HttpCache cache = HttpCache.builder()
        .store(new DiskCacheStore(Path.of("cache"), 2L << 30))   // or new MemoryCacheStore(bytes)
        .build();
MicroProxy.bootstrap().withHttpCache(cache).start();
```

What it does:

- **Storing:** complete `GET` responses up to 8 MiB that a shared cache may store. That excludes
  `no-store`, `private`, `Vary: *`, responses to requests with `Authorization` (unless
  `public`, `s-maxage` or `must-revalidate`), and responses setting cookies (unless `public`).
- **Freshness:** from `s-maxage`, `max-age`, `Expires`, or 10% of the time since
  `Last-Modified` (at most a day). Ages follow the RFC, including `Age` and the response delay.
  The request directives `max-age`, `min-fresh`, `max-stale`, `no-cache` (and `Pragma: no-cache`),
  `no-store` and `only-if-cached` are honoured.
- **Revalidation:** a stale entry with an `ETag` or `Last-Modified` is checked with a conditional
  request. A `304` refreshes the entry, and the client still gets the full response.
- **Variants:** `Vary` is matched on normalized request values, and a URL may have several
  variants. `HEAD` is answered from a stored `GET`.
- **Invalidation:** a successful `POST`, `PUT`, `DELETE`, etc. removes the URL, and same-origin
  `Location` / `Content-Location`.
- **When servers are unreachable:** a stale entry is served instead of the proxy's `502`/`504`,
  unless it is marked `must-revalidate`, `proxy-revalidate`, `no-cache` or `s-maxage`. A server's
  `5xx` is replaced only within `stale-if-error`.
  - With `--mitm`, intercepted HTTPS keeps working: a `CONNECT` to a dead server is still
    intercepted, through the `proxyToServerAllowOfflineMitm` filter hook, and the cache answers
    inside the session.
- **Offline mode:** everything is answered from the cache, whatever its age; anything else gets
  `504`.
- **Reporting:** responses carry `Cache-Status` (RFC 9211), e.g. `MicroProxy; hit; ttl=42` or
  `MicroProxy; fwd=stale; fwd-status=304`. `HttpCache.stats()` counts hits, misses, stores,
  revalidations and stale responses served.

The cache always runs after the other filters (`withFiltersSource`, `plusFiltersSource`, scripts).
So filters and scripts see a request before the cache can answer it, and the cache stores
responses after they have been rewritten.

Not implemented: `stale-while-revalidate`, `Range` requests (they bypass the cache) and caching
`POST` responses.
