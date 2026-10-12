# Concurrency limiting

Cap how many exchanges run at once per client, user, target host or any key, with a bounded wait
queue, `429` answers, a shadow mode and metrics. Use this page to keep one client from monopolising
the proxy or a server; `--max-concurrent-per-client` turns on the common case from the command
line.

`org.microproxy.extras.ConcurrencyLimiter` is a filters source that caps how many exchanges run at
once per key. Requests over the limit wait in a bounded queue, or are answered with `429 Too Many
Requests` (plain text, `Retry-After: 1` by default):

```java
ConcurrencyLimiter limiter = ConcurrencyLimiter.builder()
        .key(ConcurrencyLimiter.byUser())              // default: byClientIp(); also byTargetHost()
        .permits(8)                                     // per key
        .permits(user -> user.equals("batch") ? 32 : null)   // null: the default
        .queue(16, Duration.ofSeconds(2))               // default: refuse at once
        .onReject((key, request, flow) -> metrics.increment("limited", key))
        .build();
MicroProxy.bootstrap().withFiltersSource(HttpFiltersChain.of(limiter, myFilters)).start();
```

- **Key:** any `(request, flow) -> String`, for example `flow.getClientDetails().getUserName()` or
  the target host; a `null` key leaves the request unlimited.
- **When a permit is held:** it is taken in `clientToProxyRequest`, which runs after proxy
  authentication (requests answered with `407` are never counted), and released exactly once in
  `HttpFilters.exchangeEnded`: after the response is written, or when the exchange was abandoned
  (client gone, server failure, a filter's answer or abort, the proxy stopping). Put the limiter
  first among the filters so the others do no work for refused requests.
- **Tunnels:** a `CONNECT` tunnel and an upgraded (WebSocket) connection hold their permit until
  they close; `countTunnels(false)` stops counting `CONNECT`s and releases an upgrade's permit
  after its `101`. An intercepted `CONNECT` holds its permit only until interception starts, and
  the requests inside the session are counted one by one.
- **Safety net:** a permit held for longer than `permitTimeout` (10 minutes by default) is
  reclaimed and logged at `WARNING`; established tunnels are exempt.
- **Shadow mode:** `shadow(true)` counts and reports requests over the limit but lets them
  through, to try a limit out first.
- **Answers:** `retryAfter(Duration)` (or `null` for none) and `response((key, request, flow) ->
  ...)` replace the default `429`.
- **Metrics:** `snapshot()` returns the permits in use, waiting and refused per busy key, plus
  totals (granted, refused, reclaimed). A key is forgotten as soon as none of its permits are in
  use, so memory stays bounded by the exchanges in progress.

Waiting blocks only the client connection's virtual thread. The limiter reads request heads only,
so bodies keep the fast path. Lambda-built filters keep no state per exchange, so combine them
with a limiter in a chain rather than inside the builder. On the command line,
`--max-concurrent-per-client N` (or `max_concurrent_per_client=N`) installs one keyed by client IP.
