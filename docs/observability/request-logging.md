# Request/response logging

Log whole requests and responses (heads, what the proxy and filters changed, and optionally bodies)
as readable blocks or JSON lines, with redaction and content views. Use this page to debug traffic;
for one line per exchange use [access logs](access-logs.md).

## Logging whole messages with `HttpLogger`

`HttpLogger` logs whole requests and responses, like OkHttp's `HttpLoggingInterceptor` or a
mitmproxy flow dump. It is a filters source:

```java
HttpLogger logger = HttpLogger.builder()
        .level(HttpLogger.Level.HEADERS)          // BASIC, HEADERS (the default) or BODY
        .redact("X-Api-Key")                       // besides Authorization, Cookie, Set-Cookie, Proxy-Authorization
        .redactQueryParams("token", "api_key")
        .maxBodyBytes(4096)                        // BODY: bytes kept per body (the default)
        .only((request, ctx) -> request.uri().contains("/api/"))   // optional
        .build();
MicroProxy.bootstrap().plusFiltersSource(logger).start();
```

- **Levels:** `BASIC` logs the request line, the status line, timings and the sizes the heads
  declare. `HEADERS` adds the headers. `BODY` adds the bodies.
- **Both sides of the proxy:** the request as the client sent it, then, when the proxy or a filter
  changed it, a `forwarded as` section with the request line as sent and the headers removed (`-`)
  and added (`+`). The response as the server sent it, then a `delivered as` section in the same
  form. The response line shows the status the client got, how long the exchange took (`ttfb` is
  the wait for the server's first byte), where the response came from (`source=server`, `proxy`,
  `filter`, `cache` or `replay`) and the server's status (`upstream=`) when a filter or the cache answered or
  changed it.
- **Correlation:** each message is handed to the sink as one string, so concurrent connections do
  not interleave their lines. Every line starts with `[conn <id> #<n>]`: the client connection, as
  in the proxy's own log lines, and the exchange's number on it. Requests inside an intercepted
  TLS session are numbered after their `CONNECT`. An HTTP/2 stream's lines add its id
  (`[conn 3 #2 stream 5]`, and `"stream": 5` in JSON); its request line shows `HTTP/2.0` and its
  `forwarded as` line `HTTP/1.1`.
- **When:** a request is logged once it has been sent to the server (or answered without it), a
  response once it has been delivered in full. An exchange that fails half-way through its response
  logs no response.
- **Redaction:** the values of `Authorization`, `Cookie`, `Set-Cookie` and `Proxy-Authorization`
  are replaced with `██`, in any case and on both sides. `redact(...)` adds header names,
  `redactQueryParams(...)` redacts query parameters in logged URLs, and `redactNothing()` turns
  redaction off (later `redact` calls add to that). Bodies are never redacted.
- **Bodies (`BODY`):** each body is kept up to `maxBodyBytes`; the rest is counted, never buffered,
  and what is forwarded does not change. A body seen whole is decoded (`gzip`, `deflate`, `br`,
  `zstd`, as in [Rewriting bodies](../guides/rewriting-bodies.md)) and shown as text in the charset of its
  `Content-Type`. Binary bodies are summarised (`<1000 bytes of image/png>`). A request body is
  shown as the client sent it, a response body as the server sent it (and the delivered body too
  when a filter replaced the response).
- **Content views:** `.contentViews(ContentViews.defaults())` (or `.contentView("auto")`) renders
  bodies at `BODY` through [content views](../guides/content-views.md#content-views) where one applies: protobuf and gRPC
  (message by message) as YAML with field numbers, JSON indented, form data, GraphQL, msgpack.
  The `END` line names the view (`grpc view`), and JSON messages add `body_view`. A named view
  (`.contentView("hex")`) renders every body it can. With views, `grpc-status`,
  `grpc-message` and `grpc-status-details-bin` are explained wherever they appear, in headers
  (Trailers-Only responses) and trailers. A body cut at `maxBodyBytes` shows its complete gRPC
  messages and how much of the last one there is; raise the cap for long streams.
- **Trailers:** at `BODY`, request and response trailers (`grpc-status`, ...) follow the body
  (`<-- trailers`), redacted like headers; JSON messages add `trailers`.
- **WebSocket frames:** `.webSocketFrames(true)` at `BODY` also logs each frame after an upgrade:
  text frames' text (up to `maxBodyBytes`), other frames' sizes. It is off by default because it
  makes the proxy parse every frame. Frames are only watched, so the extension negotiation is left
  alone and compressed frames are logged as such.
- **Cost:** `BASIC` and `HEADERS` read only heads, so bodies keep the proxy's fast path. When the
  `System.Logger` is off at INFO (and no `sink` was given), no filters are created at all.
- **Failures:** a sink that throws, or a bug in the logger, is reported once to the
  `org.microproxy.extras.HttpLogger` logger and never reaches the proxy.

> **`BODY` logs payloads.** Bodies carry passwords, tokens, session data and personal data, and
> redaction does not touch them. Use `BODY` while developing, or narrowed with `only(...)` to the
> traffic you are debugging, and not in production without deciding where the logs go and who can
> read them. `HEADERS` also logs URLs and every header that is not redacted.

To log from filters built with lambdas, add the logger to the builder. It sees the request before
the lambdas and the response after them, so their changes show in the diffs:

```java
HttpFiltersBuilder.Built filters = HttpFilters.builder()
        .log(logger)
        .beforeSending(req -> { req.headers().set("X-Trace", traceId()); return null; })
        .build();
MicroProxy.bootstrap().withFiltersSource(filters).start();
// or, the same: .withFiltersSource((request, ctx) -> filters)
```

One built instance can serve every connection: the logger's state is per exchange. When the proxy
(or an `HttpFiltersChain`) gets built filters from a source, whether they are the source or a
lambda returned them, it asks them for a copy bound to that exchange, which holds the logger's state
and goes away with the exchange. Only built filters wrapped in filters of your own that delegate to
them cannot be bound; they run their hooks but log nothing, and a warning says so once.

In a chain, put the logger first: `HttpFiltersChain.of(logger, rewriter, script)`. It still sees
requests as clients sent them and responses as delivered wherever it is, but it reads server
responses (and request bodies) when they reach it. Starlark scripts chain the same way.

From the command line, `--log-http basic|headers|body` installs a logger first among the filters,
and `--log-http-json` writes JSON lines (at `headers` unless a level is given). `--log-http-view
auto` (or a view's name) adds content views, at `body` unless a level is given, and
`--proto-descriptors api.desc` gives them field names. Properties files take `log_http`,
`log_http_format=json`, `log_http_view` and `proto_descriptors`.

Logging bodies (or any filter that reads request body pieces) makes the proxy send an HTTP/2
request body whole before it reads the response, so a bidirectional gRPC stream waits for the
client to finish sending; unary and server-streaming calls are unaffected.

Without a `sink`, messages go to the `System.Logger` named `org.microproxy.http` at INFO. With the
JDK's default `java.util.logging` setup they appear on standard error with a date line before each.
To keep only the messages, or to send them to a file, pass a configuration with
`-Djava.util.logging.config.file=http-logging.properties`:

```properties
handlers = java.util.logging.ConsoleHandler
java.util.logging.ConsoleHandler.level = ALL
.level = WARNING
org.microproxy.http.level = INFO
# just the message: one block, or one JSON object per line
java.util.logging.SimpleFormatter.format = %5$s%n
# or write them to a file instead of the console:
# org.microproxy.http.handlers = java.util.logging.FileHandler
# org.microproxy.http.useParentHandlers = false
# java.util.logging.FileHandler.pattern = http-%u.log
# java.util.logging.FileHandler.formatter = java.util.logging.SimpleFormatter
```

With SLF4J or Log4j bridges, configure the logger `org.microproxy.http` there. A `sink(line -> ...)`
receives each message directly instead.

`HEADERS` output for a `POST` through the proxy (`--log-http headers`):

```text
[conn 3 #1] --> POST http://api.example.com/items?token=██&page=2 HTTP/1.1
[conn 3 #1] Content-Length: 17
[conn 3 #1] Host: api.example.com
[conn 3 #1] User-Agent: curl/8.9.1
[conn 3 #1] Authorization: ██
[conn 3 #1] Content-Type: application/json
[conn 3 #1] Proxy-Connection: Keep-Alive
[conn 3 #1] --> forwarded as POST /items?token=██&page=2 HTTP/1.1
[conn 3 #1] - Proxy-Connection: Keep-Alive
[conn 3 #1] + Via: 1.1 gateway
[conn 3 #1] --> END POST (17-byte body)
[conn 3 #1] <-- 201 Created http://api.example.com/items?token=██&page=2 (48 ms, ttfb 47 ms, source=server)
[conn 3 #1] Content-Type: application/json
[conn 3 #1] Content-Length: 25
[conn 3 #1] Set-Cookie: ██
[conn 3 #1] <-- delivered as HTTP/1.1 201 Created
[conn 3 #1] + Via: 1.1 gateway
[conn 3 #1] <-- END HTTP (25-byte body)
```

`BODY` adds the bodies after a blank line, before the `END` lines. With `--log-http-json`, each
message is one object (wrapped here):

```json
{"type":"request","conn":3,"seq":1,"time":"2026-10-09T02:44:26.372Z","method":"POST",
 "url":"http://api.example.com/items?token=██&page=2","version":"HTTP/1.1",
 "headers":[["Content-Length","17"],["Host","api.example.com"],["Authorization","██"],["Content-Type","application/json"]],
 "forwarded":{"method":"POST","uri":"/items?token=██&page=2","version":"HTTP/1.1","removed":[],"added":[["Via","1.1 gateway"]]},
 "body_bytes":17}
{"type":"response","conn":3,"seq":1,"time":"2026-10-09T02:44:26.372Z","status":201,"reason":"Created",
 "url":"http://api.example.com/items?token=██&page=2","version":"HTTP/1.1","source":"SERVER","upstream_status":201,
 "ttfb_ms":47.112,"total_ms":48.003,"headers":[["Content-Type","application/json"],["Content-Length","25"],["Set-Cookie","██"]],
 "delivered":{"status":201,"reason":"Created","version":"HTTP/1.1","removed":[],"added":[["Via","1.1 gateway"]]},
 "body_bytes":25}
```

At `BODY`, JSON messages add `body` (the text, or `null` with a `body_note` for binary or
undecodable bodies) and `body_remarks` (`gzip-decoded`, `first 4096 bytes shown`, ...); WebSocket
frames are `{"type":"websocket","from":"client","opcode":"text","fin":true,"bytes":4,"payload":"ping",...}`.
