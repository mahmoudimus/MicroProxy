# Starlark API

Every hook a MicroProxy Starlark script can define, the objects they receive, the built-in
functions and modules, the standard library that `load()` reaches, and the budgets each call runs
under. Use this page as the reference while writing scripts; [Scripting with
Starlark](../guides/scripting.md) explains how to run them, with worked examples.

## Hooks

All are optional.

| Hook | Called | Returns |
|---|---|---|
| `on_request(req, ctx)` | for every request, including `CONNECT` and requests inside intercepted HTTPS | `None` to continue, or `response(...)` to answer without contacting the server |
| `on_response(req, res, ctx)` | for every response head (the whole response when buffered) | `None`, or a new `response(...)` to replace it |
| `upstream(req, ctx)` | when a server connection is needed | `None` for the default route, `"DIRECT"`, a proxy URL (`http://`, `https://`, `socks4://`, `socks5://`), or a list to try in order |
| `allow_mitm(req, ctx)` | for `CONNECT` when `--mitm` is on | whether to intercept |
| `on_client_hello(hello, ctx)` | once a client that may be intercepted has sent its TLS ClientHello (after `allow_mitm` and the host rules), over TCP or in the Initial packets of a [transparent QUIC](../guides/transparent-mode.md#transparent-quic) flow | `False` to tunnel (or relay) the connection untouched; `True` or `None` to intercept |
| `buffer_request(req, ctx)` | before `on_request`, for requests with a body | whether to buffer it so `req.body` is available (default: no) |
| `buffer_response(req, res, ctx)` | before `on_response` | whether to buffer it (default: text in a decodable coding, except `text/event-stream`) |
| `on_websocket_frame(req, frame, ctx)` | for each frame of an upgraded WebSocket, in both directions | `None` to forward the frame (with any changes), `False` to drop it |
| `on_websocket_message(msg, ctx)` | for each whole text or binary message of an upgraded WebSocket, in both directions, joined from its frames and inflated (after `on_websocket_frame`, if defined, has seen the frames) | `None` (or `msg`) to send the message with any changes, `False` to drop it, another message to replace it, or a list of messages to send instead (`[]` drops it) |
| `on_failure(req, failure, ctx)` | when the proxy has to answer the request itself (see [Failure responses](../guides/filters.md#failure-responses)) | `response(...)` to answer, or `None` for the `FailureResponder`'s answer or the default |
| `on_frame(frame, ctx)` | for each HTTP/2 and HTTP/3 frame, in each direction and on each side, when the script defines it (see [Frames](../guides/scripting.md#frames)); and for HTTP/3 frames run through an `Http3FramePipeline` | `None` (or the frame) to pass the frame on with any changes, `False` to drop it, another frame to replace it, or a list of frames to replace it with |
| `on_tcp_start(ctx)`, `on_tcp_message(msg, ctx)`, `on_tcp_end(ctx)` | for raw TCP tunnels, when the script defines one of them (see [Raw TCP](../guides/scripting.md#tcp-hooks)): when a tunnel opens, for the bytes of each read, and when it ends | `on_tcp_message`: `None` (or `True`, or the message) to pass the bytes on with any changes, `False` to drop them, or bytes, a string or another message to replace them |
| `on_udp_start(ctx)`, `on_udp_message(msg, ctx)`, `on_udp_end(ctx)` | for CONNECT-UDP flows, when the script defines one of them (see [UDP](../guides/scripting.md#udp-hooks)): when a flow opens, for each datagram, and when it ends | `on_udp_message`: as `on_tcp_message`, for one datagram |
| `on_quic_start(ctx)`, `on_quic_stream_data(msg, ctx)`, `on_quic_datagram(msg, ctx)`, `on_quic_end(ctx)` | for QUIC that is not HTTP/3, intercepted stream by stream, when the script defines one of them (see [QUIC](../guides/scripting.md#quic-hooks)): when a connection is intercepted, for the bytes of each read of a stream, for each datagram, and when it ends | `on_quic_stream_data`: as `on_tcp_message`; `on_quic_datagram`: as `on_udp_message` |
| `on_quic_message(msg, ctx)` | for each whole message of a stream that [QUIC message framing](../guides/quic-hooks.md#quic-message-framing) cuts into messages (DNS over QUIC by default), instead of `on_quic_stream_data` | as `on_websocket_message`: `None` (or `msg`) to send the message with any changes, `False` to drop it, another message (or bytes, or a string) to replace it, or a list of them to send instead (`[]` drops it); each is framed again |
| `quic_message_length(data)` | a framer of the script's own, for the streams `--quic-framing` gives to `script`: given the bytes kept of a stream direction | the length of the whole message they start with, or `None` until the bytes say |
| `authenticate(req, ctx)` | before the other hooks, for requests and `CONNECT`s from clients that have not authenticated (every request with `AUTHENTICATE_EVERY_REQUEST = True`); only when the script is the proxy authenticator | the user name or `True` to accept; `False` or `None` for the default `407`; `response(...)` to reject with that answer |

## Objects

- `req`: `method`, `uri` (assignable), `url`, `scheme`, `host`, `port`, `path`, `query`, and
  `headers`, `body`, `text`, plus `http_version`: the version the client used, `"HTTP/1.1"`,
  `"HTTP/1.0"`, `"HTTP/2"` or `"HTTP/3"` (requests reach servers as HTTP/1.1, or as HTTP/2 or
  HTTP/3 to servers that speak it: `http2_upstream`, on by default, and `http3_upstream`). `scheme` (and
  `url`) is the absolute URI's for a request that has one, `https` for one the proxy fetches over
  TLS of its own ([TLS origination](../guides/forward-proxy.md#tls-origination-https-uris-without-connect)), and stays so in
  `on_response` and `on_failure`, after the proxy has made the request origin-form for the server;
  an origin-form request's is the client connection's.
- `res`: `status`, `reason` (assignable), and `headers`, `body`, `text`, plus `source` and
  `upstream_status` (below).
- `body` and `text`: the decoded body as bytes or as a string. Both are `None` when the body was
  streamed rather than buffered. Assigning either re-encodes the body.
- `headers`: case-insensitive. `h["name"]` (first value), `h["name"] = v`, `"name" in h`,
  `get`, `get_all`, `set`, `add`, `remove`, `keys`, `items`.
- `ctx`: `client_ip`, `client_port`, `user` (from proxy authentication), `connection_id`, `tls`,
  `timings` (below), `client_hello` (the ClientHello that started the intercepted session, or
  `None`), `forwarded_via` (the client's HTTPS or HTTP proxy, `host:port`, that a `CONNECT` or an
  absolute-form request inside its session, or a request inside the tunnel one opened, goes
  through, else `None`; see
  [In front of an HTTP or HTTPS proxy](../guides/chained-proxies.md#in-front-of-an-http-or-https-proxy)), `socks_version` (5
  or 4 for a [SOCKS client](../guides/socks.md#socks5-mode), else `None`), `transparent_quic` (whether the client's
  QUIC came to the [transparent QUIC](../guides/transparent-mode.md#transparent-quic) listener), `early_data` (whether the
  HTTP/3 request arrived as 0-RTT early data, which may be a replay; see
  [Session resumption and 0-RTT](../guides/http3.md#session-resumption-and-0-rtt)), `failure` (why the proxy has to
  answer the request itself, a `Failure` as `on_failure` gets it, else `None`), `response_flags`
  (the exchange's [response flags](response-flags.md#response-flags-and-details) so far, as short codes: `["UF"]`),
  `response_code_details` (`"proxy_failure:connect_failed"`, ..., or `None`), `script_stats`
  (what the calls into scripts for the exchange added up to before this one: `calls`, `time_ms`,
  `steps` and `alloc_bytes`; see [Budgets and measurements](#script-budgets)), and `vars`, a dict that lives for
  one request so `on_request` can pass values to `on_response`. For a WebSocket it lives as long
  as the connection.
- `hello` (and `ctx.client_hello`): `sni` (`None` without one), `alpn` (the offered protocols, in
  the client's order), `versions` (`"TLSv1.3"`, `"TLSv1.2"`, ...) and `cipher_suites` (numbers).
  Its type is `ClientHello`.
- `failure`: `kind` (`"unresolved_host"`, `"connect_failed"`, `"tls_failed"`,
  `"server_timeout"`, `"bad_server_response"`, `"no_route"`, `"no_connection_available"`,
  `"bad_request"`, `"request_too_large"`), `status` (of the default answer), `host` (the server's
  name without the port; `None` for `bad_request`, `request_too_large` and a request that names
  no host), and `message`: the cause's message
  (`Connection refused`, ...) or the reason, never a stack trace.
- `frame`: `type` (`"text"`, `"binary"`, `"continuation"`, `"close"`, `"ping"`, `"pong"`),
  `opcode`, `fin`, `from_client`, `length`, `truncated`, and `text` and `payload`, which can be
  assigned. `text` is `None` for a payload that is not UTF-8; both are `None` for a truncated
  frame. (In `on_frame`, `frame` is an HTTP/2 or HTTP/3 frame: see [Frames](../guides/scripting.md#frames).)
- `msg`: `type` (`"text"` or `"binary"`), `from_client`, `length`, and `text` and `payload`, which
  can be assigned. `text` is `None` for a payload that is not UTF-8. Its type is `WebSocketMessage`.

## Built-ins

- From Starlark: everything in the language spec, including `json.encode`/`json.decode`.
- `response(status=200, body="", headers=None, content_type=None)`.
- `websocket_message(content, from_client=...)`: a message for `on_websocket_message` to return,
  text from a string or binary from bytes; `from_client=True` sends it towards the server,
  `False` towards the client.
- `re`: `match`, `search`, `fullmatch`, `findall`, `sub` (template or function), `split`,
  `escape`. Patterns use java.util.regex syntax plus Python's `(?P<name>...)`, and are
  abandoned at the call's deadline.
- `base64.encode`/`decode` (`urlsafe=True`), `codecs.encode`/`decode`.
- `digest.md5`/`sha1`/`sha256`/`sha512`/`hmac_sha256` (all return hex), and `digest.equal(a, b)`,
  which compares bytes or strings (as UTF-8) in constant time. Use it, not `==`, for tokens and
  signatures: `==` stops at the first difference, so how long a guess takes to fail tells an
  attacker how much of it was right. Compare digests of both sides (as below) so the length does
  not leak either.
- `url.quote`/`unquote`/`parse_query`/`encode_query`.
- `h2.data(stream_id, payload, end_stream=False)`, `h2.headers(stream_id, headers,
  end_stream=False)`, `h2.unknown(type, stream_id, payload, flags=0)`, and `h3.data(payload)`,
  `h3.headers(headers)`, `h3.unknown(type, payload)`: frames for `on_frame` to return. `headers`
  is a dict, a list of `(name, value)` pairs, or a `Headers`; `payload` is bytes or a string.
- `time.now`/`monotonic`, and `log.debug`/`info`/`warn`/`error`. `print` also goes to the log.
- `protobuf` and `grpc`: protobuf messages as dicts, and gRPC's framing (see **Protobuf and
  gRPC** below).
- `dns`: DNS messages as dicts, for DNS over QUIC, DNS over HTTPS bodies and DNS in UDP flows
  (see **DNS** below).
- More with `load()`: Python's `hashlib`, `hmac`, `re`, `urllib.parse`, `json`, `zlib`, ... (see
  **Standard library** below).

## Protobuf and gRPC

`protobuf.decode(data)` turns a message into a dict keyed by field number,
decoded as the [protobuf view](../guides/content-views.md#protobuf-without-a-schema) decodes it: varints are ints (negative
when the top bit is set), text is `str`, other bytes `bytes`, nested messages dicts, and a field
that occurs more than once a list. `protobuf.encode(fields)` turns such a dict back into bytes, the
same bytes for what `decode` made. Fixed-width values decode to `ProtoFixed` values (`.value`,
`.signed`, `.float`, `.bits`) and groups to `ProtoGroup` values (`.fields`), so that they encode
back as they were; `protobuf.fixed32(x)`, `fixed64(x)` and `group(fields)` make new ones. A float
encodes as a `fixed64` double.

| Function | |
|---|---|
| `protobuf.decode(data, type=None)`, `protobuf.encode(fields, type=None)` | bytes to dict and back; with `type`, by field name |
| `protobuf.render(data, type=None)` | the YAML the protobuf view shows |
| `protobuf.fixed32(x)`, `protobuf.fixed64(x)`, `protobuf.group(fields)` | fixed-width values (from an int or a float) and groups |
| `protobuf.pack(ints)`, `protobuf.unpack(data)`, `protobuf.zigzag_encode(n)`, `protobuf.zigzag_decode(n)` | packed repeated integers, and `sint32`/`sint64` values |
| `grpc.messages(body, encoding=None)`, `grpc.frame(messages, encoding=None)` | a gRPC body to its messages (bytes, decompressed) and back (compressed when an encoding is given: `gzip` or `deflate`) |
| `grpc.decode(body, encoding=None, type=None)`, `grpc.encode(dicts, encoding=None, type=None)` | the same, with `protobuf.decode` and `encode` of each message |
| `grpc.status(details)`, `grpc.status_details(code, message, details=[])` | `grpc-status-details-bin` to a dict (`code`, `name`, `message`, `details`) and back |
| `grpc.code_name(code)` | `INVALID_ARGUMENT` for 3, ... |

Rewrite every message of a gRPC response (the call's body must be buffered, so streaming calls
wait for the whole stream):

```python
def buffer_response(req, res, ctx):
    return res.headers.get("content-type", "").startswith("application/grpc")

def on_response(req, res, ctx):
    if res.body == None:
        return None
    encoding = res.headers.get("grpc-encoding")
    messages = grpc.decode(res.body, encoding=encoding)
    for m in messages:
        m[1] = m[1].upper()
        m[2] = m[2] + 41
    res.body = grpc.encode(messages, encoding=encoding)
    return None
```

Requests work the same with `buffer_request` and `on_request`. A hook for single HTTP/2 frames
(`on_frame`) is being added separately; the same functions apply to each frame's bytes there. With
a schema from Java, `ScriptedProxy.builder(path).protoSchema(ProtoSchema.load(Path.of("api.desc")))`,
`protobuf.decode(data, type="shop.Order")` keys fields by name (enum values by name too) and
`protobuf.encode(fields, type="shop.Order")` takes names. Typed scripts can annotate with
`ProtoFixed` and `ProtoGroup`; the dicts are untyped.

## DNS

`dns.decode(data)` turns a DNS message (wire format) into a dict, and `dns.encode(m)`
turns such a dict back into bytes, owner names compressed; `dns.render(data)` is the text `dig`
would show. The dict:

| Key | Value |
|---|---|
| `id`, `flags` | the message ID, and the header's 16 bits of flags |
| `response`, `opcode`, `authoritative`, `truncated`, `recursion_desired`, `recursion_available`, `rcode` | the flags by name; `encode` lets them win over `flags` |
| `questions` | dicts with `name`, `type` and `class` |
| `answers`, `authorities`, `additionals` | dicts with `name`, `type`, `class`, `ttl` and `data` |

Names are written without the final dot. Types are names (`"A"`, `"AAAA"`, `"MX"`, `"TYPE65280"`
for a type without one), and `encode` also takes numbers. The `data` of A and AAAA records is the
address (`"192.0.2.1"`, `"2001:db8::1"`), of NS, CNAME, PTR and DNAME records the name, of TXT
records a list of strings, of MX, SRV and SOA records a dict of their fields (`preference` and
`exchange`; `priority`, `weight`, `port` and `target`; `mname`, `rname`, `serial`, `refresh`,
`retry`, `expire` and `minimum`), and of other types (an EDNS `OPT` record included) its bytes;
`encode` takes bytes for any type. `encode` fills in what is left out: `id` 0, `class` 1 (IN),
`ttl` 0, no flags.

## Where a response came from, and how long it took

`res.source` tells the server's responses
from the others, like the `source` of the [access log](../observability/access-logs.md#access-logs-envoy-compatible), and `res.upstream_status`
is the status the server sent (`None` if it sent none). They describe the response as the hook
received it, not the script's own changes:

| where | `res.source` |
|---|---|
| `on_response`, `buffer_response` | `"server"`; `"proxy"` for the `200` that opens a `CONNECT` tunnel; `"cache"` for an `HttpCache` answer (a revalidated or stale entry) when the cache runs before the script in a filter chain; `"filter"` when an earlier filter in the chain gave the response another status; `None` when it cannot be told |
| `response(...)` | `"filter"` |

The script never sees the proxy's own answers or other filters' short-circuits as `res`
(`on_failure` makes the former), and filters after it (including a cache placed last, as
`--cache-dir` does) may still replace the response: `ActivityTracker`s and the access log report
the final source.

`ctx.timings` is a read-only snapshot, taken when read, of the exchange's
[timings](../observability/activity-tracking.md#observability) in milliseconds: `dns_ms`, `connect_ms`, `tls_ms` (towards the server),
`client_tls_ms`, `ttfb_ms` (to the first byte of the server's response) and `total_ms` (to the
last byte sent to the client). Each is a float, or `None` for a phase that did not happen or has
not happened yet: in `on_request` only `client_tls_ms` can be known, in `on_response` and
`on_failure` the server phases so far, and `total_ms` only in `on_websocket_frame` (after the
upgrade's response). A request on a reused connection has no `dns_ms`, `connect_ms` or `tls_ms`;
inside an intercepted session they belong to the `CONNECT`.

Log slow servers, and tell the client how long the server took:

```python
def on_response(req, res, ctx):
    t = ctx.timings
    if t.ttfb_ms == None:
        return None
    if t.ttfb_ms > 1000:
        log.warn("%s: first byte after %d ms (dns %s, connect %s, tls %s), %s from the %s" % (
            req.url, t.ttfb_ms, t.dns_ms, t.connect_ms, t.tls_ms, res.upstream_status, res.source))
    res.headers["Server-Timing"] = "upstream;dur=%d" % t.ttfb_ms
    return None
```

## The exchange's trace

With a tracer ([OpenTelemetry](../observability/opentelemetry.md)), `ctx.trace_id` and
`ctx.span_id` are the exchange's trace id and the proxy's span id for it, in hex (`None` without
one), and the `trace` module adds to that span: `trace.set_attribute(key, value)` (a string, bool,
int, float or a list of those), `trace.add_event(name, attributes={})`, and
`trace.is_recording()`, false when the exchange is not sampled and the calls would be ignored. In
the TCP, UDP and QUIC hooks they add to the span of the tunnel or flow; in hooks that run for no
exchange (`upstream`, `quic_message_length`) they do nothing. The span's
[limits](../observability/opentelemetry.md) bound what a script adds.

Each hook call for a sampled exchange is also a span of its own, `starlark <hook>` (INTERNAL, a
child of the exchange's, tunnel's or flow's span), with `starlark.hook`, `starlark.script`,
`starlark.steps`, `starlark.alloc_bytes` and, when a [budget](#script-budgets) stopped it,
`starlark.budget_exceeded` (`steps`, `memory` or `time`); a call that failed has an error status
with its message. What `trace.set_attribute` and `trace.add_event` add goes on the exchange's span,
not on the hook call's: it describes the exchange, and stays in one place however many hooks see
it. Exchanges that are not sampled, and proxies without a tracer, get no hook spans and pay nothing
for them.

```python
def on_request(req, ctx):
    trace.set_attribute("tenant", req.headers.get("x-tenant", "none"))
    if trace.is_recording() and req.path.startswith("/admin"):
        trace.add_event("admin.access", {"user": ctx.user or "anonymous"})
    req.headers["X-Trace-Id"] = ctx.trace_id or "untraced"
```

## Standard library

Scripts can `load()` a Python-compatible standard library, ported from
[starlarky](https://github.com/verygoodsecurity/starlarky) and running on the JDK alone (no
dependency besides the interpreter's Guava). Load a module by its label, `@stdlib//<module>` or
`@vendor//<module>`, and name the bindings to take from it:

```python
load("@stdlib//hmac", "hmac")
load("@stdlib//urllib/parse", "parse")

# SECRET, from --script-var(-file), signs links as hmac_sha256(SECRET, path + expires)
def on_request(req, ctx):
    query = parse.parse_qs(req.query)
    expires = query.get("expires", ["0"])[0]
    signature = query.get("signature", [""])[0]
    expected = hmac.new(bytes(SECRET), bytes(req.path + expires), "sha256").hexdigest()
    if not hmac.compare_digest(signature, expected):
        return response(403, "bad signature\n")
    if int(expires) < time.now():
        return response(410, "link expired\n")
    return None
```

| Module | |
|---|---|
| `base64`, `binascii`, `codecs`, `struct`, `zlib` | Python's APIs over bytes (`zlib` on `java.util.zip`, including gzip and raw deflate streams) |
| `hashlib`, `hmac` | `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`, `sha3_224`…`sha3_512`, `new(name)`, `pbkdf2_hmac`; `hmac.new`/`digest`/`compare_digest` (the JDK's `MessageDigest` and `Mac`) |
| `json` | `dumps`/`loads` and `encode`/`decode`/`indent` (the predeclared `json`, plus Python's names; keys are sorted) |
| `re` | Python's `re`: `compile`, `match`, `search`, `fullmatch`, `findall`, `finditer`, `sub`/`subn`, `split`, `escape`, flags, match objects (see below) |
| `urllib/parse`, `urllib/request` | `urlparse`, `urlsplit`, `urljoin`, `quote`, `unquote`, `urlencode`, `parse_qs`, ...; `Request` objects (no network access) |
| `collections`, `dicts`, `enum`, `functools`, `itertools`, `operator`, `sets`, `types` | containers and functional helpers |
| `string`, `textwrap`, `reprlib`, `csv`, `io` (`StringIO`, `BytesIO`) | text |
| `math`, `random`, `uuid` | `random` and `uuid4` use `SecureRandom` (no seeding) |
| `xml/etree/ElementTree` | parsing, building, `find`/`findall` with ElementPath, serializing (a pure-Starlark parser) |
| `zipfile` | reading and writing archives in memory (stored and deflated; `bz2` is a stub) |
| `builtins`, `larky`, `sys` | Python builtins that Starlark lacks (`builtins.bytes(s, "latin-1")`, ...), and starlarky's helpers (`larky.struct`, `larky.mutablestruct`, ...) |
| `@vendor//option/result` | Rust-style `Ok`/`Error` results, which the library returns internally |
| `@vendor//asserts`, `six`, `escapes`, `multidict`, `luhn` | test assertions, compatibility helpers, case-insensitive multi-dicts, Luhn checksums |

What loading changes, and what it does not:

- A module is compiled and run once per process, frozen, and shared by every script and
  connection; loading it costs nothing after the first time. Its functions run in the calling
  hook, within the hook's step and time limits, under the same sandbox (no files, network or
  processes). A module's own top level is bounded too (200 million steps, 60 seconds).
- A script that loads anything runs with Python's string semantics, which the library relies on:
  `"%5.2f" % x` and the other printf flags, Unicode-aware `upper()`/`isalpha()`/..., Python's
  bounds for `find`/`count`, and CPython's codec names for `bytes.decode`. Scripts without
  `load` statements behave exactly as before.
- The predeclared built-ins (`re`, `json`, `base64`, `digest`, ...) stay available without
  `load`. A loaded name may hide one: after `load("@stdlib//json", "json")`, `json` is the
  library's; `load("@stdlib//json", py_json="json")` keeps both.
- Typed scripts are checked as usual; values from the library are untyped (`Any`).
- Only the library can be loaded: `load("helpers.star", ...)` is an error, as are unknown modules
  (the message lists the available ones) and cycles.
- The library's `re` translates Python patterns to `java.util.regex`. Unlike starlarky's (RE2),
  it supports look-ahead, look-behind, backreferences, atomic groups and possessive quantifiers;
  conditional groups (`(?(1)a|b)`) are rejected. `\d`, `\w`, `\s` and `\b` are Unicode-aware
  for str patterns (ASCII with `re.ASCII` or for bytes), and `.`, `^` and `$` treat only `\n` as
  a line end, as in Python. Java's engine backtracks, so a pathological pattern can take
  exponential time: matching is abandoned at the hook's deadline with
  `re.error: regular expression ran past the deadline`. Matches on bytes are returned as str
  (Latin-1), as in starlarky.

Not included: starlarky's cryptography, JOSE/JWT, OpenSSL, OpenPGP and XML-signature modules
(`Crypto`, `cryptography`, `jose`, `OpenSSL`, `OpenPGP`, `xmlsig`, `lxml`), which need
BouncyCastle, Tink or WSS4J; `iso8583`, `jks` and the company-specific modules of its `vgs`
namespace; and `hashlib`'s BLAKE2 and SHAKE, which the JDK lacks (`hashlib.blake2b(...)` fails
with `unsupported hash type`). starlarky's own tests run in the build against the port
(`StarlarkyStdlibTest`), with the few known differences listed there.

<a id="script-budgets"></a>

## Budgets and measurements

Every hook call is bounded, and measured, three ways:

| budget | option (`StarlarkScript.Limits`) | default | checked |
|---|---|---|---|
| interpreter steps | `--script-max-steps <n>` (`maxSteps`) | 10000000 | at every statement and expression |
| wall-clock time | `--script-max-time <time>`, as `250ms`, `5s` or `1m` (`timeout`); `0` for none | `5s` | every 64 steps, and as they go by long-running builtins (`re`, the standard library's `re`, `hashlib.pbkdf2_hmac`) |
| bytes of values created | `--script-max-alloc <bytes>`, as `512k`, `64m` or `1g` (`maxAllocBytes`); `0` for none | `256m` | where values are made |

A call past a budget fails with an error (`too many steps`, `past expiration date` or `memory
budget exceeded`), which is handled as any failing hook is (below): the call stops at its next
check, cooperatively, and no thread is killed. Once past a budget, every later step of the call
fails too, so a script cannot catch the error and go on. `--script-name <name>`
(`ScriptedProxy.Builder.statsName`) names the script in its stats; by default it is the file name
without `.star`.

The bytes are an **estimate of what a call creates, not a measure of the heap**: the JVM cannot
count a virtual thread's allocations, so the interpreter counts the values it makes, at about
what they take on a 64-bit JVM: a string two bytes a character plus its objects (a Latin-1 string
takes half that), bytes their length, lists and tuples a reference a slot (a list each time its
array grows), dicts about 48 bytes an entry, structs and objects their fields; the strings and
objects builtins return (`json`, `re`, `base64`, `digest`, `codecs`, `url`, `protobuf`, `grpc`,
`dns`, the standard library's natives) count too, and ints, floats and booleans do not. Values
that become garbage stay counted, so the budget bounds the work a call does with memory rather
than what it keeps. A size known in advance is counted before the value is made, so
`"x" * 10**9`, `[0] * 10**9` or `list(range(10**9))` fail at once without allocating; `replace`,
`re.sub` and `json.encode` check as their output grows. The default leaves room for a buffered
10 MiB body (about 20 MiB as a string) to be copied several times, and for the heaviest tests of
the standard library (about 150 MB in one call), while stopping runaway allocation long before it
fills a heap.

With metrics, each script's calls are counted per hook, in `hooks.starlark.<script>.<hook>.*`
(see [Metrics](../observability/metrics.md#metrics-envoy-compatible-stats)): `invocations`, `errors`, `latency_us`, the
histograms `steps` (in powers of ten up to the step limit) and `alloc_bytes` (in powers of four
from 1 KiB), and `budget_exceeded.steps`, `.memory` and `.time`. Each exchange adds its calls up
(`FlowContext.scriptStats()`: calls, time, steps and bytes), which a script reads as
`ctx.script_stats` and the access log shows with `%MP_SCRIPT_CALLS%`, `%MP_SCRIPT_TIME%`
(milliseconds), `%MP_SCRIPT_STEPS%` and `%MP_SCRIPT_ALLOC%`. A `ScriptCallObserver`
(`HttpProxyServerBootstrap.withScriptCallObserver`, or `ScriptedProxy.Builder.observer`) sees
each call start, and end with its steps, bytes, time, exhausted budget and error: the place for
tracing to make a span of each call.

```python
def on_response(req, res, ctx):
    s = ctx.script_stats  # the calls before this one, here on_request's
    res.headers["X-Script"] = "%d calls, %d steps, %d bytes" % (s.calls, s.steps, s.alloc_bytes)
```

Measuring costs little: without metrics, an exchange, an observer or budgets, a call reads a few
fields more, and counting allocations is a field addition where values are made (a thread-local
lookup where the interpreter does not hand its code the thread: list growth, tuples, dicts and
bytes); a representative hook (80 steps, 1 KB of values) runs within a few percent of its speed
before counting.
