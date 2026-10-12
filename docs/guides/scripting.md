# Scripting with Starlark

Drive the proxy from a sandboxed [Starlark](https://github.com/bazelbuild/starlark) script: answer,
rewrite and route requests, decide what to intercept, authenticate clients, and see WebSocket,
HTTP/2 and HTTP/3 frames, raw TCP, UDP and QUIC traffic. This page shows how to run a script and
gives worked examples per hook family; the [Starlark API](../reference/starlark-api.md) lists every
hook, object and built-in. New to scripting? Start with [Your first Starlark
script](../getting-started/first-script.md).

## Running a script

The optional `microproxy-starlark` module runs proxy logic written in
[Starlark](https://github.com/bazelbuild/starlark/blob/master/spec.md), the Python dialect Bazel
uses for configuration. Scripts are sandboxed: they have no file, network or process access,
cannot change global state after loading, and each hook call is limited in steps, wall-clock
time and the bytes of values it creates (10 million steps, 5 seconds and 256 MiB by default; see
[Budgets and measurements](../reference/starlark-api.md#script-budgets)). One loaded script is shared by every connection.

```python
# proxy.star
BLOCKED = ["ads.example.com", "tracker.example.net"]

def on_request(req, ctx):
    if req.host in BLOCKED:
        return response(403, "blocked\n")
    req.headers["X-Client"] = ctx.client_ip
    ctx.vars["started"] = time.monotonic()

def on_response(req, res, ctx):
    res.headers["X-Elapsed-Ms"] = str(int((time.monotonic() - ctx.vars["started"]) * 1000))
    if res.text != None and "Example Domain" in res.text:
        res.text = res.text.replace("Example Domain", "Scripted Domain")

def upstream(req, ctx):
    if req.host.endswith(".onion"):
        return "socks5://127.0.0.1:9050"
    return None  # the default route (--upstream-proxy, or direct)

def allow_mitm(req, ctx):
    return not req.host.endswith(".bank.example")
```

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.2.0
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --mitm --script proxy.star
```
<!-- x-release-please-end -->

Or from Java, install one `ScriptedProxy` as both the filters source and the chained proxy
manager, and as the authenticator when the script defines `authenticate` (`--script` does this
by itself):

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("proxy.star")).build();
HttpProxyServerBootstrap bootstrap = MicroProxy.bootstrap().withFiltersSource(script).withChainProxyManager(script);
if (script.definesAuthenticate()) bootstrap.withProxyAuthenticator(script);
bootstrap.start();
```

## Hooks at a glance

All hooks are optional; a script defines the ones it needs. The [hooks
table](../reference/starlark-api.md#hooks) says when each is called and what it returns, and the
reference describes the [objects](../reference/starlark-api.md#objects) they receive (`req`,
`res`, `ctx`, `frame`, `msg`, ...), the [built-ins](../reference/starlark-api.md#built-ins), the
[`protobuf`, `grpc`](../reference/starlark-api.md#protobuf-and-grpc) and
[`dns`](../reference/starlark-api.md#dns) modules, [where a response came from and its
timings](../reference/starlark-api.md#where-a-response-came-from-and-how-long-it-took), the
[`trace` module](../reference/starlark-api.md#the-exchanges-trace), the [standard
library](../reference/starlark-api.md#standard-library) and the [budgets](../reference/starlark-api.md#script-budgets).
Scripts' own metrics (the `stats` module) are in [Script
stats](../observability/metrics.md#script-stats).

| Family | Hooks | Example |
|---|---|---|
| HTTP | `on_request`, `on_response`, `buffer_request`, `buffer_response` | [Running a script](#running-a-script) |
| Routing and interception | `upstream`, `allow_mitm`, `on_client_hello` | [Deciding by the ClientHello](#deciding-by-the-clienthello) |
| Failures | `on_failure` | [Answering failures](#answering-failures) |
| Authentication | `authenticate` | [Authenticating clients](#authenticating-clients) |
| WebSockets | `on_websocket_frame`, `on_websocket_message` | [WebSocket examples](#websocket-examples), [WebSocket message examples](#websocket-message-examples) |
| HTTP/2 and HTTP/3 frames | `on_frame` | [HTTP/2 and HTTP/3 frames](#frames) |
| Raw TCP | `on_tcp_start`, `on_tcp_message`, `on_tcp_end` | [TCP hooks](#tcp-hooks) |
| UDP (CONNECT-UDP) | `on_udp_start`, `on_udp_message`, `on_udp_end` | [UDP hooks](#udp-hooks) |
| QUIC | `on_quic_start`, `on_quic_stream_data`, `on_quic_message`, `on_quic_datagram`, `on_quic_end`, `quic_message_length` | [QUIC hooks](#quic-hooks) |

## Deciding by the ClientHello

`allow_mitm` runs when the `CONNECT` arrives, before the client
has said which server name it wants. `on_client_hello` runs once it has, and later hooks of the
session see the same ClientHello as `ctx.client_hello`:

```python
def on_client_hello(hello, ctx):
    # Banks keep their own certificates: tunnel them untouched.
    return not (hello.sni or "").endswith(".bank.example")

def on_request(req, ctx):
    hello = ctx.client_hello
    if hello != None:
        req.headers["X-Client-Alpn"] = ",".join(hello.alpn)
```

## Answering failures

`on_failure` replaces the proxy's plain-text answers, and leaves the rest
to the [`FailureResponder`](filters.md#failure-responses) or the default by returning `None`:

```python
def on_failure(req, failure, ctx):
    if failure.kind in ["unresolved_host", "connect_failed"]:
        return response(502, "%s is unreachable: %s\n" % (failure.host, failure.message),
                        headers={"Retry-After": "30"})
    if failure.kind == "server_timeout":
        return response(504, json.encode({"error": "timeout", "host": failure.host}),
                        content_type="application/json")
    return None  # the FailureResponder's answer, or the proxy's default
```

## Authenticating clients

A script that defines `authenticate` decides who may use the proxy
(see [Proxy authentication](authentication.md)). `req` is read-only there, and still carries
`Proxy-Authorization`, which the proxy removes before the other hooks see the request. `ctx.user`
is the user the connection authenticated as before, if any; `ctx.vars` is not shared with the
other hooks, whose `ctx.user` is the user it accepts. It fails closed: a failing or timed-out
call, an empty string or any other value rejects the request with the default `407` and is
logged, and so is every request if a reload removes `authenticate`. By default the first
accepted request authenticates its connection; `AUTHENTICATE_EVERY_REQUEST = True` checks every
request.

Bearer tokens, compared in constant time. Never write secrets into a script: here they come from
constants (below), and only their SHA-256 digests are given to the proxy:

```python
# TOKENS = "alice:<sha256 of alice's token>,bob:<sha256 of bob's token>", from --script-var(-file)
USERS = [entry.split(":") for entry in TOKENS.split(",")]

def authenticate(req, ctx):
    value = req.headers.get("Proxy-Authorization", "")
    if value.startswith("Bearer "):
        presented = digest.sha256(value[len("Bearer "):].strip())
        for user, expected in USERS:
            if digest.equal(presented, expected):
                return user
    return response(407, "a valid token is required\n",
                    headers={"Proxy-Authenticate": 'Bearer realm="proxy"'})
```

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.2.0
echo "TOKENS=alice:$(printf %s "$ALICE_TOKEN" | sha256sum | cut -d' ' -f1)" > tokens.properties
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --script auth.star --script-var-file tokens.properties
```
<!-- x-release-please-end -->

## Constants

Values a script needs but should not contain (tokens, host lists, per-site
settings) come from outside as read-only globals. On the command line, `--script-var NAME=VALUE`
(repeatable) gives a string, and `--script-var-file file.properties` reads a properties file;
later options win. Arguments are visible to other local users (`ps`), so put secrets in a file.
From Java, `ScriptedProxy.Builder.constants(Map)` also takes ints, booleans, and lists and dicts
of these:

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("auth.star"))
        .constants(Map.of("TOKENS", System.getenv("PROXY_TOKENS"), "MAX_BODY", 1 << 20,
                "ALLOWED", List.of("example.com", "example.org")))
        .build();
```

Constants are frozen, predeclared like the built-ins (so the type checker knows their types),
and cannot be assigned by the script. A name must be an identifier that does not hide a built-in
(`len`, `json`, `Request`, ...); a script that uses a constant nobody set does not load. They
are kept when the script reloads.

## WebSocket examples

`on_websocket_frame` gets the upgrade request, the frame and the
context. Frames from the client and from the server come through the same hook (`frame.from_client`
tells them apart) and share `ctx.vars`, so a script can keep state for the whole connection.

Redact a field in a JSON protocol, both ways:

```python
def on_websocket_frame(req, frame, ctx):
    if frame.type != "text" or not frame.text.startswith("{"):
        return None
    msg = json.decode(frame.text)
    if "token" in msg:
        msg["token"] = "<redacted>"
        frame.text = json.encode(msg)
```

Block client commands on one endpoint, and drop pings the server sends:

```python
def on_websocket_frame(req, frame, ctx):
    if req.path == "/admin/ws" and frame.from_client and frame.type == "text":
        if frame.text.startswith("DELETE "):
            log.warn("blocked %s from %s" % (frame.text, ctx.client_ip))
            return False
    if frame.type == "ping" and not frame.from_client:
        return False  # the proxy forwards nothing; the client simply never sees it
```

Number the messages in a chat, with types (see below):

```python
def on_websocket_frame(req: Request, frame: WebSocketFrame, ctx: Context) -> bool | None:
    if frame.type != "text" or frame.from_client:
        return None
    n: int = ctx.vars.get("n", 0) + 1
    ctx.vars["n"] = n
    frame.text = "#%d %s" % (n, cast(str, frame.text))
    return None
```

Binary protocols work on `frame.payload` (bytes): for example, replace a magic prefix with
`frame.payload = b"v2" + frame.payload[2:]`. Frames over the buffer limit
(`withMaxWebSocketFrameBufferSize`, 1 MiB by default) arrive with `truncated` set and no payload;
they can be forwarded or dropped but not rewritten. A failing hook is logged and the frame is
forwarded unchanged.

## WebSocket message examples

`on_websocket_message(msg, ctx)` sees whole messages: a message
split into continuation frames arrives joined, and one compressed with permessage-deflate arrives
inflated, so a hook never has to reassemble or decompress anything. It follows `on_frame`'s
convention: change `msg.text` or `msg.payload` in place and return `None` (or `msg`) to send it,
`False` to drop it, another message to replace it, or a list of messages to send in its place.
Each message in a list goes the way its `from_client` says, so a script can answer a peer itself
with `websocket_message(..., from_client=not msg.from_client)`. `ctx.vars` is shared with
`on_request` and `on_websocket_frame` for the life of the connection; the hook does not get the
request, so keep what you need from it in `ctx.vars`. When a script defines both hooks, each frame
goes through `on_websocket_frame` first and `on_websocket_message` sees the message joined from
what that returned. A failing hook is logged and the message is sent unchanged.

Rewrite a field in JSON text messages from the client:

```python
def on_websocket_message(msg, ctx):
    if msg.type != "text" or not msg.from_client or not msg.text.startswith("{"):
        return None
    data = json.decode(msg.text)
    if data.get("room") == "staging":
        data["room"] = "production"
        msg.text = json.encode(data)
```

Drop binary messages over 64 KiB, and tell the client why:

```python
MAX_UPLOAD = 64 * 1024

def on_websocket_message(msg, ctx):
    if msg.type == "binary" and msg.length > MAX_UPLOAD:
        log.warn("dropped a %d-byte upload from %s" % (msg.length, ctx.client_ip))
        return [websocket_message('{"error": "upload too large"}', from_client=False)]
    return None
```

Log a compressed chat as plain text, with types:

```python
def on_request(req: Request, ctx: Context) -> Response | None:
    ctx.vars["chat"] = req.path
    return None

def on_websocket_message(msg: WebSocketMessage, ctx: Context) -> None:
    if msg.type == "text":
        sender = "client" if msg.from_client else "server"
        log.info("%s %s: %s" % (ctx.vars["chat"], sender, cast(str, msg.text)))
    return None
```

Messages larger than `withMaxWebSocketMessageSize` (16 MiB by default), joined or inflated, fail
the connection with close code 1009; see [WebSocket frames and
messages](websockets.md#websocket-frames-and-messages) for the rest of the rules.

<a id="frames"></a>

## HTTP/2 and HTTP/3 frames

A script that defines `on_frame(frame, ctx)` sees HTTP/2 and
HTTP/3 frames on live connections ([Frame interception](frame-interception.md) and
[HTTP/3 frames](frame-interception.md#http3-frame-interception) describe where, and which changes the proxy accepts) and HTTP/3
frames run through an `Http3FramePipeline`. `--script` installs it
as the proxy's frame interceptor only when the script defines `on_frame` when it loads, so other
scripts cost nothing per frame (a reload that removes the hook passes frames on unchanged; one
that adds it takes effect after a restart). From Java: `bootstrap.withFrameInterceptor(script.frameInterceptor())`
when `script.definesFrameHook()`, and `Http3FramePipeline.builder(script.frameInterceptor())` for
HTTP/3. Like `on_websocket_frame`, the hook edits the frame in place: returning `None` (or the
frame) passes it on with its changes, so a hook that only looks drops nothing; `False` drops it,
and a list of frames replaces it (`[frame, extra]` adds a frame after it; `[]` drops it).

- `frame`: `protocol` (`"h2"` or `"h3"`), `type` (`"DATA"`, `"HEADERS"`, `"PRIORITY"`,
  `"RST_STREAM"`, `"SETTINGS"`, `"PUSH_PROMISE"`, `"PING"`, `"GOAWAY"`, `"WINDOW_UPDATE"`,
  `"CANCEL_PUSH"`, `"MAX_PUSH_ID"`, or `"UNKNOWN"` for extension and grease frames), `type_code`,
  `stream_id`, `end_stream`, `ack`, `direction` (`"from_client"`, `"to_client"`, `"from_server"`,
  `"to_server"`; `None` for frames the script made), and, where the frame type has them:
  `payload` and `text` (DATA and extension frames; assignable; `text` is `None` for a payload that
  is not UTF-8), `headers` (HEADERS: a `Headers`, live, pseudo-headers included, names lower-cased
  as they are set), `settings` (a live dict of name to value: `"MAX_CONCURRENT_STREAMS"`, ...,
  `"0x..."` for others), `error_code` (assignable) and `error` (its name, RST_STREAM and GOAWAY),
  `debug_data` (GOAWAY, assignable) and `last_stream_id` (GOAWAY). The others are `None`.
- `ctx`: `protocol`, `connection_id`, `stream_id`, `client_ip`, `client_port`, and `server` (the
  server's `host:port` for frames to and from servers, else `None`). Frames from the two
  directions and from many streams are seen concurrently; there is no `ctx.vars`.
- A failing hook, a wrong return value or a result that breaks the rules is logged, and the frame
  passed on unchanged.

Rewrite a header in the HEADERS frames clients send:

```python
def on_frame(frame, ctx):
    if frame.type == "HEADERS" and frame.direction == "from_client":
        frame.headers["user-agent"] = "MicroProxy"
        frame.headers.remove("x-debug")
```

Redact card numbers in DATA frames, in both directions. A pattern split across two frames is not
seen; a body whose length changes needs its `content-length` gone:

```python
def on_frame(frame, ctx):
    if frame.type == "HEADERS":
        frame.headers.remove("content-length")  # redacting changes the body's length
    elif frame.type == "DATA" and frame.text != None:
        frame.text = re.sub(r"\b[0-9]{13,16}\b", "<card>", frame.text)
```

Drop PRIORITY and extension frames:

```python
def on_frame(frame, ctx):
    if frame.type in ("PRIORITY", "UNKNOWN"):
        return False
```

Log what servers say about their connections:

```python
def on_frame(frame, ctx):
    if frame.direction != "from_server":
        return None
    if frame.type == "SETTINGS" and not frame.ack:
        log.info("%s settings: %s" % (ctx.server, frame.settings))
    elif frame.type == "GOAWAY":
        log.warn("%s goes away: %s after stream %d (%s)" % (
            ctx.server, frame.error, frame.last_stream_id, frame.debug_data))
```

Add frames: trailers after every response's last DATA frame (END_STREAM moves to them), and an
extension frame:

```python
def on_frame(frame, ctx):
    # Trailers after the last DATA frame of every response, and a hint before it.
    if frame.type == "DATA" and frame.direction == "to_client" and frame.end_stream:
        hint = h2.unknown(0xf0, 0, "checked")
        return [frame, hint, h2.headers(frame.stream_id, {"x-proxied-by": "MicroProxy"})]
```

Live HTTP/3, on a reverse proxy serving it (`--http3`): the client's requests get a field, and
the responses' bodies are redacted, so their `content-length` goes:

```python
def on_frame(frame, ctx):
    if frame.protocol != "h3":
        return None
    if frame.type == "HEADERS" and frame.direction == "from_client" and ":method" in frame.headers:
        frame.headers["x-from-frame"] = "stream %d" % ctx.stream_id
    elif frame.type == "HEADERS" and frame.direction == "to_client" and ":status" in frame.headers:
        frame.headers.remove("content-length")  # the DATA below changes the body's length
        frame.headers["x-h3-frame"] = "edited"
    elif frame.type == "DATA" and frame.direction == "to_client" and frame.text != None:
        frame.text = frame.text.replace("secret", "[redacted]")
```

The same kind of hook over HTTP/3 relayed by other means, through the pipeline:

```python
def on_frame(frame, ctx):
    if frame.protocol != "h3":
        return None
    if frame.type == "HEADERS" and ":method" in frame.headers:
        frame.headers["x-seen-by"] = "MicroProxy"
    elif frame.type == "DATA" and frame.text != None:
        return [frame, h3.data(" (checked)")]
    elif frame.type == "SETTINGS":
        frame.settings["MAX_FIELD_SECTION_SIZE"] = 16384
```

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("frames.star")).build();
Http3FramePipeline pipeline = Http3FramePipeline.builder(script.frameInterceptor()).build();
pipeline.requestStream(0, capturedRequestStream, rewritten);
```

With types: `Frame` and `FrameContext`. `headers`, `settings`, `payload` and the like are typed
`... | None`, so typed code casts them:

```python
def on_frame(frame: Frame, ctx: FrameContext) -> list[Frame] | bool | None:
    if frame.type == "UNKNOWN":
        return False
    if frame.type == "HEADERS" and frame.direction == "from_client":
        headers = cast(Headers, frame.headers)
        headers["x-stream"] = str(ctx.stream_id)
    return None
```

## TCP hooks

A script that defines `on_tcp_start(ctx)`, `on_tcp_message(msg, ctx)` or
`on_tcp_end(ctx)` sees the bytes of raw TCP tunnels, decrypted where the proxy intercepted TLS
that does not carry HTTP ([Raw TCP streams](tcp-hooks.md#raw-tcp-streams) describes which tunnels). As with
`on_frame`, `--script` installs the TCP interceptor only when the script defines one of these
hooks when it loads, so other scripts leave tunnels on their fast path. From Java:
`bootstrap.withTcpInterceptor(script.tcpInterceptor())` when `script.definesTcpHooks()`.

- `msg`: `data` (bytes) and `text` (`None` when the bytes are not UTF-8), both assignable,
  `from_client` and `timestamp` (seconds since the epoch); `msg.with_data(data)` and
  `msg.with_text(text)` make changed copies. Its type is `TcpMessage`. TCP has no message
  boundaries: a message is whatever one read returned, so a line or a command may arrive in
  pieces, or several in one message.
- `ctx`: `connection_id`, `client_ip`, `client_port`, `host`, `port`, `server` (`host:port`),
  `tls` (whether the proxy decrypted the client's TLS), `sni` and `alpn` (or `None`), `vars`, a
  dict that lives as long as the tunnel, and `error`, why the tunnel failed (`None` otherwise, and
  before `on_tcp_end`). `ctx.send(from_client, data)` adds bytes as if that side had sent them
  (to the server when `from_client` is `True`), after the message being handled when sent in the
  same direction. Its type is `TcpContext`.
- The hooks of one tunnel run one at a time, though its two directions are read concurrently. A
  failing `on_tcp_message`, or one returning something else, is logged and the bytes passed on
  unchanged.

Rewrite a server's greeting, such as an SMTP banner, which arrives before the client says
anything:

```python
def on_tcp_message(msg, ctx):
    # The server's first message is its greeting.
    if not msg.from_client and not ctx.vars.get("greeted"):
        ctx.vars["greeted"] = True
        if msg.text != None:
            return msg.text.replace("ESMTP", "ESMTP (via MicroProxy)")
```

Log a line-based protocol (POP3, SMTP, IMAP, Redis), a line at a time whatever the reads:

```python
def on_tcp_start(ctx):
    log.info("%s opened by %s (tls %s, sni %s)" % (ctx.server, ctx.client_ip, ctx.tls, ctx.sni))

def on_tcp_message(msg, ctx):
    # TCP has no message boundaries: keep a line's start until its end arrives.
    side = "C" if msg.from_client else "S"
    lines = (ctx.vars.get(side, "") + (msg.text or "")).split("\n")
    for line in lines[:-1]:
        log.info("%s: %s" % (side, line.rstrip("\r")))
    ctx.vars[side] = lines[-1]

def on_tcp_end(ctx):
    log.info("%s closed%s" % (ctx.server, "" if ctx.error == None else ": " + ctx.error))
```

Drop a command, answering it in the server's place:

```python
def on_tcp_message(msg, ctx):
    # Never let a POP3 client delete mail: answer DELE in the server's place.
    if msg.from_client and msg.text != None and msg.text.upper().startswith("DELE "):
        ctx.send(False, "-ERR deleting is disabled here\r\n")
        return False
```

With types: `TcpMessage` and `TcpContext`. `text` is typed `str | None`, so typed code casts it; a
returned message replaces the bytes with its own:

```python
def on_tcp_message(msg: TcpMessage, ctx: TcpContext) -> TcpMessage | str | bool | None:
    if msg.text == None:
        return None
    text = cast(str, msg.text)
    if msg.from_client:
        return msg.with_text(text.upper())
    ctx.vars["lines"] = ctx.vars.get("lines", 0) + text.count("\n")
    return text + "!"
```

## UDP hooks

A script that defines `on_udp_start(ctx)`, `on_udp_message(msg, ctx)` or
`on_udp_end(ctx)` sees the datagrams of [CONNECT-UDP flows](masque.md), which `--script`
then installs the UDP interceptor for (from Java: `bootstrap.withUdpInterceptor(script.udpInterceptor())`
when `script.definesUdpHooks()`). `msg` is a `UdpMessage`, one datagram, with the fields,
methods and results of a `TcpMessage` (`False` drops the datagram); `ctx` is a `UdpContext`:
`connection_id`, `client_ip`, `client_port`, `host`, `port`, `server`, `address` (what the
target's name resolved to) and `vars`, with `ctx.send(from_client, data)` to add a datagram.

```python
def on_udp_start(ctx):
    log.info("UDP flow to %s (%s) from %s" % (ctx.server, ctx.address, ctx.client_ip))

def on_udp_message(msg, ctx):
    # Drop the client's datagrams that mention "blocked"; tag the target's answers.
    if msg.text == None:
        return None
    if msg.from_client and "blocked" in msg.text:
        return False
    if not msg.from_client:
        return msg.text + " (via MicroProxy)"
```

## QUIC hooks

A script that defines `on_quic_start(ctx)`, `on_quic_stream_data(msg,
ctx)`, `on_quic_message(msg, ctx)`, `on_quic_datagram(msg, ctx)` or `on_quic_end(ctx)` sees the
streams and datagrams of QUIC that the proxy intercepts without speaking its protocol
([QUIC stream hooks](quic-hooks.md)).
`--script` installs the QUIC interceptor only when the script defines one of these hooks when it
loads, and only then is QUIC that offers no HTTP/3 intercepted rather than relayed (from Java:
`bootstrap.withQuicInterceptor(script.quicInterceptor())` when `script.definesQuicHooks()`).

- `msg`: a `QuicMessage`, with the fields, methods and results of a `TcpMessage`, and `stream_id`
  (`None` for a datagram) and `with_from_client`: the bytes of one read of a stream for
  `on_quic_stream_data` (a stream has no message boundaries either), one datagram for
  `on_quic_datagram`.
- `ctx`: a `QuicContext`: `connection_id`, `client_ip`, `client_port`, `host`, `port`, `server`,
  `address` (where the proxy connected), `sni`, `alpn`, `masque` (whether the QUIC came inside a
  CONNECT-UDP flow), `vars`, a dict that lives as long as the connection and that its streams
  share, and `error` in `on_quic_end` after a failure. In `on_quic_stream_data`, `stream_id` (on
  the client's connection), `bidirectional` and `client_initiated` name the stream (`None`
  elsewhere), and `ctx.send(from_client, data)` adds bytes to it. `ctx.send_datagram(from_client,
  data)` adds a datagram.
- The hooks of one connection run one at a time, though its streams are read concurrently. A
  failing hook is logged and the bytes passed on unchanged.
- `on_quic_message(msg, ctx)` sees the whole messages of the streams that
  [QUIC message framing](quic-hooks.md#quic-message-framing) cuts into messages: by default those of DNS over
  QUIC (ALPN `doq`), whose messages have a two-byte length, and those `--quic-framing` names
  (`--quic-framing myproto=varint,chat=lf`). `--script` frames streams only when the script
  defines `on_quic_message` when it loads (from Java: `script.quicInterceptor()` overrides
  `streamMessage` only then), and on those streams `on_quic_stream_data` is not called. `msg` is a
  `QuicMessage` whose `data` is the payload, without its length prefix or delimiter, with
  `stream_id` (`None` only for datagrams); `with_data`, `with_text` and `with_from_client` make
  copies. It returns as `on_websocket_message` does, each message going the way its
  `from_client` says (`msg.with_from_client(False)` answers the client on the same stream), and
  what it returns is framed again, with a length prefix computed for the new payload. A message
  larger than `--quic-max-message-size` (1 MiB) resets the stream with
  `--quic-message-error-code` (2). `ctx.send(from_client, data)` still sends bytes unframed.

```python
def on_quic_start(ctx):
    log.info("QUIC %s to %s for %s" % (ctx.alpn, ctx.server, ctx.client_ip))

def on_quic_stream_data(msg, ctx):
    # A stream is a byte stream, as TCP is: a message is whatever one read returned.
    if not msg.from_client and msg.text != None:
        return msg.text.replace("secret", "******")

def on_quic_datagram(msg, ctx):
    if msg.from_client and msg.text == "blocked":
        return False
```

DNS over QUIC through a transparent QUIC port, logging each query and answering a blocked name
with `0.0.0.0` by rewriting the server's answer (`--script doq.star`; `doq` is framed by default):

```python
BLOCKED = ["ads.example", "tracker.example"]

def on_quic_message(msg, ctx):
    # DNS over QUIC (ALPN doq): one DNS message each way on each stream.
    if ctx.alpn != "doq":
        return None
    m = dns.decode(msg.data)
    q = m["questions"][0]
    if msg.from_client:
        log.info("%s asks for %s %s" % (ctx.client_ip, q["name"], q["type"]))
    elif q["name"].lower() in BLOCKED:
        for answer in m["answers"]:
            if answer["type"] == "A":
                answer["data"] = "0.0.0.0"
                answer["ttl"] = 60
        msg.data = dns.encode(m)
```

A protocol of one's own, framed by the script (`--quic-framing tiny=script`): `quic_message_length`
gets the bytes kept of a stream direction and returns the length of the message they start with,
or `None` until it can tell; the message, its prefix included, goes to `on_quic_message` as it is,
and what that returns is sent as it is. A framer that fails resets the stream.

```python
def quic_message_length(data):
    # Each message: a byte with the length of what follows, then that many bytes.
    return 1 + data[0]

def on_quic_message(msg, ctx):
    # The message as quic_message_length cut it, its length byte included.
    if msg.from_client and msg.text != None:
        return msg.text.upper()
```

## Typed scripts

Scripts may use Starlark's type annotations, which are checked when the
script loads and again on each call. Unannotated code is not checked, so annotations can be added
one function at a time. The proxy's objects are named `Request`, `Response`, `Headers`,
`Context`, `WebSocketFrame`, `WebSocketMessage`, `Failure`, `Timings`, `Frame`, `FrameContext`,
`TcpMessage`, `TcpContext`, `UdpMessage`, `UdpContext`, `QuicMessage` and `QuicContext`:

```python
ALLOWED: list[str] = ["example.com", "example.org"]

def on_request(req: Request, ctx: Context) -> Response | None:
    if req.host not in ALLOWED:
        return response(403, "not allowed\n")
    req.headers["X-Client"] = ctx.client_ip
    return None

def on_response(req: Request, res: Response, ctx: Context) -> None:
    if res.text != None:
        text = cast(str, res.text)  # the checker does not narrow `str | None` after a test
        res.text = text.replace("http://", "https://")
```

A misspelt field (`req.hots`), an assignment of the wrong type (`req.uri = 3`), or a return of
the wrong type stops the script from loading, with the line and column. Arguments of the wrong
type to an annotated function fail the call. `body` and `text` are typed `bytes | None` and
`str | None`, since a streamed body has neither; `ctx.user`, `res.source` and `failure.host` are
`str | None`, `res.upstream_status` is `int | None`, and the fields of `ctx.timings` are
`float | None`.

## Errors and reloading

- A hook that fails is logged with its Starlark stack trace, and the client gets a bare `500`.
  A failing `allow_mitm` declines interception; a failing `upstream` gives `502`; a failing
  `on_failure` leaves the answer to the `FailureResponder` or the default; a failing
  `authenticate` rejects the request.
- A script file is re-read when it changes (checked at most once a second). An edit that does
  not compile is logged and the previous version stays in use. `--script-no-reload` turns this
  off.
- As in Bazel, `if` and `for` statements must be inside functions, and global values are frozen
  once the file has loaded.
