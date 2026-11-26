# Addons, HAR and replay

Ready-made filters ported from mitmproxy (map local and remote, modify bodies and headers, block
lists, anti-cache, sticky cookies) with mitmproxy's option syntax and flow filter expressions, plus
HAR recording and server and client replay. Use this page to change, record or replay traffic from
the command line without writing code.

## mitmproxy-style addons

`org.microproxy.extras` has ports of mitmproxy's request and response addons. Each is an
`HttpFiltersSource`, so they compose with each other, with your own filters and with scripts
through `HttpFiltersChain`, and each reads the same option syntax as mitmproxy:
`[|flow-filter]|subject|replacement`, where the first character is the separator (any character;
`/` in mitmproxy's documentation) and the filter is optional.

```java
bootstrap.withFiltersSource(HttpFiltersChain.of(
        BlockList.of("|~d ads\\.example\\.com|404", "|~u /beacon|444"),     // 444: close, no response
        AntiCache.create(),
        MapRemote.of("|https://api\\.example\\.com/|http://localhost:8000/"),
        MapLocal.of("|example.com/static/|/srv/static"),
        ModifyBody.of("|~s & ~t html|Example Domain|Local Domain"),
        ModifyHeaders.of("|~q|User-Agent|MicroProxy", "|~s|Server|"),      // empty value: remove
        StickyCookie.of("~d example.com")));
```

```bash
java -jar microproxy.jar --mitm --map-remote '|https://api\.example\.com/|http://localhost:8000/' \
    --map-local '|example.com/static/|/srv/static' --block-list '|~u /beacon|444' --anticache
```

| addon | command line | what it does |
|---|---|---|
| `MapLocal` | `--map-local [\|filter]\|url-regex\|file-or-dir` | answers from a file, or from a directory: the URL after the match (or the regex's first group) names the file; `index.html` for directories; a `Content-Type` from the extension; `404` when nothing matches; never outside the directory (`..`, absolute parts, links pointing out) |
| `MapRemote` | `--map-remote [\|filter]\|url-regex\|replacement` | replaces matches in the absolute URL (`\1` or `$1` for groups) and sends the request there, with `Host` to match; inside intercepted sessions too |
| `ModifyBody` | `--modify-body [\|filter]\|regex\|[@]replacement` | replaces matches in decoded request and response bodies (`~q` / `~s` pick one side); the replacement is literal, `@file` reads it from a file |
| `ModifyHeaders` | `--modify-headers [\|filter]\|name\|[@]value` | removes the header, then adds the value (none if empty), on requests and on server responses |
| `BlockList` | `--block-list \|filter\|status` | answers with an empty response of that status; `444` closes the connection without one (resets an HTTP/2 stream) |
| `AntiCache` | `--anticache` | removes `If-None-Match` and `If-Modified-Since`, so servers send whole responses |
| `StickyCookie` | `--stickycookie filter` | remembers every `Set-Cookie` (RFC 6265 `Domain`, `Path`, `Max-Age`/`Expires`, `Secure`) in one jar for all clients, and adds the cookies to requests the filter matches, keeping the client's own |

### Filter expressions

**Filter expressions** are a compact subset of mitmproxy's (`org.microproxy.extras.FlowFilter`):

| expression | matches |
|---|---|
| `~u regex`, or a bare `regex` | the URL (absolute; `https://` inside intercepted sessions), normalized: see below |
| `~d regex`, `~m regex` | the host, the method |
| `~h regex`, `~hq regex`, `~hs regex` | a `Name: value` header line of the request or response, the request, the response |
| `~t regex`, `~tq regex`, `~ts regex` | the `Content-Type` of either, the request, the response |
| `~b regex`, `~bq regex`, `~bs regex` | the decoded body of either, the request, the response |
| `~c code`, `~q`, `~s`, `~a`, `~all` | the response status; no response yet; a response; an asset (CSS, JavaScript, images, fonts); everything |
| `!x`, `x & y`, `x \| y`, `(x)` | not, and, or, grouping |

URL rules match a normalized URL, so a rule cannot be passed by spelling the same URL
another way:

- the scheme and host in lower case, without user info (`https://u@example.com/` is
  `https://example.com/`) and without a trailing dot on the host;
- the port as the proxy reads it: `:080`, `:+80` and an empty `:` are port 80, and the
  scheme's default port (`:80` for http, `:443` for https) is dropped;
- `%xx` escapes of unreserved characters (letters, digits, `-._~`) decoded, so `/%61ds/` is
  `/ads/`; other escapes stay escaped, in upper-case hex;
- dot segments removed from the path, escaped or not: `/x/../admin` and `/x/%2E%2E/admin`
  are `/admin`.

Escaped `/` and `\`, `;` parameters and empty segments (`//`) are left as they are, since
origins disagree on what they mean. A rule written for the old spelling (one with `%61`,
`:443` on https, `user@` or `/../`) may never match now; MicroProxy logs a warning when it
parses one. `~d` drops a trailing dot from the host as well.

`block_list` also blocks when a rule matches the URL with its query fully percent-decoded,
since origins decode query values: `|~u [?&]file=/files/x|403` blocks `?file=%2Ffiles%2Fx`.
Decoding never lets more through: an allow written as `|!~u ^https://example\.com/dl\?file=/ok$|403`
still blocks `/dl?file=%2Fok`. The query is decoded with `+` kept and with `+` read as a space, and
covers anything after a `#` too, so an allow for a query with a literal `+` (`?q=a+b`) needs `[+ ]`.
Decoded control characters stay as the origin sees them, and a form holding a line break is
tried with `.` crossing it and with `.` stopping at it: `|~u cmd=rm\s+-rf|403` blocks
`?cmd=rm%09-rf`, and `|~u "^(?!.*[?&]safe=1)"|403` blocks `?a=%0A&safe=1`. An allow whose `.` must span a line break in a query value (a multi-line form field) writes `(?s)` or `[\s\S]`, or it blocks those requests. Each decoding is also tried with escaped query delimiters
(`%26 %3D %23 %3B`) kept, so `[?&]file=/files/[^&]*\.exe` blocks `?file=%2Ffiles%2Fa%26b.exe`.
Query decoding is UTF-8; origins that read query bytes as ISO-8859-1 are not modelled. Origins
that split parameters on `;` need `[?&;]` in the rule. Write query rules in decoded form (`next=/home`, not `next=%2Fhome`): a deny
written escaped does not match the literal spelling, and an allow for a query that clients
escape must accept both spellings (`next=(/|%2F)home`). URL rules see the URL as one line: raw
control characters and non-ASCII bytes in the request are escaped (a raw `é` is `%C3%A9`, so a
path rule spells it `/caf%C3%A9/`; query rules can use `é`, since the decoded forms carry it), and `^` and `$` match
only at the URL's ends.

`!` binds tightest, then `&`, then `|`; expressions side by side are joined by "and" with the lowest
precedence, as in mitmproxy (`a b | c` is `a & (b | c)`). Regexes are `java.util.regex`, searched
anywhere and ignoring case; put one with spaces or `()~'"` in quotes. A backslash in quotes only
escapes the quote and itself, so `"\d+"` keeps its `\d` (pyparsing would drop it).

### Cost

The addons read heads only, so bodies keep the proxy's zero-copy relay. A body is buffered
only when a rule might need it, which the heads decide: `ModifyBody` buffers the messages a rule
might edit (and that it can decode; never event streams), and a filter that looks at a body
(`~bq secret`) buffers that body when the rest of the filter could still match. Body filters are
evaluated lazily, with three-valued logic: `~m GET & ~bq x` never buffers a `POST`. Request bodies
over the limit (10 MiB by default, `maxBodySize`) get `413`, as for any filter that buffers
requests; response bodies over it stream through unchanged.

The addon, HAR and replay options are command-line flags (and Java builders); properties files
do not take them.

### Order

The command line chains them as mitmproxy does: `--save-har`, `--warc-dir` and
`--log-http` first, then `--block-list` and `--anticache`, then a `--script`, then
`--server-replay`, `--map-remote`, `--map-local`, `--modify-body`, `--modify-headers` and
`--stickycookie`; the cache comes last. The first short-circuit wins, so a blocked request is never
replayed, and a script sees requests before they are mapped elsewhere.

### Leaving an intercepted session

Requests inside a `CONNECT` that the proxy intercepts normally
go to the `CONNECT` target. When a filter gives one an absolute URI of its own, as `MapRemote` does
and as a script does by assigning `req.uri = "https://other.example/..."`, the request goes to that
server instead: over TLS for `https://` (with the MITM manager's trust), with `Host` set to the new
authority, and on a server connection kept and pooled under the new target. Changing only `Host`
or an origin-form path keeps the request on the session's server. The session's
[ALPN mirroring](mitm.md#alpn-mirroring) still applies to the new server, and a plain HTTP session after
`CONNECT` and a [reverse proxy](reverse-proxy.md#reverse-proxy-mode) are left the same way. Absolute `https://`
URIs in plain forward requests are fetched over TLS too.

## HAR files

`org.microproxy.extras.HarRecorder` writes the exchanges it sees as an HTTP Archive (HAR 1.2), as
mitmproxy's `--set hardump=` and `save.har` do, for browser developer tools, HAR viewers and
[replay](#replaying-traffic):

```bash
java -jar microproxy.jar --mitm --save-har flows.har                         # written on exit
java -jar microproxy.jar --mitm --save-har flows.har --save-har-stream --save-har-filter '~d example.com'
```

```java
HarRecorder har = HarRecorder.builder(Path.of("flows.har")).filter(FlowFilter.parse("!~a")).build();
MicroProxy.bootstrap().withFiltersSource(HttpFiltersChain.of(har, otherFilters)).start();
// ... har.close() writes the file; har.save(path) writes a snapshot at any time.
```

- **Entries:** the request as the client sent it (method, absolute URL, version, headers, cookies,
  query string, `postData` with form `params`) and the response as the client received it (status,
  headers, cookies with `expires`, `redirectURL`, decoded content as text, or base64 with
  `"encoding": "base64"` for binary bodies). Also `serverIPAddress`, the client `connection` id,
  and `_source` (`server`, `filter`, `cache`, `replay` or `proxy`). Responses from filters, the
  cache and replays are recorded too; `CONNECT` tunnels are not. An exchange that ends without a
  response has status `0` and an `_error`.
- **Timings** come from [`FlowTimings`](../observability/activity-tracking.md#observability): `dns`, `connect` (including `ssl`, as HAR
  says), `send`, `wait` and `receive`, and `-1` for a phase that did not happen (no lookup or
  connect on a reused connection; inside an intercepted session the server handshake belongs to the
  `CONNECT`).
- **Bodies** are captured as they stream past, up to `maxBodySize` each (1 MiB by default,
  `--save-har-max-body`); a longer one is cut short and marked `_truncated`, and is not replayed.
  Capturing bodies turns off the zero-copy relay for recorded exchanges; `content(false)`
  (`--save-har-max-body 0`) records heads only and keeps it.
- **Memory:** by default every entry, bodies included, stays in memory until the file is written on
  exit (or `close()`), as with mitmproxy's `hardump`: plan for up to twice `maxBodySize` per
  exchange (a third more for base64). `stream(true)` (`--save-har-stream`) appends each entry to the
  file as it completes and keeps nothing; the file is valid JSON once closed. A name ending in
  `.zhar` is written zlib-compressed.

The JSON is written and read by a small package-private writer and parser shared with
`HttpLogger` and `ActivityLogger`; there is no JSON dependency.

## Replaying traffic

### Server replay

**Server replay** (`ServerReplay`, `--server-replay path`) answers requests from recorded
responses instead of contacting servers, as mitmproxy's `server_replay`. Recordings are HAR files
(from `HarRecorder`, browsers or mitmproxy, `.har` or `.zhar`), WARC files (from `WarcRecorder`:
`--server-replay warcs/` takes the whole directory) or both:

```bash
java -jar microproxy.jar --mitm --server-replay flows.har --server-replay-ignore-params _,cb \
    --server-replay-extra 404
```

```java
ServerReplay replay = ServerReplay.builder().load(Path.of("warcs")).ignoreHost(true).reuse(true).build();
MicroProxy.bootstrap().withFiltersSource(replay).start();
```

- **Matching** ports mitmproxy's `_hash`: scheme, method, path, request body, host, port and query
  parameters (in order) must be equal. `--server-replay-ignore-content`, `-ignore-host`,
  `-ignore-port`, `-ignore-params a,b` and `-ignore-payload-params a,b` (form bodies) loosen it;
  `--server-replay-use-headers a,b` adds headers. Request bodies are buffered to compare them (16
  MiB at most).
- **Use:** recordings answer once each, in recorded order, so a repeated request gets the recorded
  sequence of responses; `--server-replay-reuse` lets them answer again and again. Requests without
  a recording are forwarded (the default), killed (`--server-replay-extra kill`, the connection is
  closed) or answered with an empty response (`--server-replay-extra 404`).
- **Refresh:** `Date`, `Expires`, `Last-Modified` and cookie expiry move forward by the time since
  the recording (`--server-replay-no-refresh` keeps them).
- **Bodies:** HAR content is decoded, so it is served without its `Content-Encoding`; WARC bodies
  keep the coding they arrived with. The proxy sets `Content-Length`.
- **Source:** replayed answers are `ResponseSource.REPLAY` to trackers, access logs (`REPLAY`),
  `HttpLogger` (`source=replay`) and `HarRecorder` (`_source`).
- All recordings are held in memory.

### Client replay

**Client replay** (`ClientReplay`, `--client-replay path`) sends recorded requests again, as
mitmproxy's `client_replay`. They go to the proxy's own listener as ordinary client requests in
absolute form, so every filter, addon, script, cache and recorder applies, and the proxy fetches
`https://` URLs over TLS. `--client-replay-concurrency n` (default 1) bounds the requests in
flight; the proxy stops when they are done, unless `--keepserving` is given. Recorded framing and
hop-by-hop headers are not sent, and a proxy that requires authentication answers them `407`.

```bash
java -jar microproxy.jar --client-replay flows.har --save-har replayed.har   # replay, record, exit
```

### With scripts

The command-line addons and recorders compose with `--script`: the script runs
after `--block-list` and `--anticache` and before the other addons (as in mitmproxy), its
`on_request` can move a request elsewhere by assigning `req.uri`, and recorders and loggers placed
first see what the script changed. From Java, put a `ScriptedProxy` anywhere in an
`HttpFiltersChain` with the addons; a script that wants to keep a HAR of its own traffic can be
chained after a `HarRecorder` and the HAR written with `har.save(path)`.
