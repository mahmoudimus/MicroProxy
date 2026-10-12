# Access logs

Write one access-log line per exchange, tunnel or flow, in Envoy's format strings or JSON,
filtered, to a file, standard output or the `System.Logger`. Use this page to turn access logs on;
the operators, filters and presets are in the [access-log format
reference](../reference/access-log-format.md), and the flags in [response
flags](../reference/response-flags.md).

## Access logs (Envoy-compatible)

`ActivityLogger` writes one access-log line per finished exchange or flow. Its format strings are
compatible with Envoy's access-log command operators, so `%START_TIME%`, `%REQ(:PATH)%`,
`%RESPONSE_FLAGS%` and the rest mean what they mean in Envoy, and tools that read Envoy's logs
read these. Formats are parsed once, into an array of pieces that each render one literal or one
operator: rendering a line uses no regular expressions and allocates a few small strings.

```java
MicroProxy.bootstrap()
        .plusActivityTracker(ActivityLogger.builder()
                .format(LogFormat.envoy("[%START_TIME%] %REQ(:METHOD)% %REQ(:AUTHORITY)%%REQ(:PATH)%"
                        + " %RESPONSE_CODE% %RESPONSE_FLAGS% %DURATION%ms %UPSTREAM_HOST%"))
                .filter(AccessLogFilter.parse("status>=500 || response_flag"))
                .sink(AccessLogWriter.open(Path.of("access.log")))   // default: the System.Logger
                .build())
        .start();
```

From the command line, `--access-log <path|->` writes to a file (appended, a line flushed at a
time) or to standard output, in Envoy's default format unless `--access-log-format` (a format
string, or a preset's name) or `--access-log-json` (a JSON object of keys and format strings) says
otherwise; `--access-log-filter` (repeatable, all must pass) leaves lines out. Without
`--access-log`, the lines go to the `System.Logger` named `org.microproxy.extras.ActivityLogger`.
The properties file takes `access_log`, `access_log_format`, `access_log_json` and
`access_log_filter`.

```sh
java -jar microproxy.jar --port 8080 --access-log - \
    --access-log-format '[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%" %RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%'
# [2026-10-08T12:34:56.789Z] "GET /api HTTP/1.1" 502 UF proxy_failure:connect_failed

java -jar microproxy.jar --port 8080 --access-log access.jsonl \
    --access-log-json '{"start":"%START_TIME%","status":"%RESPONSE_CODE%","flags":"%RESPONSE_FLAGS%","ms":"%DURATION%","flow":"%MP_FLOW%"}' \
    --access-log-filter 'not_health_check && (status>=400 || duration>=1s)'
# {"start":"2026-10-08T12:34:56.789Z","status":504,"flags":"UT","ms":10003,"flow":"h2"}
```

### When lines are written

Once per HTTP exchange, when its response has been written or it was
abandoned (then with the flag that says why); once per `CONNECT` tunnel (over HTTP/1, HTTP/2 or
HTTP/3), SOCKS client, WebSocket session, TCP-hook tunnel, CONNECT-UDP flow, QUIC flow
intercepted stream by stream and relayed transparent QUIC flow, when it closes, with its bytes,
duration and flags. A `CONNECT` the proxy intercepts is a line of its own, which ends when the
session inside starts; the requests inside are lines of their own. Trackers get the same records
from `ActivityTracker.flowEnded(FlowRecord)`.

## Choosing a record of traffic

Three ways to keep a record of traffic:

- **`ActivityLogger`:** one line per exchange or flow, in an access-log format. Cheap enough to
  leave on.
- **`HttpLogger`:** whole messages, with their headers, what the proxy and filters changed, and
  optionally bodies, as readable blocks or JSON lines. For debugging and audits (see
  [Request/response logging](request-logging.md)).
- **`WarcRecorder`:** an archive of the exchanges with servers as binary WARC records, complete and
  unredacted, for replay tools (see [WARC recording](../guides/warc.md)).
