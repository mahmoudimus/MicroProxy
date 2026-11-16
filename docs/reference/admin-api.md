# Admin endpoints

Every path of the admin API, with its method and answer, and the flags and properties that
configure the admin listener, draining and health checks. Use this page when scripting against the
admin listener; [Admin, readiness and draining](../observability/admin.md) explains the security
model, server states and draining.

## Paths

| path | method | answer |
|---|---|---|
| `/`, `/help` | GET | the paths and what they do |
| `/stats` | GET | the stats as `name: value` lines, histograms as their quantiles (Envoy's text dump); `?filter=<regex>` keeps the names it finds, `?usedonly` the stats with a value, `?format=json` or `?format=prometheus` changes the form |
| `/stats/prometheus` | GET | Prometheus's text exposition format 0.0.4 (`text/plain; version=0.0.4; charset=utf-8`), with `?filter=` and `?usedonly` too |
| `/ready` | GET | `200 LIVE`, or `503` and the state: `DRAINING`, `INITIALIZING`, `PRE_INITIALIZING`, `HEALTH_CHECK_FAILED` after `/healthcheck/fail`, or `NOT_READY` while the embedder's [readiness check](#stats-listener) is false; needs no token |
| `/live` | GET | `200 ALIVE`, or `503 STOPPED` once the proxy has stopped, or `503 NOT_ACCEPTING` when it is `LIVE` but its listener no longer accepts (closed, or its acceptor thread gone); starting and draining are alive, so a liveness probe does not restart a proxy finishing its exchanges. It opens no connection to the proxy |
| `/server_info` | GET | JSON: the version, state, uptime (`uptime_current_epoch`), listeners, the features in use (`h2`, `h2c`, `h3`, `quic`, `socks`, `masque`, `mitm`, `transparent`, `reverse_proxy`, `cache`, `replay`, `scripting`, `tracing`, ...), the drain settings, the JVM, and the command line, secrets redacted |
| `/listeners` | GET | a line per listener, `name::address::transport::protocols` (`edge::127.0.0.1:8080::tcp::http/1.1,h2c`); `?format=json` |
| `/clusters` | GET | a line per cluster stat, `cluster::stat::value`, for `direct`, the chained proxies, `cache`, `replay` and, with `--stats-per-host`, each server; with the shared pool's state on `direct`; `?format=json` (histograms as count, p50 and p99) |
| `/config_dump` | GET | JSON: the configuration in effect (listener, modes, timeouts, limits, pool, chained proxies, HTTP/2 and HTTP/3 options, TLS, interception, filters, trackers, tracer, stats, drain, health check, admin, command line), every secret `[redacted]` |
| `/logging` | GET, POST | GET lists the proxy's loggers and their levels; `POST /logging?level=<level>` sets them all, `POST /logging?<logger>=<level>` one (and its children) |
| `/healthcheck/fail` | POST | fails the health check: `/ready` and the [health-check path](../observability/admin.md#lifecycle-draining-and-shutdown) answer `503`, and connections drain as their next request comes |
| `/healthcheck/ok` | POST | restores it |
| `/drain_listeners` | POST | stops accepting connections now (open ones are left alone); with `?graceful`, drains for the drain time first, still accepting; `?inboundonly` is accepted, every proxy listener being inbound |
| `/quitquitquit` | POST | stops the proxy gracefully, as `stop()` does |

Reads are `GET` (and `HEAD`); what changes the proxy takes `POST` only, so that a link or a
prefetch cannot change it; any other method gets `405` with an `Allow` header. An unknown path
gets `404` and the list. Envoy's other paths (`/certs`, `/memory`, `/runtime`,
`/stats/recentlookups`, `/reset_counters`, `/heap_dump`, `/hot_restart_version`, ...) are not
served: MicroProxy has no runtime-overridable settings, hot restarts or certificates to list.

## Stats listener

The admin listener can drain and stop the proxy, so it belongs on loopback. Prometheus and the
kubelet's probes connect to the pod's address. The stats listener (`withStatsListener`,
`--stats-port`, `--stats-address`) serves only `/stats`, `/stats/prometheus`, `/ready` and
`/live` (and `/`, their list), with `GET` and `HEAD`: nothing it answers changes the proxy, it
needs no token, and it never reads a request's body. Any other path gets `404`, any other method
`405`. It can run alongside the admin listener or alone, and turns metrics on.

`withStatsListenerPaths` (`--stats-paths`, `stats_paths`) adds paths that answer as one of those
four, so that the listener fits the layout the platform expects; for Spring Boot Actuator's:

```
--stats-port 9902 --stats-paths /metrics=/stats/prometheus,/health=/ready,/health/liveness=/live,/health/readiness=/ready
```

`withReadinessCheck(BooleanSupplier)` adds an embedder's condition to `/ready` on both listeners
(`503 NOT_READY` while it is false or throws). It is asked on every `/ready`; it changes neither
the proxy's state nor its health-check path nor `/live`.

## Flags and properties

| flag | property | meaning |
|---|---|---|
| `--admin-port <port>` | `admin_port` | serve the admin API on this port of `127.0.0.1` (0 for any free port) |
| `--admin-address <host:port>` | `admin_address` | on another address, such as `0.0.0.0:9901` or `[::1]:9901` |
| `--admin-token <token>` | `admin_token` | require the token on every path but `/ready` |
| `--admin-token-file <file>` | | the same, from the file's first line (kept out of the process list) |
| `--stats-port <port>` | `stats_port` | serve the read-only [stats listener](#stats-listener) on this port of every address (0 for any free port) |
| `--stats-address <host:port>` | `stats_address` | on one address |
| `--stats-paths <paths>` | `stats_paths` | more paths for it, `<path>=<stats path>` pairs, comma-separated |
| `--drain-time <seconds>` | `drain_time` | how long a drain lasts, and how long stopping lets exchanges finish (default 10) |
| `--drain-strategy <strategy>` | `drain_strategy` | `gradual` (the default) or `immediate` |
| `--health-check-path <path>` | `health_check_path` | answer health checks on the proxy's listener |
| `--health-check-pass-through` | `health_check_pass_through` | forward a healthy health check to the server instead |
