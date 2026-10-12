# Metrics, Prometheus and statsd

Keep counters, gauges and histograms under Envoy's stat names and tags, and read them as Prometheus
text, Envoy's `/stats` dump or JSON, or push them to statsd and DogStatsD. Use this page to turn
metrics on and understand names, tags and clusters; every stat is listed in the [stats
reference](../reference/stats.md).

## Metrics (Envoy-compatible stats)

With metrics on, the proxy keeps counters, gauges and histograms under Envoy's stat names, so
dashboards and alerts written for Envoy read them: `http.<name>.downstream_rq_5xx`,
`cluster.<cluster>.upstream_cx_connect_fail`, `listener.<address>.downstream_cx_active`, and so on.
They live in a `StatsRegistry` (package `org.microproxy.stats`); `StatsFormatter` renders them as
Prometheus's text exposition format, Envoy's `/stats` text dump, or its JSON form, and
`StatsdSink` pushes them to statsd. The [admin interface](admin.md#admin-interface) serves them over HTTP
(`/stats`, `/stats/prometheus`).

```java
StatsRegistry stats = StatsRegistry.builder().prefix("envoy").build();   // or .withMetrics(true)
HttpProxyServer proxy = MicroProxy.bootstrap().withName("edge").withStats(stats).start();
...
String scrape = StatsFormatter.prometheus(proxy.getStats());
// # TYPE envoy_http_downstream_rq_xx counter
// envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge",envoy_response_code_class="2"} 1042
// envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge",envoy_response_code_class="5"} 3
StatsdSink sink = StatsdSink.builder(stats, "127.0.0.1:8125").start();     // every 5 s; close() stops it
```

```sh
java -jar microproxy.jar --port 8080 --name edge --metrics
java -jar microproxy.jar --port 8080 --statsd 127.0.0.1:8125            # implies --metrics
java -jar microproxy.jar --port 8080 --dogstatsd 127.0.0.1:8125 --stats-prefix microproxy
```

| flag | property | meaning |
|---|---|---|
| `--metrics` | `metrics` | keep the stats |
| `--statsd <host:port>` | | push them to statsd over UDP every 5 seconds, and once more when the proxy stops (implies `--metrics`) |
| `--dogstatsd <host:port>` | | the same with DogStatsD tags (`name:1\|c\|#tag:value`) and tag-extracted names |
| `--stats-prefix <prefix>` | `stats_prefix` | prefix of exported names: `envoy` (the default) gives `envoy_http_downstream_rq_total` and `envoy.http.edge.downstream_rq_total`; `microproxy` gives `microproxy_...` |
| `--stats-max-clusters <n>` | | clusters with stats of their own, besides the fixed ones (default 100) |
| `--stats-cluster-lru` | | past that, evict the least recently used cluster's stats rather than counting new ones in `other` |
| `--stats-per-host` | | a cluster per server of direct connections (`host_port`) instead of one `direct` cluster |
| `--qlog-dir <dir>` | `qlog_dir` | write a qlog file per QUIC connection into `<dir>` ([qlog](qlog.md#qlog-files)) |
| `--qlog-max-files <n>` | `qlog_max_files` | qlog files the directory keeps; past it, the oldest are deleted (default 1000) |

## Names and tags

Every stat has Envoy's flat name, with its values in it, which the text dump and
statsd show. When it is registered, Envoy's tag extraction takes those values out as tags, which
Prometheus shows as labels on the tag-extracted name: `cluster.direct.upstream_rq_2xx` is
`envoy_cluster_upstream_rq_xx{envoy_cluster_name="direct",envoy_response_code_class="2"}`. The
tags are Envoy's `envoy_http_conn_manager_prefix` (the proxy's name, `withName`, `--name`),
`envoy_cluster_name`, `envoy_listener_address` (`0.0.0.0_8080`, `[__1]_8080`) and
`envoy_response_code_class`, and MicroProxy's `microproxy_response_flag`, plus those of the
[per-protocol stats](../reference/stats.md): `microproxy_direction` (`downstream`, `upstream`), `microproxy_quic_scope`,
`microproxy_quic_error`, `microproxy_congestion_controller`, `microproxy_drop_reason`,
`microproxy_socks_version`, `microproxy_socks_reply`, `microproxy_reject_reason`,
`microproxy_tunnel_kind`, `microproxy_close_code`, `microproxy_hook`, and for scripts'
calls `microproxy_script`, `microproxy_script_hook` and `microproxy_budget`. Histograms are in
milliseconds, with Envoy's buckets (0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000,
30000, 60000, 300000, 600000, 1800000, 3600000), shown as `_bucket{le="..."}`, `_sum` and `_count`.

## Clusters and cardinality

A forward proxy's servers are any number, so they are not clusters
by default. A request's cluster is `direct` for a direct connection, the chained proxy for one
through a chained proxy (`host_port` of its address, such as `proxy_example_com_3128`), `cache`
for a response from the HTTP cache, and `replay` for one from server replay. With
`perHostClusters(true)` (`--stats-per-host`) each server of a direct connection is a cluster of its
own (`api_example_com_443`). Chained proxies and servers together are bounded by `maxClusters`
(`--stats-max-clusters`, default 100): past it, new ones count in the cluster `other`, or, with
`clusterOverflow(Overflow.LRU)` (`--stats-cluster-lru`), the least recently used cluster loses its
stats (which start from zero if it comes back). A cluster is looked up once per server
connection, never per request.

## Script stats

A script's `stats` module makes metrics of its own, named `script.<name>`:

```python
BLOCKED = stats.counter("blocked")          # looked up once, at load time

def on_request(req, ctx):
    stats.histogram("path_length").record(len(req.path))
    if req.path.startswith("/admin"):
        BLOCKED.inc()
        return response(403)
```

A script makes at most `maxScriptStats` of them (100 by default); past that, new names count
nothing (a warning is logged once), so names made from requests cannot grow the registry without
bound. Without metrics, the module's metrics count nothing. Counters have `inc(n=1)` and `value`,
gauges `set(v)`, `inc(n=1)`, `dec(n=1)` and `value`, histograms `record(x)` and `count`.

## Cost

Each metric is resolved once and kept in a field: per proxy for the `http`, `listener`,
per-protocol, hook and fixed `cluster` stats, per server connection for its cluster, per client
connection for its own. Counting a request is a few `LongAdder` adds and a histogram bucket search;
nothing is allocated per request, and nothing goes through `ActivityTracker`s. Nothing is counted
in the registry per QUIC packet: a connection counts in plain fields of its own, added once when
it closes, and CONNECT-UDP flows and transparent QUIC relays count their datagrams the same way.
Without metrics the registry is `StatsRegistry.NOOP`, whose metrics do nothing, and the call sites
that would read a clock (the hooks', for one) check first; `AllocationTest` (HTTP/1, and HTTP/2
and HTTP/3 with metrics against without) and `StatsFastPathTest` guard both.

## Limitations

QUIC connections are counted when they close, so `quic.*` counters lag a
long-lived connection (`connections_active` and `QuicConnection.stats()` are live). The proxy's own
connections to servers do not move, so `quic.upstream.migrations` counts only moves to a server's
preferred address, and a relayed transparent flow whose client moves is no QUIC connection of the
proxy's: it counts in none of these. `http2.*.outbound_flood` and `requests_rejected_with_underscores_in_headers` have no
equivalent: writes block rather than queue, and underscores in header names are not refused.
Envoy's `upstream_cx_destroy_*` and
`downstream_cx_destroy_*` tell who closed first only where the proxy saw it (an end of stream
before a request, a server that closed its connection). Statsd gets a histogram as one timer per
flush, the mean of its new values sampled at `1/n`, which keeps the count and mean, not the spread.
