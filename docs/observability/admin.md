# Admin, readiness and draining

Serve Envoy's admin API on a listener of its own (stats, readiness, configuration, log levels,
draining), and stop the proxy gracefully with server states, drains and a drain time. Use this page
to run MicroProxy behind a load balancer or on Kubernetes; every path and flag is listed in the
[admin endpoints reference](../reference/admin-api.md).

## Admin interface

The admin listener serves Envoy's admin API (the same paths and semantics, reimplemented) on a
listener of its own, apart from the proxy's: metrics for Prometheus, readiness for load balancers
and orchestrators, the configuration in effect, log levels, and draining. It runs on the JDK's
built-in HTTP server (`com.sun.net.httpserver`, module `jdk.httpserver`), so it adds no dependency;
a `jlink`ed runtime needs `--add-modules jdk.httpserver`. It turns [metrics](metrics.md#metrics-envoy-compatible-stats) on.

```sh
java -jar microproxy.jar --port 8080 --admin-port 9901            # admin on 127.0.0.1:9901

curl -s localhost:9901/ready                                       # LIVE
curl -s 'localhost:9901/stats?filter=^cluster\.&usedonly'
curl -s localhost:9901/stats/prometheus
curl -s -X POST 'localhost:9901/logging?org.microproxy.impl.Tls=debug'
curl -s -X POST 'localhost:9901/drain_listeners?graceful'         # drain for --drain-time
```

```java
HttpProxyServer proxy = MicroProxy.bootstrap()
        .withAdmin(new InetSocketAddress(InetAddress.getLoopbackAddress(), 9901))
        .withAdminToken(System.getenv("MICROPROXY_ADMIN_TOKEN"))   // optional
        .withDrainTime(Duration.ofSeconds(20))
        .start();
proxy.state();                          // LIVE
proxy.drain(Duration.ofSeconds(20));    // returns when the drain is over
proxy.stop();                           // STOPPED
```

### Security

The admin API can drain and stop the proxy, so it listens on `127.0.0.1` unless told
otherwise. A token (`withAdminToken`, `--admin-token`) is then required on every path but
`/ready`: as `Authorization: Bearer <token>`, or as the password of basic authentication with
any user name (or as `user:password` itself, when the token has a colon); it is compared in
constant time. Bound to a loopback address, the listener also answers only requests whose `Host`
is `localhost` or a loopback address, so a web page cannot reach it through DNS rebinding, and it
refuses every `POST` that carries an `Origin`, as a browser's would. It speaks plain HTTP: to reach
it from elsewhere, bind it to a private address with a token, or tunnel to it (`kubectl
port-forward`, SSH). `/config_dump` and `/server_info` redact the secrets they would show: key
store passwords, the admin token, proxy authentication credentials and those in chained proxy
URLs, the interception CA's private key and its key store password, `--script-var` values, and any
option named for a password, token, secret or credential.

### Threads

The JDK's server reads requests and writes responses inside `synchronized` methods
(`sun.net.httpserver.Request.ReadStream.read` and `WriteStream.write`). On JDK 21 a virtual thread
blocked in one pins its carrier, so a client sending its request or reading the answer slowly
would hold one of the few carriers every virtual thread of the proxy shares. The admin listener
therefore runs on four platform threads of its own (idle keep-alive connections hold none: they
wait in the server's selector). `HttpsServer` pins the same way, and more, which is why the admin
listener has no TLS. JDK 24 (JEP 491) no longer pins on monitors.

### Logging levels

The proxy logs through `System.Logger`, which the JDK backs with
`java.util.logging` unless another backend is on the class path (SLF4J's
`slf4j-jdk-platform-logging`, Log4j's `log4j-jpl`). With `java.util.logging`, `/logging` lists the
loggers under `org.microproxy` and `io.github.mahmoudimus` with their effective levels, and sets
them with Envoy's names (`trace`, `debug`, `info`, `warning`, `error`, `critical`, `off`) or
`java.util.logging`'s (`FINE`, `ALL`, ...); a root handler that would drop the records of a lower
level is lowered to it. With another backend, `/logging` says which one, and levels are set there:
the JDK gives no portable way to change them.

## Lifecycle, draining and shutdown

A proxy is `INITIALIZING` while it starts (the admin listener first, then the proxy's own),
`LIVE` once it serves, `DRAINING` once it drains, stops accepting or stops, and `STOPPED` at the
end: `HttpProxyServer.state()`, the admin's `/ready`, and the `server.state` gauge with Envoy's
numbers (0 live, 1 draining, 2 pre-initializing, 3 initializing; 4 stopped, which Envoy has not).

- **Drain** (`drain(time)`, `POST /drain_listeners?graceful`): `/ready` fails at once, and the
  listeners keep accepting, so that clients a load balancer still sends are served. Each new
  request is told to go elsewhere: an HTTP/1 response gets `Connection: close` and its connection
  closes after it; an HTTP/2 or HTTP/3 connection is sent GOAWAY (the request is served, and named
  the last one). With the `gradual` strategy (Envoy's default) the chance that a request does so
  grows from 0 at the start of the drain to 1 at its end, so clients move away gradually; with
  `immediate`, every connection is told at once (idle ones close now). Exchanges in progress get
  until the drain time is over; then the listeners close and so does every connection still open.
  The proxy stays `DRAINING`, its admin listener up, until it is stopped.
- **Stop accepting** (`stopListeners()`, `POST /drain_listeners`): the TCP listener closes, the UDP
  ones (HTTP/3, transparent QUIC) refuse new QUIC connections, and open connections are left
  alone.
- **Stop** (`stop()`, `POST /quitquitquit`, and the launcher's SIGTERM or Ctrl-C): the listeners
  close, idle connections close, HTTP/2 and HTTP/3 ones get GOAWAY, HTTP/1 ones close after their
  exchange in progress; exchanges get up to the drain time to finish (`withDrainTime`,
  `--drain-time`, 10 seconds by default), then everything is closed, resources added with
  `closeOnStop` are closed, and last the admin listener. `abort()` closes everything at once.
- **Health check** (`setHealthCheckFailed`, `POST /healthcheck/fail` and `/healthcheck/ok`): while
  it fails, `/ready` answers `503 HEALTH_CHECK_FAILED`, and every new request drains its
  connection, as Envoy does. `withHealthCheckPath("/healthz", passThrough)` (`--health-check-path`)
  answers health checks on the proxy's own listener, before authentication and the filters, as
  Envoy's health check filter: an origin-form request for the path gets `200`, or `503` with
  `x-envoy-immediate-health-check-fail: true` while the health check fails or the proxy is not
  `LIVE`. With pass-through, a healthy check goes on to the server (in reverse mode, the
  upstream's own health) and only failures are answered by the proxy.

The drain counts `http.<name>.downstream_cx_drain_close` (connections told to go away),
`listener_manager.listener_stopped`, and the gauges `listener_manager.total_listeners_active` and
`total_listeners_draining`; `server.live` is 1 only while `LIVE`.

### Kubernetes

Readiness follows `/ready`; on deletion, a `preStop` hook drains while the
endpoints controller and the load balancers forget the pod, then the kubelet's SIGTERM stops the
proxy, which finishes the exchanges still in progress:

```yaml
spec:
  terminationGracePeriodSeconds: 45          # > preStop sleep + drain time
  containers:
    - name: microproxy
      image: example/microproxy
      args: ["--port", "8080", "--server", "--admin-address", "0.0.0.0:9901",
             "--admin-token-file", "/etc/microproxy/admin-token", "--drain-time", "15"]
      ports: [{containerPort: 8080}, {containerPort: 9901}]
      readinessProbe:
        httpGet: {path: /ready, port: 9901}  # /ready needs no token
        periodSeconds: 2
      lifecycle:
        preStop:
          exec:
            command:
              - sh
              - -c
              - |
                curl -sf -X POST -H "Authorization: Bearer $(cat /etc/microproxy/admin-token)" \
                  'http://127.0.0.1:9901/drain_listeners?graceful&inboundonly'
                sleep 15
      volumeMounts: [{name: admin-token, mountPath: /etc/microproxy, readOnly: true}]
  volumes:
    - name: admin-token
      secret: {secretName: microproxy-admin-token}
```

The kubelet probes the pod's address, so this binds the admin listener to every interface, with a
token. To keep it on loopback instead, probe with `exec` (`curl -sf localhost:9901/ready`), or
give the proxy `--health-check-path /healthz` and probe `httpGet: {path: /healthz, port: 8080}`,
which also fails while draining. Without a `preStop` hook (an image without `curl` or `sh`),
SIGTERM alone stops accepting at once and lets the exchanges in progress finish for up to
`--drain-time`; a `preStop` of `sleep 5` covers most of the time endpoints take to update.

### Limitations

`/clusters` lists the clusters that have stats so far, so a chained proxy shows
once it has been used; every cluster is reported `healthy`, as the proxy runs no active health
checks. `?usedonly` keeps what is not zero, where Envoy keeps what was ever written (a gauge back
at zero shows there). A gradual drain is a matter of chance per request, so an HTTP/1 client that
sends few requests may keep its connection until the drain ends. Envoy's `?inboundonly` and
`traffic_direction` distinction has nothing to choose from here, and the admin listener itself is
never drained. Scripts do not see the state: they run per request, and a draining proxy's own
answers (`Connection: close`, GOAWAY) need nothing from them.
