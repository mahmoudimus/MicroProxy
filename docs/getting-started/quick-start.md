# Quick start

Run MicroProxy from the command line in a minute, then embed it in a Java program. Use this page
for copy-pasteable commands; the [command-line reference](../reference/cli.md) lists every flag.

## A forward proxy in one command

Build the jars (or download them: see [Install](install.md)), start the proxy on port 8080, and
send a request through it:

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.2.0
mvn -q -DskipTests package
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080
```
<!-- x-release-please-end -->

The launcher prints where it listens (after the same line from its logger):

```text
MicroProxy listening on localhost/127.0.0.1:8080
```

In another terminal:

```bash
curl -x http://127.0.0.1:8080 -I http://example.com/
```

The response carries the proxy's `Via` header (`Via: 1.1 <host name>`, with the server's HTTP
version). By default the proxy listens on loopback only; `--server` listens on all interfaces.

## Intercepting HTTPS

```bash
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm
curl -x http://127.0.0.1:8080 --cacert microproxy-ca.pem https://example.com/
```

`--mitm` creates (or reuses) a CA in `microproxy-ca.p12` and writes its certificate to
`microproxy-ca.pem`. To intercept HTTPS without errors, add that certificate to your client's
trust store. See [MITM, certificates and TLS](../guides/mitm.md).

## More command lines

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.2.0
mvn package
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm   # intercept HTTPS
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --dnssec --activity-log-format clf
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --log-http headers   # dump traffic
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --save-har flows.har    # record, then
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --server-replay flows.har   # replay offline
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8080 --mitm --ignore-hosts '\.bank\.example:443$'
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 8443 --reverse https://example.com   # reverse proxy
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --port 1080 --mode socks5 --mitm   # SOCKS5 server
java -jar microproxy/target/microproxy-${MICROPROXY_VERSION}.jar --help

# With zstd decoding:
java -cp microproxy/target/microproxy-${MICROPROXY_VERSION}.jar:\
zstd-decoder/target/zstd-decoder-${MICROPROXY_VERSION}.jar org.microproxy.Launcher --port 8080

# With HTTP/2 to clients on intercepted TLS and to servers, on by default once the http2-codec jar
# is on the class path (without it, the proxy speaks HTTP/1.1; --no-http2 and --no-http2-upstream
# turn HTTP/2 off):
java -cp microproxy/target/microproxy-${MICROPROXY_VERSION}.jar:\
http2-codec/target/http2-codec-${MICROPROXY_VERSION}.jar org.microproxy.Launcher --port 8080 --mitm

# The same launcher with scripting, zstd, HTTP/2, QUIC and HTTP/3 built in (one self-contained jar):
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --script proxy.star
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --mitm

# Traces, metrics and access logs to an OpenTelemetry Collector (OTLP/HTTP on 4318):
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
    java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080

# A reverse proxy serving HTTPS, HTTP/2 and HTTP/3 (on UDP 8443), speaking HTTP/3 to servers that offer it:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8443 \
    --mode reverse:https://example.com --listener-keystore site.p12 --listener-keystore-password secret \
    --http3 --http3-upstream

# A forward proxy on TLS (8443) that also serves HTTP/3 on UDP 8443: CONNECT, WebSockets and
# CONNECT-UDP (MASQUE) for HTTP/3 clients and, over TCP, for HTTP/2 clients, the QUIC inside their
# UDP flows intercepted too:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8443 \
    --listener-keystore proxy.p12 --listener-keystore-password secret --http3 \
    --mitm --masque-intercept-quic

# A plain forward proxy (8080) that tunnels UDP too, without HTTP/3: CONNECT-UDP over h2c and as
# an HTTP/1.1 upgrade:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 \
    --http2-cleartext --masque

# A transparent proxy for redirected TCP (8080) and QUIC (UDP 8443), intercepting HTTP/3 too, and
# other QUIC stream by stream through a script's on_quic_*() hooks:
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --server \
    --transparent --transparent-quic-port 8443 --mitm --http3-upstream --script quic.star
```
<!-- x-release-please-end -->

Each of these is described in its guide: [MITM](../guides/mitm.md),
[DNSSEC](../guides/dnssec.md), [access logs](../observability/access-logs.md),
[request logging](../observability/request-logging.md),
[HAR and replay](../guides/addons.md#har-files),
[ignoring hosts](../guides/mitm.md#ignoring-and-allowing-hosts),
[reverse proxy](../guides/reverse-proxy.md), [SOCKS](../guides/socks.md),
[HTTP/2](../guides/http2.md), [HTTP/3](../guides/http3.md), [CONNECT-UDP](../guides/masque.md),
[transparent mode](../guides/transparent-mode.md), [OpenTelemetry](../observability/opentelemetry.md)
and [scripting](../guides/scripting.md).

## Embedded in a Java program

Add `io.github.mahmoudimus:microproxy` to your build ([Install](install.md)) and start a proxy
with `MicroProxy.bootstrap()`:

```java
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;

public class Proxy {
    public static void main(String[] args) {
        HttpProxyServer proxy = MicroProxy.bootstrap()
                .withPort(8080)
                .start();
        System.out.println("listening on " + proxy.getListenAddress());
    }
}
```

The proxy runs until `proxy.stop()` (or the JVM exits). Every flag has a bootstrap method: the
guides show both, and the [configuration properties](../reference/properties.md) give the same
settings in a file (`MicroProxy.bootstrapFromFile(path)`). Next:
[Your first filter](first-filter.md) changes traffic as it passes.
