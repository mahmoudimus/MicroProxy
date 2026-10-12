# qlog

Write a qlog trace of every QUIC connection the proxy makes or accepts, to read in qvis or with
`jq`. Use this page to debug QUIC and HTTP/3 behaviour (handshakes, loss, congestion); it is not
meant for production.

<a id="qlog-files"></a>

**qlog.** With `--qlog-dir <dir>` (`Http3Options.Builder.qlogDirectory`, `qlog_dir`), each of the
proxy's QUIC connections, to clients and to servers, writes a qlog trace into `<dir>`, whether or
not metrics are on: `<ODCID>_server.sqlog` or `<ODCID>_client.sqlog`, named after the connection's
original Destination Connection ID and the proxy's side of it. A file is JSON-SEQ (RFC 7464), as the
qlog main schema serializes a trace: each record starts with the record separator (0x1E) and ends
with a newline. The first is the header (`"qlog_version":"0.3"`, `"qlog_format":"JSON-SEQ"`, the
vantage point, and `ODCID` and `group_id` in `common_fields`, with `"time_format":"relative"` and
the wall-clock `reference_time`); then one record per event, `{"time":<ms since the first
event>,"name":"transport:packet_sent","data":{...}}`, with the quic module's events: packets sent,
received and lost, key updates, state changes and the connection's close. The directory keeps at
most `--qlog-max-files` files (1000 by default; the oldest the proxy wrote are deleted), and a file
stops at 64 MiB (`qlogMaxFileBytes`). qlog builds an event for every packet, so it is for debugging.

```sh
java -jar microproxy.jar --port 8443 --http3 --listener-keystore proxy.p12 --qlog-dir /tmp/qlog
# Open the files in qvis (https://qvis.quictools.info), or read them with jq --seq:
jq --seq -c 'select(.name == "recovery:packet_lost")' /tmp/qlog/*_server.sqlog
```
