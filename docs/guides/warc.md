# WARC recording

Record the traffic between the proxy and servers as WARC 1.1 files, the format web archives use,
and read them back for replay. Use this page to archive what passes through the proxy; for HAR
files see [Addons, HAR and replay](addons.md#har-files).

`org.microproxy.warc.WarcRecorder` records what passes between the proxy and servers as WARC 1.1
files (ISO 28500), the format web archives use. Replay or inspect them with tools such as
[pywb](https://github.com/webrecorder/pywb) and [warcio](https://github.com/webrecorder/warcio).

```bash
java -jar microproxy.jar --mitm --warc-dir warcs      # browse; HTTPS is recorded too
warcio index warcs/*.warc.gz
```

```java
WarcRecorder recorder = WarcRecorder.builder(Path.of("warcs")).maxFileSize(1L << 30).build();
MicroProxy.bootstrap().withFiltersSource(recorder).start();
// ... recorder.close() finishes the current file.
```

What gets written:

- **Records:** each exchange becomes a `response` record and a `request` record, linked by
  `WARC-Concurrent-To`, with block and payload digests (`sha1:` base32), the target URI
  (`https://` inside intercepted sessions) and the server's IP address. Every file starts with a
  `warcinfo` record.
- **Files:** each record is its own gzip member, so readers can seek to any record. Files are
  named `microproxy-<timestamp>-<serial>.warc.gz`, carry an `.open` suffix while being written,
  and roll over at 1 GiB by default.
- **Bodies:** captured as they stream past, without buffering the exchange (large ones spill to a
  temporary file), up to 512 MiB per body. Beyond that the record says `WARC-Truncated: length`.
  Chunked transfer coding is removed and `Content-Length` gives the recorded length; content
  codings such as gzip are kept as received.
- **Not recorded:** responses from the cache or produced by filters, and `CONNECT` tunnels that
  are not intercepted.
- **Ordering:** put the recorder first among the filters, as `--warc-dir` does, to record
  messages before other filters change them.

The output is checked with `warcio check` (all digests pass) and indexed by `warcio index`.

`org.microproxy.warc.WarcReader` reads WARC files back, record by record (plain or gzip, one member
per record or one for the file), and `--server-replay warcs` answers requests from the responses
in a directory of them (see [Replaying traffic](addons.md#replaying-traffic)).
