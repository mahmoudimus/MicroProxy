# Rewriting bodies

Decode, edit and re-encode message bodies safely (compression, charsets, lengths), buffer one
message at a time from a filter, and rewrite headers and text bodies declaratively with
`RewriteRules`. Use this page before writing a filter that changes bodies.

`org.microproxy.http.HttpBodies` handles the parts of body editing that are easy to get wrong:

- **Decoding:** gzip, x-gzip, deflate (zlib-wrapped or raw), `br` (Brotli, through a vendored
  copy of the pure-Java codec [jaybrotli](https://github.com/mahmoudimus/jaybrotli)) and, when
  `zstd-decoder` is on the class path, `zstd`. Decoding is capped at 64 MiB by default to defuse
  compression bombs; the Brotli decoder stops before writing past the cap. A `br` body must be
  exactly one Brotli stream: as in the reference decoder, a command that runs past the end of its
  meta-block, or any byte after the end of the stream, is an `IOException` ("corrupt brotli
  data"), so the proxy and the client never disagree about where a body ends. `canDecode` reports
  codings that can't be decoded, such as the dictionary codings `dcb` and `dcz`.
- **Negotiation:** `restrictAcceptEncoding(request)` trims a request's `Accept-Encoding` to the
  codings above (keeping q-values), so the server never picks one the proxy can't read.
  `RewriteRules` and scripts that define `on_response` do this automatically.
- **Charset:** taken from the *response's* `Content-Type`, defaulting to UTF-8.
- **Rewriting:** the original coding is re-applied, Brotli included, except that zstd is
  re-encoded as gzip because there is no pure-Java encoder for it. Brotli is written at quality 5
  (`HttpBodies.BROTLI_QUALITY`) with jaybrotli's default strategies, in the smallest window that
  spans the body (see [Brotli speed and size](#brotli-speed-and-size)). `ETag`/`Content-MD5` are
  dropped because they no longer match. `Content-Length` is fixed when the message is written.

Filters can also ask to buffer one message at a time, after seeing its head:

- `HttpFilters.responseBufferSizeInBytes(response)`: a body larger than requested simply streams
  through.
- `HttpFilters.requestBufferSizeInBytes(request)`: a body larger than requested is answered with
  `413`, since part of it has already been read.

`org.microproxy.extras.RewriteRules` builds on both. It is a filters source with an ordered list
of rules. Each rule matches a URL regex (absolute form, `https://` inside intercepted sessions)
and edits request headers, response headers and textual response bodies:

```java
bootstrap.withFiltersSource(RewriteRules.builder()
        .add(RewriteRules.Rule.matching("https://example\\.com/.*")
                .replaceInBody("Example Domain", "Rewritten Domain")
                .removeResponseHeader("Content-Security-Policy"))
        .build());
```

Only matching text responses are buffered; everything else streams.

## Brotli speed and size

`br` is decoded and encoded by jaybrotli, a pure-Java codec vendored in the core. Its decoder runs
at a median 1.1 times the speed of Google's Java decoder, which MicroProxy used before (0.9 to 1.2
times in the table below). Rewritten bodies use quality 5 with jaybrotli's default strategies: the
setting that stays at about 10 MB/s or more on large HTML and JSON while coming out smaller than
gzip's default level on all but one of the bodies below. Qualities 4 and 6 are within 1% of it in
size, at the same speed. jaybrotli's hash-chain finder with lazy parsing is 4 to 5% smaller on
bodies of 500 KB to 1 MB but drops to about 6 MB/s on 1 MB of HTML; with greedy parsing (the setting
before jaybrotli's default strategies became fast) it is faster on small bodies but up to 20% larger
there, and about as fast on large ones.

Measured through `HttpBodies.decode` (the build before and after the switch, each in its own class
loader) and `HttpBodies.encode` (against `GZIPOutputStream`), in one JVM, interleaved round by
round: the median MB/s of 9 rounds of 0.4 s (decoding, MB/s of
output) or 7 rounds of 1 s (encoding, MB/s of input), with the minimum and maximum in brackets.
Host: a shared 4-vCPU Xeon at 2.1 GHz, OpenJDK 21, `nice -n 19`; compare within a row. The
bodies are javadoc and documentation pages (HTML), ISO code tables and an npm lock file (JSON);
the decoded streams come from the reference `brotli` encoder.

| Decoding | Google's decoder | jaybrotli |
|---|---:|---:|
| HTML 11 KB, q5 / q11 | 153 (110–172) / 156 (138–168) | 175 (145–194) / 172 (154–189) |
| HTML 170 KB, q5 / q11 | 435 (368–497) / 379 (119–394) | 431 (393–504) / 425 (363–480) |
| HTML 293 KB, q5 / q11 | 155 (141–182) / 154 (128–165) | 185 (144–206) / 157 (137–193) |
| HTML 1 MB, q5 / q11 | 153 (139–166) / 172 (131–175) | 172 (155–186) / 177 (155–204) |
| JSON 17 KB, q5 / q11 | 240 (197–264) / 176 (171–192) | 273 (231–295) / 215 (160–226) |
| JSON 498 KB, q5 / q11 | 340 (279–397) / 322 (247–360) | 319 (255–368) / 294 (228–344) |
| JSON 558 KB, q5 / q11 | 318 (265–341) / 255 (227–269) | 359 (287–376) / 289 (272–308) |

| Encoding | gzip -6 size | `br` size | gzip -6 MB/s | `br` MB/s |
|---|---:|---:|---:|---:|
| HTML 11 KB | 3,280 | 2,842 (−13%) | 51 (35–54) | 12 (11–12) |
| HTML 170 KB | 14,343 | 13,093 (−9%) | 87 (75–92) | 35 (33–40) |
| HTML 293 KB | 79,369 | 77,515 (−2%) | 23 (21–25) | 9.5 (8.8–10.8) |
| HTML 1 MB | 264,641 | 260,475 (−2%) | 29 (27–30) | 11 (10–11) |
| JSON 17 KB | 2,956 | 2,918 (−1%) | 120 (100–136) | 24 (23–27) |
| JSON 498 KB | 60,190 | 61,098 (+2%) | 76 (64–79) | 22 (22–25) |
| JSON 558 KB | 102,506 | 92,590 (−10%) | 63 (59–67) | 18 (17–20) |

gzip stays the faster encoder, by 2.4 to 5 times; Brotli is kept because the client asked for it,
and at this setting encoding costs at most about a millisecond per 10 KB of body.
