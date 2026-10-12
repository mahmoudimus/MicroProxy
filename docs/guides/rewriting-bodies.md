# Rewriting bodies

Decode, edit and re-encode message bodies safely (compression, charsets, lengths), buffer one
message at a time from a filter, and rewrite headers and text bodies declaratively with
`RewriteRules`. Use this page before writing a filter that changes bodies.

`org.microproxy.http.HttpBodies` handles the parts of body editing that are easy to get wrong:

- **Decoding:** gzip, x-gzip, deflate (zlib-wrapped or raw), `br` (Brotli, through a vendored
  copy of Google's pure-Java decoder) and, when `zstd-decoder` is on the class path, `zstd`.
  Decoding is capped at 64 MiB by default to defuse compression bombs. `canDecode` reports
  codings that can't be decoded, such as the dictionary codings `dcb` and `dcz`.
- **Negotiation:** `restrictAcceptEncoding(request)` trims a request's `Accept-Encoding` to the
  codings above (keeping q-values), so the server never picks one the proxy can't read.
  `RewriteRules` and scripts that define `on_response` do this automatically.
- **Charset:** taken from the *response's* `Content-Type`, defaulting to UTF-8.
- **Rewriting:** the original coding is re-applied, except that Brotli and zstd are re-encoded as
  gzip because there are no pure-Java encoders for them. `ETag`/`Content-MD5` are dropped because they no longer
  match. `Content-Length` is fixed when the message is written.

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
