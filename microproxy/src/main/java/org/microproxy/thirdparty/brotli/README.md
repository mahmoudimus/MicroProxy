# Vendored Brotli decoder

The pure-Java Brotli decoder from [google/brotli](https://github.com/google/brotli)
(`java/org/brotli/dec`, commit `392b261`), MIT licensed. The license text ships in the jar as
`META-INF/LICENSE-brotli.txt`.

Changes from upstream: the package is renamed from `org.brotli.dec` to
`org.microproxy.thirdparty.brotli`; the tests and the encoder bindings are not included.
`org.microproxy.http.HttpBodies` uses it to decode `Content-Encoding: br`.
