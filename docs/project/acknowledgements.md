# Acknowledgements and license

The code MicroProxy vendors or ports, the projects that contributed ideas, and its license.

## Acknowledgements

The Zstandard decoder in `zstd-decoder` was written from RFC 8878 and is tested against the
reference `zstd` tool. Vendored code, with licenses and changes listed in [NOTICE](https://github.com/mahmoudimus/MicroProxy/blob/main/NOTICE) and
the `README.md` next to each copy:

- Google's [Brotli](https://github.com/google/brotli) decoder (MIT), in the core.
- The Java [Starlark](https://github.com/bazelbuild/bazel) interpreter from Bazel, as extended by
  [starlarky](https://github.com/verygoodsecurity/starlarky) (Apache-2.0), in
  `microproxy-starlark`.
- starlarky's Larky runtime and Python-compatible standard library (Apache-2.0, with CPython and
  ElementTree notices in some files), in `microproxy-starlark`.
- Logic ported from [mitmproxy](https://github.com/mitmproxy/mitmproxy) and
  [mitmproxy_rs](https://github.com/mitmproxy/mitmproxy_rs) (MIT): in the core, ClientHello
  parsing (from TLS records and from QUIC Initial packets), the ignore / allow host rules and the
  reverse mode specification; in
  `org.microproxy.extras`, the addons, flow filter expressions, HAR export and reading, and server
  and client replay; and for the content views in `org.microproxy.contentviews`, the schema-less
  protobuf heuristics and rendering, the gRPC view, the choice of views by priority, and the
  GraphQL, Socket.IO and form views. The ported files name their sources in their header comments,
  and the content views' test vectors run in the build.

Besides LittleProxy, these projects contributed ideas only; no code was copied:

- [baloise/proxy](https://github.com/baloise/proxy): `NO_PROXY` bypass and proxy settings from
  the environment.
- [littleproxy-response-modifier](https://github.com/MichielCM/littleproxy-response-modifier):
  declarative rewrite rules.
- [MoCuishle](https://github.com/ganskef/MoCuishle): content decoding and merged trust stores.
- [LittleProxy-mitm](https://github.com/ganskef/LittleProxy-mitm): a bounded certificate cache
  and copying IP SANs.

## License

Apache License 2.0, like LittleProxy, from which this project is derived.
