# .NET6 targeting-pack authority

The offline coverage build requires the two exact6.0.36 nupkg archives in
`net6-targeting-packs.json`, provided through mandatory `--targeting-packs`.
The package is not fetched during replay and is never inferred from a user
NuGet cache.

Authority is the official NuGet.org versioned package endpoint, independently
checked against its official catalog SHA512 hash and packageSize record. The
manifest records both versioned URLs, catalog URLs/digests, SHA256, base64 SHA512,
archive/expanded sizes and293+284 file counts. The reviewed SDK10.0.400's own
BundledVersions.props selects these exact net6 targeting-pack versions.

- Microsoft.NETCore.App.Ref6.0.36 SHA256:
  `f4b66056820517ca8dc94bbc91d26b6062eeb4c17f70bd8af361cddb2c30971f`
- Microsoft.AspNetCore.App.Ref6.0.36 SHA256:
  `f630e459b8f0fe777ccaa7735536a00aeaabea8c09fc350c8b80655194f88565`

After archive authentication and path/type checks, all577 payloads are copied
into the private installed targeting-pack root and hashed before/after. SDK
pack downloads are disabled. Empty explicit sources/fallbacks and a private
NuGet config/cache must produce no download dependencies; every actual compiler
reference/analyzer must belong to those authenticated packs or pinned tool trees.

The archive/provider/compiler remain explicit trusted boundaries. Coverage
receipts continue to say qualification:false and do not claim functional proofs,
noninterference, Java identity, delivery qualification or physical timing.

Primary documentation: [NuGet package content](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource),
[NuGet catalog hash fields](https://learn.microsoft.com/en-us/nuget/api/catalog-resource),
[MSBuild response-file suppression](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-response-files).
