# Writing documentation

Where new documentation goes, the conventions every page follows, and how the site, `llms.txt` and
the checks are built. Read this before adding a feature, a flag or a property, or before changing a
page.

## Where content goes

The README is a short pitch, a quick start and links. Everything else lives in `docs/`, one topic
per page, and every page is listed in the `nav` of `mkdocs.yml` (a page that is not in the nav is a
build error).

| You are adding | Put it in |
|---|---|
| a command-line flag | its guide, **and** a row in [reference/cli.md](reference/cli.md) (a test fails without it) |
| a properties-file key | its guide, **and** a row in [reference/properties.md](reference/properties.md) (a test fails without it) |
| a stat | a row in [reference/stats.md](reference/stats.md), in the table of its family |
| an access-log operator or response flag | [reference/access-log-format.md](reference/access-log-format.md) or [reference/response-flags.md](reference/response-flags.md) |
| an admin path | [reference/admin-api.md](reference/admin-api.md) |
| a Starlark hook, object field, built-in or module | [reference/starlark-api.md](reference/starlark-api.md), with a worked example in [guides/scripting.md](guides/scripting.md) |
| a feature of an existing area | that area's guide under `guides/`, and a row (or a change) in the feature table of [index.md](index.md) |
| a new area | a new page under `guides/` (or `observability/`), added to `mkdocs.yml`'s nav and linked from [index.md](index.md) |
| a security-relevant default or limit | its guide, plus a line in [security.md](security.md) |
| a change that matters to LittleProxy users | [migrating-from-littleproxy.md](migrating-from-littleproxy.md) |
| internals (how the code works) | `microproxy/src/main/java/org/microproxy/impl/README.md`, summarised in [architecture.md](architecture.md) |

Homes for the work in flight:

- **TLS origination** (`https://` URIs without `CONNECT`): [Forward proxy, TLS
  origination](guides/forward-proxy.md#tls-origination-https-uris-without-connect), with its flags in
  the CLI reference, `originate_tls` in the properties reference, and pointers from
  [HTTP/2](guides/http2.md) (h2c and HTTP/2 to servers) and [Security](security.md).
- **HTTP/2 to chained proxies**: [Chained proxies](guides/chained-proxies.md) (a section next to
  *Upstream proxies and NO_PROXY*), with the limit removed from [HTTP/2, Remaining
  limits](guides/http2.md#remaining-limits) and [HTTP/2 to servers](guides/http2.md#http2-to-servers).
- **HTTP/2 on by default**: the defaults in [HTTP/2](guides/http2.md) (the paragraph after the first
  example), [reference/cli.md](reference/cli.md), [reference/properties.md](reference/properties.md),
  the [Quick start](getting-started/quick-start.md) and the feature table of [index.md](index.md),
  and a line in [Migrating from LittleProxy](migrating-from-littleproxy.md#behaviour-differences).

## Page conventions

These make the pages predictable for readers and for AI coding agents:

- **One H1 per page**, the page's title, followed by a **1-3 sentence summary** of what the page
  covers and when to use it. The first sentence of that summary becomes the page's line in
  `llms.txt`, so make it stand on its own.
- **Stable, descriptive headings.** Anchors come from heading text (GitHub's rules, which the site
  uses too), and other pages link to them: do not rename a heading without updating its links
  (`mkdocs build --strict` fails on a broken anchor). Prefer a heading to a bold run-in paragraph
  for anything a reader may want to link to. When a heading must change but old links exist, keep
  the old anchor with `<a id="old-anchor"></a>` on the line before it.
- **Runnable examples.** Commands and Java snippets should be copy-pasteable, with the imports or
  the context they need; show expected output where it helps (`console` blocks).
- **Links** between pages are relative Markdown links to `.md` files (`../guides/http2.md#limits`),
  which work both on GitHub and on the site. Links to files outside `docs/` (module READMEs,
  source files) are absolute GitHub URLs (`https://github.com/mahmoudimus/MicroProxy/blob/main/...`).
- **Versions** in examples sit between `<!-- x-release-please-start-version -->` and
  `<!-- x-release-please-end -->`, and the file is listed in `release-please-config.json`'s
  `extra-files`, so releases update them.
- **Tested examples.** Several Starlark examples are run by the tests exactly as the docs show
  them (`ScriptedReadmeTest.inDocs`): editing such an example means editing its test too.
- Plain Markdown only: no MkDocs-only syntax that would render badly on GitHub.

## Building and checking

The tools are pinned in `docs/requirements.txt` and used only in CI and development:

```bash
python3 -m venv .venv && .venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs serve                      # preview at http://127.0.0.1:8000/MicroProxy/
.venv/bin/mkdocs build --strict             # what CI runs: broken links and anchors fail
python3 docs/scripts/gen_llms.py write      # after adding, removing or retitling a page
python3 docs/scripts/check_links.py         # links in the Markdown outside docs/ (README, module READMEs)
mvn -pl microproxy test -Dtest=DocsDriftTest   # flags and properties are documented
```

`llms.txt` (the page list) and `llms-full.txt` (every page in one file) are written to the site's
root by the MkDocs hook `docs/scripts/hooks.py` on every build. `docs/llms.txt` is the
committed copy of the first, and CI fails when it is stale (`gen_llms.py check`).

The aggregated Javadoc is published under `/api/` with the site; see [Java API](java-api.md).
