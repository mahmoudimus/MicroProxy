# Your first Starlark script

Drive the proxy from a [Starlark](https://github.com/bazelbuild/starlark) script (a sandboxed
Python dialect) instead of Java: answer a request, add headers, and watch the script reload when
you edit it. Use this page to get started; [Scripting with Starlark](../guides/scripting.md) and
the [Starlark API](../reference/starlark-api.md) cover everything else.

## Write the script

Save this as `hello.star`. Every hook is optional; these two run for every request and every
response:

```python
def on_request(req, ctx):
    if req.path == "/hello":
        return response(200, "hello from Starlark\n")   # answer without contacting the server
    req.headers["X-Client"] = ctx.client_ip              # add a header to what goes upstream

def on_response(req, res, ctx):
    res.headers["X-Scripted"] = "yes"
```

## Run it

Scripting is in the `microproxy-starlark` module; its `-all` jar has the launcher and every
optional feature built in ([Install](install.md#the-self-contained-all-jar)):

<!-- x-release-please-start-version -->
```bash
MICROPROXY_VERSION=0.5.0
java -jar microproxy-starlark/target/microproxy-starlark-${MICROPROXY_VERSION}-all.jar --port 8080 --script hello.star
```
<!-- x-release-please-end -->

```console
$ curl -s -x http://127.0.0.1:8080 http://example.com/hello
hello from Starlark
$ curl -s -o /dev/null -D - -x http://127.0.0.1:8080 http://example.com/ | grep -i x-scripted
X-Scripted: yes
```

Add `--mitm` to run the same hooks on the requests inside HTTPS connections (see
[MITM, certificates and TLS](../guides/mitm.md)).

## Edit it while it runs

The proxy re-reads the script when the file changes (checked at most once a second). An edit that
does not compile is logged and the previous version stays in use; `--script-no-reload` turns
reloading off. Scripts are sandboxed: no file, network or process access, and each hook call has
a budget of steps, time and memory ([Budgets and measurements](../reference/starlark-api.md#script-budgets)).

## From Java

The same script, embedded: one `ScriptedProxy` is the filters source and the chained proxy
manager (for an `upstream` hook).

```java
ScriptedProxy script = ScriptedProxy.builder(Path.of("hello.star")).build();
MicroProxy.bootstrap().withPort(8080).withFiltersSource(script).withChainProxyManager(script).start();
```

## Next steps

- [Scripting with Starlark](../guides/scripting.md): routing (`upstream`), interception decisions,
  failures, authentication, WebSockets, frames, TCP, UDP and QUIC hooks, with examples.
- [Starlark API](../reference/starlark-api.md): every hook, object, built-in and module.
