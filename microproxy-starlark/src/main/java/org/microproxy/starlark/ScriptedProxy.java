package org.microproxy.starlark;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ChainedProxyManager;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ProxyFailure;
import org.microproxy.UpstreamProxyManager;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.WebSocketFrame;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;

/**
 * Drives the proxy from a Starlark script. Install it as both the filters source and the chained
 * proxy manager:
 *
 * <pre>{@code
 * ScriptedProxy script = ScriptedProxy.builder(Path.of("proxy.star")).build();
 * MicroProxy.bootstrap().withFiltersSource(script).withChainProxyManager(script).start();
 * }</pre>
 *
 * <p>The script may define any of these functions; each is optional:
 *
 * <ul>
 *   <li>{@code on_request(req, ctx)}: inspect or change a request. Return {@code response(...)} to
 *       answer it without contacting the server. Also called for {@code CONNECT}.
 *   <li>{@code on_response(req, res, ctx)}: inspect or change a response; may return a new
 *       {@code response(...)} to replace it.
 *   <li>{@code upstream(req, ctx)}: choose the route. Return {@code None} for the default,
 *       {@code "DIRECT"}, a proxy URL such as {@code "socks5://host:1080"}, or a list of these to
 *       try in order.
 *   <li>{@code allow_mitm(req, ctx)}: for a {@code CONNECT}, whether to intercept it (when a MITM
 *       manager is configured).
 *   <li>{@code buffer_request(req, ctx)}: whether to buffer this request's body so {@code
 *       on_request} can read {@code req.body}. Default: no.
 *   <li>{@code buffer_response(req, res, ctx)}: whether to buffer this response's body. Default:
 *       text bodies in a coding the proxy can decode, except event streams.
 *   <li>{@code on_websocket_frame(req, frame, ctx)}: for each frame of an upgraded WebSocket
 *       connection, in both directions. Assign {@code frame.text} or {@code frame.payload} to
 *       change it; return {@code False} to drop it, or {@code None} to forward it.
 *   <li>{@code on_failure(req, failure, ctx)}: when the proxy has to answer the request itself
 *       (the server's name did not resolve, the connection was refused, the server timed out,
 *       ...). Return {@code response(...)} to answer, or {@code None} to leave it to the {@link
 *       org.microproxy.FailureResponder} or the default answer.
 * </ul>
 *
 * <p>A failing hook is logged and answered with {@code 500}; a failing {@code allow_mitm}
 * declines interception, a failing {@code upstream} rejects the request with {@code 502}, and a
 * failing {@code on_failure} leaves the answer to the responder or the default. When
 * the script is a file it is re-read when it changes (checked at most once a second); a version
 * that does not compile is logged and the previous one stays in use.
 */
public final class ScriptedProxy implements HttpFiltersSource, ChainedProxyManager {

    private static final System.Logger LOG = System.getLogger(ScriptedProxy.class.getName());
    private static final long RELOAD_CHECK_NANOS = TimeUnit.SECONDS.toNanos(1);

    private final Path path;
    private final boolean reload;
    private final StarlarkScript.Limits limits;
    private final int maxBodySize;
    private final ChainedProxyManager fallback;
    private final ReentrantLock reloadLock = new ReentrantLock();
    private volatile StarlarkScript script;
    private volatile FileTime loadedModified;
    private volatile long lastCheck;

    private ScriptedProxy(Builder b, StarlarkScript script, FileTime modified) {
        this.path = b.path;
        this.reload = b.reload && b.path != null;
        this.limits = b.limits;
        this.maxBodySize = b.maxBodySize;
        this.fallback = b.fallback;
        this.script = script;
        this.loadedModified = modified;
        this.lastCheck = System.nanoTime();
    }

    /** A proxy driven by the script in {@code file}. */
    public static Builder builder(Path file) {
        return new Builder(Objects.requireNonNull(file), null, null);
    }

    /** A proxy driven by {@code source}, for embedding and tests. */
    public static Builder builder(String source, String name) {
        return new Builder(null, Objects.requireNonNull(source), Objects.requireNonNull(name));
    }

    /** Options for {@link ScriptedProxy}. */
    public static final class Builder {
        private final Path path;
        private final String source;
        private final String name;
        private boolean reload = true;
        private StarlarkScript.Limits limits = StarlarkScript.Limits.DEFAULT;
        private int maxBodySize = 10 << 20;
        private ChainedProxyManager fallback;

        private Builder(Path path, String source, String name) {
            this.path = path;
            this.source = source;
            this.name = name;
        }

        /** Re-read the file when it changes (default true). */
        public Builder reload(boolean reload) {
            this.reload = reload;
            return this;
        }

        /** Step and time limits for each hook call. */
        public Builder limits(StarlarkScript.Limits limits) {
            this.limits = Objects.requireNonNull(limits);
            return this;
        }

        /** The most body bytes buffered for a script (default 10 MiB). */
        public Builder maxBodySize(int maxBodySize) {
            if (maxBodySize <= 0) throw new IllegalArgumentException("maxBodySize must be positive");
            this.maxBodySize = maxBodySize;
            return this;
        }

        /**
         * Routes requests when the script has no {@code upstream} function or it returns {@code
         * None}; by default such requests connect directly.
         */
        public Builder fallback(ChainedProxyManager fallback) {
            this.fallback = fallback;
            return this;
        }

        /** Compiles the script and runs its top level. */
        public ScriptedProxy build() throws IOException, ScriptException {
            if (path != null) {
                FileTime modified = Files.getLastModifiedTime(path);
                return new ScriptedProxy(this, StarlarkScript.load(path, limits), modified);
            }
            return new ScriptedProxy(this, StarlarkScript.compile(source, name, limits), null);
        }
    }

    /** The script in use, re-reading the file first if it changed. */
    public StarlarkScript script() {
        if (reload && System.nanoTime() - lastCheck >= RELOAD_CHECK_NANOS && reloadLock.tryLock()) {
            try {
                lastCheck = System.nanoTime();
                FileTime modified = Files.getLastModifiedTime(path);
                if (!modified.equals(loadedModified)) {
                    loadedModified = modified;
                    script = StarlarkScript.load(path, limits);
                    LOG.log(Level.INFO, "reloaded {0}", path);
                }
            } catch (IOException | ScriptException e) {
                LOG.log(Level.WARNING, "keeping the previous version of " + path + ": " + e.getMessage());
            } finally {
                reloadLock.unlock();
            }
        }
        return script;
    }

    // ---------------------------------------------------------------------------------------
    // HttpFiltersSource
    // ---------------------------------------------------------------------------------------

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        StarlarkScript s = script();
        if (s.defines("on_websocket_frame")) {
            return new FrameScriptFilters(s, originalRequest, flowContext);
        }
        if (!s.defines("on_request") && !s.defines("on_response") && !s.defines("allow_mitm")
                && !s.defines("buffer_request") && !s.defines("on_failure") && !s.defines("authenticate")) {
            return null;
        }
        return new ScriptFilters(s, originalRequest, flowContext);
    }

    /**
     * Adds {@code on_websocket_frame}. A separate class, because the proxy parses frames (and
     * keeps compression off) only for filters classes that override the frame hook.
     */
    private final class FrameScriptFilters extends ScriptFilters {
        /** Frames from both directions arrive concurrently but share ctx.vars. */
        private final ReentrantLock frameLock = new ReentrantLock();

        FrameScriptFilters(StarlarkScript s, HttpRequest original, FlowContext flow) {
            super(s, original, flow);
        }

        @Override
        public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
            ScriptFrame f = new ScriptFrame(frame, fromClient);
            frameLock.lock();
            try {
                Object r = s.call("on_websocket_frame", mu, request(), f, ctx);
                if (r == Starlark.NONE || r == Boolean.TRUE || r == f) return f.frame();
                if (r == Boolean.FALSE) return null;
                if (r instanceof ScriptFrame other) return other.frame();
                throw Starlark.errorf("on_websocket_frame must return None, True, False or a frame, not %s",
                        Starlark.type(r));
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": on_websocket_frame failed; forwarding the frame: "
                        + e.getMessageWithStack());
                return frame;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return frame;
            } finally {
                frameLock.unlock();
            }
        }
    }

    private class ScriptFilters implements HttpFilters {
        final StarlarkScript s;
        final Mutability mu = Mutability.create("request");
        final ScriptContext ctx;
        private final boolean secure;
        /** A copy of the request as it arrived, for hooks that may run before clientToProxyRequest. */
        private final HttpRequest original;
        private ScriptRequest req;

        ScriptFilters(StarlarkScript s, HttpRequest original, FlowContext flow) {
            this.s = s;
            this.original = original;
            this.secure = flow.getClientSslSession() != null;
            this.ctx = new ScriptContext(flow.getClientAddress(), flow.getClientDetails().getUserName(),
                    flow.getConnectionId(), secure, mu);
        }

        @Override
        public int requestBufferSizeInBytes(HttpRequest request) {
            if (!s.defines("buffer_request")) return 0;
            try {
                Object r = s.call("buffer_request", mu, new ScriptRequest(request, secure, true), ctx);
                return Starlark.truth(r) ? maxBodySize : 0;
            } catch (EvalException e) {
                failed("buffer_request", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return 0;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (!(httpObject instanceof HttpRequest request)) return null;
            req = new ScriptRequest(request, secure, false);
            if (s.defines("on_response")) {
                // Keep the server from choosing a coding (dcb, ...) the script could not read.
                HttpBodies.restrictAcceptEncoding(request);
            }
            if (!s.defines("on_request")) return null;
            try {
                Object r = s.call("on_request", mu, req, ctx);
                if (r instanceof ScriptResponse res) return res.response();
                if (r != Starlark.NONE) {
                    throw Starlark.errorf("on_request must return None or response(...), not %s", Starlark.type(r));
                }
                return null;
            } catch (EvalException e) {
                return failed("on_request", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return scriptError();
            }
        }

        @Override
        public boolean proxyToServerAllowMitm() {
            if (!s.defines("allow_mitm") || req == null) return true;
            try {
                return Starlark.truth(s.call("allow_mitm", mu, req, ctx));
            } catch (EvalException e) {
                failed("allow_mitm", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return false;
        }

        @Override
        public int responseBufferSizeInBytes(HttpResponse response) {
            if (!s.defines("on_response")) return 0;
            if (s.defines("buffer_response")) {
                try {
                    Object r = s.call("buffer_response", mu, request(), new ScriptResponse(response, true), ctx);
                    return Starlark.truth(r) ? maxBodySize : 0;
                } catch (EvalException e) {
                    failed("buffer_response", e);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return 0;
            }
            return HttpBodies.isText(response) && HttpBodies.canDecode(response)
                    && !"text/event-stream".equals(HttpBodies.mediaType(response)) ? maxBodySize : 0;
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            if (!(httpObject instanceof HttpResponse response) || !s.defines("on_response")) return httpObject;
            ScriptResponse res = new ScriptResponse(response, false);
            try {
                Object r = s.call("on_response", mu, request(), res, ctx);
                if (r instanceof ScriptResponse replacement && replacement != res) return replacement.response();
                if (r != Starlark.NONE && r != res) {
                    throw Starlark.errorf("on_response must return None or response(...), not %s", Starlark.type(r));
                }
                return httpObject;
            } catch (EvalException e) {
                return failed("on_response", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return scriptError();
            }
        }

        @Override
        public HttpResponse proxyToServerFailure(ProxyFailure failure) {
            if (!s.defines("on_failure")) return null;
            try {
                Object r = s.call("on_failure", mu, request(), new ScriptFailure(failure), ctx);
                if (r instanceof ScriptResponse res) return res.response();
                if (r != Starlark.NONE) {
                    throw Starlark.errorf("on_failure must return None or response(...), not %s", Starlark.type(r));
                }
            } catch (EvalException e) {
                // Falls through to the FailureResponder or the default: a failure stays a failure.
                LOG.log(Level.WARNING, s.name() + ": on_failure failed; sending the default answer: "
                        + e.getMessageWithStack());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        }

        ScriptRequest request() {
            if (req != null) return req;
            HttpRequest r = original != null ? original : new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
            return new ScriptRequest(r, secure, true);
        }

        private FullHttpResponse failed(String hook, EvalException e) {
            LOG.log(Level.WARNING, s.name() + ": " + hook + " failed: " + e.getMessageWithStack());
            return scriptError();
        }
    }

    private static FullHttpResponse scriptError() {
        byte[] body = "Proxy script error\n".getBytes(StandardCharsets.UTF_8);
        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR, body);
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
        HttpUtil.setContentLength(response, body.length);
        return response;
    }

    // ---------------------------------------------------------------------------------------
    // ChainedProxyManager
    // ---------------------------------------------------------------------------------------

    @Override
    public void lookupChainedProxies(HttpRequest request, Queue<ChainedProxy> chainedProxies, ClientDetails client) {
        StarlarkScript s = script();
        if (!s.defines("upstream")) {
            useFallback(request, chainedProxies, client);
            return;
        }
        Mutability mu = Mutability.create("upstream");
        // Without the flow context, an intercepted request's scheme is unknown; guess from the port.
        boolean secure = request.uri().startsWith("/") && request.headers().get(HttpHeaderNames.HOST) != null
                && request.headers().get(HttpHeaderNames.HOST).endsWith(":443");
        ScriptContext ctx = new ScriptContext(client.getClientAddress(), client.getUserName(), -1, secure, mu);
        try {
            Object r = s.call("upstream", mu, new ScriptRequest(request, secure, true), ctx);
            if (r == Starlark.NONE) {
                useFallback(request, chainedProxies, client);
            } else if (r instanceof String route) {
                chainedProxies.add(route(route));
            } else if (r instanceof Iterable<?> routes) {
                for (Object route : routes) {
                    if (!(route instanceof String text)) {
                        throw Starlark.errorf("upstream routes are strings, not %s", Starlark.type(route));
                    }
                    chainedProxies.add(route(text));
                }
            } else {
                throw Starlark.errorf("upstream must return None, a string or a list, not %s", Starlark.type(r));
            }
        } catch (EvalException e) {
            chainedProxies.clear();
            LOG.log(Level.WARNING, s.name() + ": upstream failed: " + e.getMessageWithStack());
        } catch (InterruptedException e) {
            chainedProxies.clear();
            Thread.currentThread().interrupt();
        }
    }

    private void useFallback(HttpRequest request, Queue<ChainedProxy> chainedProxies, ClientDetails client) {
        if (fallback != null) {
            fallback.lookupChainedProxies(request, chainedProxies, client);
        } else {
            chainedProxies.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
        }
    }

    private static ChainedProxy route(String route) throws EvalException {
        if (route.equalsIgnoreCase("DIRECT")) return ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION;
        try {
            return UpstreamProxyManager.proxy(route);
        } catch (IllegalArgumentException e) {
            throw Starlark.errorf("bad upstream %s: %s", route, e.getMessage());
        }
    }
}
