package org.microproxy.starlark;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.AuthResult;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.ChainedProxyManager;
import org.microproxy.ClientDetails;
import org.microproxy.ClientHello;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ProxyAuthenticator;
import org.microproxy.ProxyFailure;
import org.microproxy.SelectiveFilters;
import org.microproxy.UpstreamProxyManager;
import org.microproxy.cache.HttpCache;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.frames.FrameContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.Http3FramePipeline;
import org.microproxy.frames.HttpFrame;
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
import org.microproxy.http.WebSocketMessage;
import org.microproxy.quic.QuicContext;
import org.microproxy.quic.QuicDatagram;
import org.microproxy.quic.QuicInterceptor;
import org.microproxy.quic.QuicStreamContext;
import org.microproxy.quic.QuicStreamMessage;
import org.microproxy.tcp.TcpContext;
import org.microproxy.tcp.TcpInterceptor;
import org.microproxy.tcp.TcpMessage;
import org.microproxy.udp.UdpContext;
import org.microproxy.udp.UdpInterceptor;
import org.microproxy.udp.UdpMessage;
import org.microproxy.thirdparty.starlark.eval.Dict;
import org.microproxy.thirdparty.starlark.eval.EvalException;
import org.microproxy.thirdparty.starlark.eval.Mutability;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkBytes;
import org.microproxy.thirdparty.starlark.eval.StarlarkList;
import org.microproxy.thirdparty.starlark.eval.Tuple;

/**
 * Drives the proxy from a Starlark script. Install it as both the filters source and the chained
 * proxy manager:
 *
 * <pre>{@code
 * ScriptedProxy script = ScriptedProxy.builder(Path.of("proxy.star")).build();
 * MicroProxy.bootstrap().withFiltersSource(script).withChainProxyManager(script).start();
 * }</pre>
 *
 * <p>Install it as the {@link ProxyAuthenticator} too when the script defines {@code
 * authenticate} ({@link #definesAuthenticate()}).
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
 *   <li>{@code on_client_hello(hello, ctx)}: once the client of a {@code CONNECT} that may be
 *       intercepted (or of a transparent TLS connection, or a transparent QUIC flow, whose
 *       ClientHello the proxy reads from its Initial packets) has sent its TLS ClientHello, whether
 *       to intercept it: {@code False} tunnels (or relays) it untouched, {@code True} or {@code
 *       None} intercepts.
 *       {@code hello} has {@code sni}, {@code alpn}, {@code versions} and {@code cipher_suites};
 *       later hooks of the session see it as {@code ctx.client_hello}.
 *   <li>{@code buffer_request(req, ctx)}: whether to buffer this request's body so {@code
 *       on_request} can read {@code req.body}. Default: no.
 *   <li>{@code buffer_response(req, res, ctx)}: whether to buffer this response's body. Default:
 *       text bodies in a coding the proxy can decode, except event streams.
 *   <li>{@code on_websocket_frame(req, frame, ctx)}: for each frame of an upgraded WebSocket
 *       connection, in both directions. Assign {@code frame.text} or {@code frame.payload} to
 *       change it; return {@code False} to drop it, or {@code None} to forward it.
 *   <li>{@code on_websocket_message(msg, ctx)}: for each whole message (text or binary) of an
 *       upgraded WebSocket connection, joined from its frames and inflated, in both directions,
 *       after {@code on_websocket_frame} has seen its frames. As with {@code on_frame}: change
 *       {@code msg.text} or {@code msg.payload} in place and return {@code None} (or the message)
 *       to send it, {@code False} to drop it, another message to replace it, or a list of
 *       messages ({@code websocket_message(content, from_client=...)}) to send instead, each in
 *       the direction its {@code from_client} names (an empty list drops it).
 *   <li>{@code authenticate(req, ctx)}: decides whether a client may use the proxy, when this
 *       object is also installed as the {@link ProxyAuthenticator} ({@code
 *       withProxyAuthenticator(script)}). Return the user name (a non-empty string) or {@code
 *       True} to accept, {@code False} or {@code None} to reject with the default {@code 407}, or
 *       {@code response(...)} to reject with that answer. Anything else, a failure or a timeout
 *       rejects. A global {@code AUTHENTICATE_EVERY_REQUEST = True} authenticates every request
 *       instead of the first accepted one on each connection.
 *   <li>{@code on_failure(req, failure, ctx)}: when the proxy has to answer the request itself
 *       (the server's name did not resolve, the connection was refused, the server timed out,
 *       ...). Return {@code response(...)} to answer, or {@code None} to leave it to the {@link
 *       org.microproxy.FailureResponder} or the default answer.
 *   <li>{@code on_frame(frame, ctx)}: for each HTTP/2 and HTTP/3 frame, in each direction, when
 *       this object's {@link #frameInterceptor()} is installed ({@code withFrameInterceptor}): live
 *       where the proxy speaks the protocol, and for HTTP/3 frames run through an {@link
 *       Http3FramePipeline} with it. Change the frame in place and
 *       return {@code None} (or the frame) to pass it on, {@code False} to drop it, another frame
 *       to replace it, or a list of frames to replace it with (an empty list drops it). The rules
 *       of {@link FrameInterceptor} apply; a result that breaks them is logged, and the frame
 *       passed on unchanged.
 *   <li>{@code on_tcp_start(ctx)}, {@code on_tcp_message(msg, ctx)} and {@code on_tcp_end(ctx)}:
 *       for raw TCP tunnels (see {@link TcpInterceptor}), when this object's {@link
 *       #tcpInterceptor()} is installed ({@code withTcpInterceptor}). {@code msg} is a {@code
 *       TcpMessage}: {@code data}, {@code text}, {@code from_client} and {@code timestamp}. Change
 *       it in place and return {@code None} (or {@code True}, or the message) to pass it on,
 *       {@code False} to drop it, or bytes, a string or another message to replace it. {@code ctx}
 *       is a {@code TcpContext}: the target, {@code tls}, {@code sni}, {@code alpn}, {@code vars}
 *       for the tunnel, {@code error} in {@code on_tcp_end} after a failure, and {@code
 *       send(from_client, data)} to add bytes. A failing {@code on_tcp_message} passes the bytes
 *       on unchanged.
 *   <li>{@code on_udp_start(ctx)}, {@code on_udp_message(msg, ctx)} and {@code on_udp_end(ctx)}:
 *       for the datagrams of CONNECT-UDP flows (see {@link UdpInterceptor}), when this object's
 *       {@link #udpInterceptor()} is installed ({@code withUdpInterceptor}). {@code msg} is a
 *       {@code UdpMessage}, one datagram, with the fields and results of a {@code TcpMessage};
 *       {@code ctx} is a {@code UdpContext}: the target, its resolved {@code address}, {@code
 *       vars} for the flow, and {@code send(from_client, data)} to add a datagram.
 *   <li>{@code on_quic_start(ctx)}, {@code on_quic_stream_data(msg, ctx)}, {@code
 *       on_quic_datagram(msg, ctx)} and {@code on_quic_end(ctx)}: for QUIC intercepted stream by
 *       stream (see {@link QuicInterceptor}), when this object's {@link #quicInterceptor()} is
 *       installed ({@code withQuicInterceptor}). {@code msg} is a {@code QuicMessage}, with the
 *       fields and results of a {@code TcpMessage}: bytes of one read of a stream, or one datagram.
 *       {@code ctx} is a {@code QuicContext}: the server, {@code sni}, {@code alpn}, {@code masque},
 *       the stream ({@code stream_id}, {@code bidirectional}, {@code client_initiated}; {@code
 *       None} outside {@code on_quic_stream_data}), {@code vars} for the connection, {@code error}
 *       in {@code on_quic_end} after a failure, {@code send(from_client, data)} to add bytes to the
 *       stream and {@code send_datagram(from_client, data)} to add a datagram.
 * </ul>
 *
 * <p>A failing hook is logged and answered with {@code 500}; a failing {@code allow_mitm} or
 * {@code on_client_hello} declines interception, a failing {@code upstream} rejects the request with {@code 502}, and a
 * failing {@code on_failure} leaves the answer to the responder or the default. When
 * the script is a file it is re-read when it changes (checked at most once a second); a version
 * that does not compile is logged and the previous one stays in use.
 */
public final class ScriptedProxy implements HttpFiltersSource, ChainedProxyManager, ProxyAuthenticator {

    private static final System.Logger LOG = System.getLogger(ScriptedProxy.class.getName());
    private static final long RELOAD_CHECK_NANOS = TimeUnit.SECONDS.toNanos(1);

    private final Path path;
    private final boolean reload;
    private final StarlarkScript.Limits limits;
    private final int maxBodySize;
    private final ChainedProxyManager fallback;
    private final Map<String, Object> constants;
    private final ProtoSchema protoSchema;
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
        this.constants = b.constants;
        this.protoSchema = b.protoSchema;
        this.script = script;
        this.loadedModified = modified;
        this.lastCheck = System.nanoTime();
    }

    /**
     * A proxy driven by the script in {@code file}.
     *
     * @param file the UTF-8 script file, reloaded on changes by default
     * @return a builder configured to load the file
     */
    public static Builder builder(Path file) {
        return new Builder(Objects.requireNonNull(file), null, null);
    }

    /**
     * A proxy driven by {@code source}, for embedding and tests.
     *
     * @param source the Starlark source to compile
     * @param name the script name used in diagnostics
     * @return a builder configured to compile the supplied source
     */
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
        private Map<String, Object> constants = Map.of();
        private ProtoSchema protoSchema;

        private Builder(Path path, String source, String name) {
            this.path = path;
            this.source = source;
            this.name = name;
        }

        /**
         * Re-read the file when it changes (default true).
         *
         * @param reload whether to check for file changes; ignored for source strings
         * @return this builder
         */
        public Builder reload(boolean reload) {
            this.reload = reload;
            return this;
        }

        /**
         * Step and time limits for each hook call.
         *
         * @param limits the execution bounds for loading and calling the script
         * @return this builder
         */
        public Builder limits(StarlarkScript.Limits limits) {
            this.limits = Objects.requireNonNull(limits);
            return this;
        }

        /**
         * The most body bytes buffered for a script (default 10 MiB).
         *
         * @param maxBodySize the positive buffer limit in bytes
         * @return this builder
         * @throws IllegalArgumentException if the limit is not positive
         */
        public Builder maxBodySize(int maxBodySize) {
            if (maxBodySize <= 0) throw new IllegalArgumentException("maxBodySize must be positive");
            this.maxBodySize = maxBodySize;
            return this;
        }

        /**
         * Routes requests when the script has no {@code upstream} function or it returns {@code
         * None}; by default such requests connect directly.
         *
         * @param fallback the routing manager, or null to connect directly
         * @return this builder
         */
        public Builder fallback(ChainedProxyManager fallback) {
            this.fallback = fallback;
            return this;
        }

        /**
         * Adds read-only globals the script can use, such as tokens or host lists that should not
         * be written into the script. Values are strings, ints ({@code Integer}, {@code Long},
         * {@code BigInteger}, ...), booleans, and {@code List}s and {@code Map}s of them (map keys:
         * strings, ints or booleans); they are copied and frozen. They are predeclared, so the
         * type checker knows their types, and the script cannot assign them. Later calls add to
         * earlier ones.
         *
         * @param constants the additional globals, merged with earlier calls
         * @return this builder
         * @throws IllegalArgumentException for a name that is not an identifier or would hide a
         *     built-in ({@code len}, {@code json}, {@code Request}, ...), or a value of another type
         */
        public Builder constants(Map<String, ?> constants) {
            Map<String, Object> merged = new LinkedHashMap<>(this.constants);
            merged.putAll(ScriptConstants.convert(constants));
            this.constants = Collections.unmodifiableMap(merged);
            return this;
        }

        /**
         * A protobuf schema for the script's {@code protobuf} and {@code grpc} modules: with it,
         * {@code protobuf.decode(data, type="pkg.Message")} keys fields by name and {@code
         * protobuf.encode(fields, type="pkg.Message")} takes names.
         *
         * @param schema the schema, as from {@link ProtoSchema#load}
         * @return this builder
         */
        public Builder protoSchema(ProtoSchema schema) {
            this.protoSchema = Objects.requireNonNull(schema);
            return this;
        }

        /**
         * Compiles the script and runs its top level.
         *
         * @return a proxy using the compiled script
         * @throws IOException if the script file cannot be read or inspected
         * @throws ScriptException if compilation or top-level execution fails
         */
        public ScriptedProxy build() throws IOException, ScriptException {
            if (path != null) {
                FileTime modified = Files.getLastModifiedTime(path);
                return new ScriptedProxy(this,
                        StarlarkScript.load(path, limits, constants).withProtoSchema(protoSchema), modified);
            }
            return new ScriptedProxy(this,
                    StarlarkScript.compile(source, name, limits, constants).withProtoSchema(protoSchema), null);
        }
    }

    /**
     * The script in use, re-reading the file first if it changed.
     *
     * @return the current successfully compiled script
     */
    public StarlarkScript script() {
        if (reload && System.nanoTime() - lastCheck >= RELOAD_CHECK_NANOS && reloadLock.tryLock()) {
            try {
                lastCheck = System.nanoTime();
                FileTime modified = Files.getLastModifiedTime(path);
                if (!modified.equals(loadedModified)) {
                    loadedModified = modified;
                    script = StarlarkScript.load(path, limits, constants).withProtoSchema(protoSchema);
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
        if (s.defines("on_websocket_frame") || s.defines("on_websocket_message")) {
            return new WebSocketScriptFilters(s, originalRequest, flowContext);
        }
        if (!s.defines("on_request") && !s.defines("on_response") && !s.defines("allow_mitm")
                && !s.defines("on_client_hello") && !s.defines("buffer_request") && !s.defines("on_failure")
                && !s.defines("authenticate")) {
            return null;
        }
        return new ScriptFilters(s, originalRequest, flowContext);
    }

    /**
     * Adds {@code on_websocket_frame} and {@code on_websocket_message}. Selective, because the
     * proxy parses frames, and joins messages, only for the hooks the script defines.
     */
    private final class WebSocketScriptFilters extends ScriptFilters implements SelectiveFilters {
        /** Frames and messages from both directions arrive concurrently but share ctx.vars. */
        private final ReentrantLock frameLock = new ReentrantLock();
        private final boolean frames;
        private final boolean messages;

        WebSocketScriptFilters(StarlarkScript s, HttpRequest original, FlowContext flow) {
            super(s, original, flow);
            frames = s.defines("on_websocket_frame");
            messages = s.defines("on_websocket_message");
        }

        @Override
        public boolean sees(Body stream) {
            return switch (stream) {
                // As for any class that overrides the head hooks (see SelectiveFilters).
                case REQUEST, RESPONSE -> true;
                case WEBSOCKET_FRAMES -> frames;
                case WEBSOCKET_MESSAGES -> messages;
                case OBSERVED_WEBSOCKET_FRAMES -> false;
            };
        }

        @Override
        public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
            if (!frames) return frame;
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

        @Override
        public List<WebSocketMessage> filterWebSocketMessages(WebSocketMessage message, boolean fromClient) {
            if (!messages) return List.of(message);
            ScriptWebSocketMessage m = new ScriptWebSocketMessage(message);
            frameLock.lock();
            try {
                Object r = s.call("on_websocket_message", mu, m, ctx);
                if (r == Starlark.NONE || r == Boolean.TRUE || r == m) return List.of(m.message());
                if (r == Boolean.FALSE) return List.of();
                if (r instanceof ScriptWebSocketMessage other) return List.of(other.message());
                if (r instanceof StarlarkList<?> || r instanceof Tuple) {
                    List<WebSocketMessage> out = new ArrayList<>();
                    for (Object item : (Iterable<?>) r) {
                        if (!(item instanceof ScriptWebSocketMessage x)) {
                            throw Starlark.errorf("on_websocket_message lists hold messages, not %s", Starlark.type(item));
                        }
                        out.add(x.message());
                    }
                    return out;
                }
                throw Starlark.errorf("on_websocket_message must return None, True, False, a message or a list of"
                        + " messages, not %s", Starlark.type(r));
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": on_websocket_message failed; forwarding the message: "
                        + e.getMessageWithStack());
                return List.of(message);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return List.of(message);
            } finally {
                frameLock.unlock();
            }
        }
    }

    private class ScriptFilters implements HttpFilters {
        final StarlarkScript s;
        final Mutability mu = Mutability.create("request");
        final ScriptContext ctx;
        private final FlowContext flow;
        private final boolean secure;
        /** A copy of the request as it arrived, for hooks that may run before clientToProxyRequest. */
        private final HttpRequest original;
        private ScriptRequest req;

        ScriptFilters(StarlarkScript s, HttpRequest original, FlowContext flow) {
            this.s = s;
            this.original = original;
            this.flow = flow;
            this.secure = flow.getClientSslSession() != null;
            this.ctx = new ScriptContext(flow, mu);
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
        public boolean proxyToServerAllowMitm(ClientHello clientHello) {
            if (!s.defines("on_client_hello")) return true;
            try {
                Object r = s.call("on_client_hello", mu, new ScriptClientHello(clientHello), ctx);
                if (r == Starlark.NONE || r == Boolean.TRUE) return true;
                if (r == Boolean.FALSE) return false;
                throw Starlark.errorf("on_client_hello must return True, False or None, not %s", Starlark.type(r));
            } catch (EvalException e) {
                failed("on_client_hello", e);
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
                    Object r = s.call("buffer_response", mu, request(), received(response, true), ctx);
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
            ScriptResponse res = received(response, false);
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

        /** A response arriving at serverToProxyResponse (or its head, to decide on buffering). */
        private ScriptResponse received(HttpResponse response, boolean readOnly) {
            OptionalInt upstream = flow.upstreamStatus();
            return new ScriptResponse(response, readOnly, source(response, upstream), upstream.orElse(-1));
        }

        /**
         * Where a response reaching serverToProxyResponse came from. The proxy decides the final
         * {@link org.microproxy.ResponseSource} only when the response is sent, after every filter;
         * here it is known from what this hook receives: the cache's answers are their own class,
         * the CONNECT 200 is the proxy's, and anything else is the server's response, unless an
         * earlier filter in a chain gave it another status. Null when none of these applies.
         */
        private String source(HttpResponse response, OptionalInt upstream) {
            if (response instanceof HttpCache.Answer) return "cache";
            if (original != null && original.method().equals(HttpMethod.CONNECT)) {
                return response.status().code() == 200 ? "proxy" : "filter";
            }
            if (upstream.isEmpty()) return null;
            return upstream.getAsInt() == response.status().code() ? "server" : "filter";
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
    // FrameInterceptor
    // ---------------------------------------------------------------------------------------

    /**
     * Whether the script in use defines {@code on_frame}, so {@link #frameInterceptor()} is worth
     * installing. A proxy without it pays nothing per frame.
     *
     * @return whether the current script provides the frame hook
     */
    public boolean definesFrameHook() {
        return script().defines("on_frame");
    }

    /**
     * An interceptor that calls the script's {@code on_frame(frame, ctx)}, for {@link
     * org.microproxy.HttpProxyServerBootstrap#withFrameInterceptor} (live HTTP/2 and HTTP/3) or
     * {@link Http3FramePipeline#builder} (HTTP/3 streams relayed otherwise). Frames pass on
     * unchanged when the script in use (after
     * a reload) has no {@code on_frame}, and when the call fails, which is logged.
     *
     * @return the interceptor
     */
    public FrameInterceptor frameInterceptor() {
        return this::onFrame;
    }

    private HttpFrame onFrame(HttpFrame frame, FrameDirection direction, FrameContext context) {
        StarlarkScript s = script();
        if (!s.defines("on_frame")) return frame;
        Mutability mu = Mutability.create("frame");
        ScriptHttpFrame f = new ScriptHttpFrame(frame, direction, context.streamId(), mu);
        try {
            Object r = s.call("on_frame", mu, f, new ScriptFrameContext(context));
            if (r == Starlark.NONE || r == Boolean.TRUE || r == f) return f.toFrame();
            if (r == Boolean.FALSE) return null;
            if (r instanceof ScriptHttpFrame other) return other.toFrame();
            if (r instanceof StarlarkList<?> || r instanceof Tuple) {
                List<HttpFrame> frames = new ArrayList<>();
                for (Object item : Starlark.toIterable(r)) {
                    if (!(item instanceof ScriptHttpFrame x)) {
                        throw Starlark.errorf("on_frame lists hold frames, not %s", Starlark.type(item));
                    }
                    frames.add(x.toFrame());
                }
                if (frames.isEmpty()) return null;
                for (HttpFrame added : frames.subList(1, frames.size())) context.send(added);
                return frames.getFirst();
            }
            throw Starlark.errorf("on_frame must return None, True, False, a frame or a list of frames, not %s",
                    Starlark.type(r));
        } catch (EvalException e) {
            LOG.log(Level.WARNING, s.name() + ": on_frame failed; passing the frame on: " + e.getMessageWithStack());
            return frame;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return frame;
        }
    }

    // ---------------------------------------------------------------------------------------
    // UdpInterceptor
    // ---------------------------------------------------------------------------------------

    /**
     * Whether the script in use defines {@code on_udp_start}, {@code on_udp_message} or {@code
     * on_udp_end}, so {@link #udpInterceptor()} is worth installing.
     *
     * @return whether the current script provides a UDP hook
     */
    public boolean definesUdpHooks() {
        StarlarkScript s = script();
        return s.defines("on_udp_start") || s.defines("on_udp_message") || s.defines("on_udp_end");
    }

    /**
     * An interceptor that calls the script's {@code on_udp_start(ctx)}, {@code on_udp_message(msg,
     * ctx)} and {@code on_udp_end(ctx)}, for {@link
     * org.microproxy.HttpProxyServerBootstrap#withUdpInterceptor}: the datagrams of CONNECT-UDP
     * flows. The calls of one flow, which come from a thread per direction, run one at a time, so
     * they can share {@code ctx.vars}. {@code on_udp_message} returns what to send on: {@code None}
     * or {@code True} for the message (as changed), {@code False} to drop it, or bytes, a string
     * or a message to send instead. A datagram passes on unchanged when the script in use has no
     * {@code on_udp_message}, and when the call fails, which is logged.
     *
     * @return the interceptor
     */
    public UdpInterceptor udpInterceptor() {
        return new ScriptUdpInterceptor();
    }

    /** One flow's script state: its context, and the lock its calls take turns with. */
    private static final class UdpFlowState {
        final Mutability mu = Mutability.create("udp");
        final ScriptUdpContext ctx;
        final ReentrantLock lock = new ReentrantLock();

        UdpFlowState(UdpContext context) {
            this.ctx = new ScriptUdpContext(context, mu);
        }
    }

    private final class ScriptUdpInterceptor implements UdpInterceptor {
        private final Map<UdpContext, UdpFlowState> flows = new ConcurrentHashMap<>();

        private UdpFlowState flow(UdpContext context) {
            return flows.computeIfAbsent(context, UdpFlowState::new);
        }

        @Override
        public void udpStart(UdpContext context) {
            UdpFlowState f = flow(context);
            StarlarkScript s = script();
            if (s.defines("on_udp_start")) call(s, f, "on_udp_start", f.ctx);
        }

        @Override
        public byte[] udpMessage(UdpMessage message, UdpContext context) {
            StarlarkScript s = script();
            if (!s.defines("on_udp_message")) return message.data();
            UdpFlowState f = flow(context);
            ScriptUdpMessage m = new ScriptUdpMessage(message.data(), message.fromClient(), message.timestamp());
            f.lock.lock();
            try {
                Object r = s.call("on_udp_message", f.mu, m, f.ctx);
                if (r == Starlark.NONE || r == Boolean.TRUE || r == m) return m.data();
                if (r == Boolean.FALSE) return null;
                if (r instanceof ScriptUdpMessage other) return other.data();
                if (r instanceof String || r instanceof StarlarkBytes) return Builtins.bytes(r, "the result");
                throw Starlark.errorf("on_udp_message must return None, True, False, bytes, a string or a message,"
                        + " not %s", Starlark.type(r));
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": on_udp_message failed; passing the datagram on: "
                        + e.getMessageWithStack());
                return message.data();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return message.data();
            } finally {
                f.lock.unlock();
            }
        }

        @Override
        public void udpEnd(UdpContext context) {
            UdpFlowState f = flows.remove(context);
            if (f == null) f = new UdpFlowState(context);
            StarlarkScript s = script();
            if (s.defines("on_udp_end")) call(s, f, "on_udp_end", f.ctx);
        }

        /** Calls a hook whose result does not matter; a failure is logged. */
        private void call(StarlarkScript s, UdpFlowState f, String hook, Object... args) {
            f.lock.lock();
            try {
                s.call(hook, f.mu, args);
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": " + hook + " failed: " + e.getMessageWithStack());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                f.lock.unlock();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // QuicInterceptor
    // ---------------------------------------------------------------------------------------

    /**
     * Whether the script in use defines {@code on_quic_start}, {@code on_quic_stream_data}, {@code
     * on_quic_datagram} or {@code on_quic_end}, so {@link #quicInterceptor()} is worth installing.
     * Installing it makes the proxy intercept QUIC that is not HTTP/3 (see {@link QuicInterceptor}).
     *
     * @return whether the current script provides a QUIC hook
     */
    public boolean definesQuicHooks() {
        StarlarkScript s = script();
        return s.defines("on_quic_start") || s.defines("on_quic_stream_data") || s.defines("on_quic_datagram")
                || s.defines("on_quic_end");
    }

    /**
     * An interceptor that calls the script's {@code on_quic_start(ctx)}, {@code
     * on_quic_stream_data(msg, ctx)}, {@code on_quic_datagram(msg, ctx)} and {@code on_quic_end(ctx)},
     * for {@link org.microproxy.HttpProxyServerBootstrap#withQuicInterceptor}: QUIC intercepted
     * stream by stream. The calls of one connection, which come from a thread per direction of each
     * stream and of datagrams, run one at a time, so they can share {@code ctx.vars}. {@code
     * on_quic_stream_data} and {@code on_quic_datagram} return what to send on: {@code None} or
     * {@code True} for the message (as changed), {@code False} to drop it, or bytes, a string or a
     * message to send instead. Bytes pass on unchanged when the script in use has no such hook, and
     * when the call fails, which is logged.
     *
     * @return the interceptor
     */
    public QuicInterceptor quicInterceptor() {
        return new ScriptQuicInterceptor();
    }

    /** One connection's script state: its {@code vars}, and the lock its calls take turns with. */
    private static final class QuicConnectionState {
        final Mutability mu = Mutability.create("quic");
        final Dict<Object, Object> vars = Dict.of(mu);
        final ReentrantLock lock = new ReentrantLock();
    }

    private final class ScriptQuicInterceptor implements QuicInterceptor {
        private final Map<QuicContext, QuicConnectionState> connections = new ConcurrentHashMap<>();

        private QuicConnectionState state(QuicContext context) {
            return connections.computeIfAbsent(context.connection(), c -> new QuicConnectionState());
        }

        @Override
        public void quicStart(QuicContext context) {
            QuicConnectionState c = state(context);
            StarlarkScript s = script();
            if (s.defines("on_quic_start")) {
                call(s, c, "on_quic_start", new ScriptQuicContext(context, null, c.vars, null));
            }
        }

        @Override
        public byte[] streamData(QuicStreamMessage message, QuicStreamContext stream) {
            return data("on_quic_stream_data", message.data(), message.fromClient(), message.timestamp(), stream, stream);
        }

        @Override
        public byte[] datagram(QuicDatagram datagram, QuicContext context) {
            return data("on_quic_datagram", datagram.data(), datagram.fromClient(), datagram.timestamp(), context, null);
        }

        /** Calls a hook that decides what bytes to pass on. */
        private byte[] data(String hook, byte[] data, boolean fromClient, java.time.Instant timestamp, QuicContext context,
                QuicStreamContext stream) {
            StarlarkScript s = script();
            if (!s.defines(hook)) return data;
            QuicConnectionState c = state(context);
            ScriptQuicMessage m = new ScriptQuicMessage(data, fromClient, timestamp);
            c.lock.lock();
            try {
                Object r = s.call(hook, c.mu, m, new ScriptQuicContext(context.connection(), stream, c.vars, null));
                if (r == Starlark.NONE || r == Boolean.TRUE || r == m) return m.data();
                if (r == Boolean.FALSE) return null;
                if (r instanceof ScriptQuicMessage other) return other.data();
                if (r instanceof String || r instanceof StarlarkBytes) return Builtins.bytes(r, "the result");
                throw Starlark.errorf("%s must return None, True, False, bytes, a string or a message, not %s", hook,
                        Starlark.type(r));
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": " + hook + " failed; passing the bytes on: " + e.getMessageWithStack());
                return data;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return data;
            } finally {
                c.lock.unlock();
            }
        }

        @Override
        public void quicEnd(QuicContext context) {
            end(context, null);
        }

        @Override
        public void quicError(QuicContext context, Throwable error) {
            end(context, error);
        }

        private void end(QuicContext context, Throwable error) {
            QuicConnectionState c = connections.remove(context.connection());
            if (c == null) c = new QuicConnectionState();
            StarlarkScript s = script();
            if (!s.defines("on_quic_end")) return;
            String why = null;
            if (error != null) {
                why = error.getMessage() == null || error.getMessage().isEmpty() ? error.getClass().getSimpleName()
                        : error.getMessage();
            }
            call(s, c, "on_quic_end", new ScriptQuicContext(context, null, c.vars, why));
        }

        /** Calls a hook whose result does not matter; a failure is logged. */
        private void call(StarlarkScript s, QuicConnectionState c, String hook, Object... args) {
            c.lock.lock();
            try {
                s.call(hook, c.mu, args);
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": " + hook + " failed: " + e.getMessageWithStack());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                c.lock.unlock();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // TcpInterceptor
    // ---------------------------------------------------------------------------------------

    /**
     * Whether the script in use defines {@code on_tcp_start}, {@code on_tcp_message} or {@code
     * on_tcp_end}, so {@link #tcpInterceptor()} is worth installing. A proxy without one copies
     * tunnel bytes as before.
     *
     * @return whether the current script provides a TCP hook
     */
    public boolean definesTcpHooks() {
        StarlarkScript s = script();
        return s.defines("on_tcp_start") || s.defines("on_tcp_message") || s.defines("on_tcp_end");
    }

    /**
     * An interceptor that calls the script's {@code on_tcp_start(ctx)}, {@code on_tcp_message(msg,
     * ctx)} and {@code on_tcp_end(ctx)}, for {@link
     * org.microproxy.HttpProxyServerBootstrap#withTcpInterceptor}. The calls of one tunnel, which
     * come from a thread per direction, run one at a time, so they can share {@code ctx.vars}.
     * Bytes pass on unchanged when the script in use (after a reload) has no {@code
     * on_tcp_message}, and when the call fails, which is logged.
     *
     * @return the interceptor
     */
    public TcpInterceptor tcpInterceptor() {
        return new ScriptTcpInterceptor();
    }

    /** One tunnel's script state: its context, and the lock its calls take turns with. */
    private static final class TcpTunnel {
        final Mutability mu = Mutability.create("tcp");
        final ScriptTcpContext ctx;
        final ReentrantLock lock = new ReentrantLock();

        TcpTunnel(TcpContext context) {
            this.ctx = new ScriptTcpContext(context, mu);
        }
    }

    private final class ScriptTcpInterceptor implements TcpInterceptor {
        private final Map<TcpContext, TcpTunnel> tunnels = new ConcurrentHashMap<>();

        private TcpTunnel tunnel(TcpContext context) {
            return tunnels.computeIfAbsent(context, TcpTunnel::new);
        }

        @Override
        public void tcpStart(TcpContext context) {
            TcpTunnel t = tunnel(context);
            StarlarkScript s = script();
            if (s.defines("on_tcp_start")) call(s, t, "on_tcp_start", t.ctx);
        }

        @Override
        public byte[] tcpMessage(TcpMessage message, TcpContext context) {
            StarlarkScript s = script();
            if (!s.defines("on_tcp_message")) return message.data();
            TcpTunnel t = tunnel(context);
            ScriptTcpMessage m = new ScriptTcpMessage(message.data(), message.fromClient(), message.timestamp());
            t.lock.lock();
            try {
                Object r = s.call("on_tcp_message", t.mu, m, t.ctx);
                if (r == Starlark.NONE || r == Boolean.TRUE || r == m) return m.data();
                if (r == Boolean.FALSE) return null;
                if (r instanceof ScriptTcpMessage other) return other.data();
                if (r instanceof String || r instanceof StarlarkBytes) return Builtins.bytes(r, "the result");
                throw Starlark.errorf("on_tcp_message must return None, True, False, bytes, a string or a message,"
                        + " not %s", Starlark.type(r));
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": on_tcp_message failed; passing the bytes on: "
                        + e.getMessageWithStack());
                return message.data();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return message.data();
            } finally {
                t.lock.unlock();
            }
        }

        @Override
        public void tcpEnd(TcpContext context) {
            end(context, null);
        }

        @Override
        public void tcpError(TcpContext context, Throwable error) {
            end(context, error);
        }

        private void end(TcpContext context, Throwable error) {
            TcpTunnel t = tunnels.remove(context);
            if (t == null) t = new TcpTunnel(context);
            if (error != null) t.ctx.error(error);
            StarlarkScript s = script();
            if (s.defines("on_tcp_end")) call(s, t, "on_tcp_end", t.ctx);
        }

        /** Calls a hook whose result does not matter; a failure is logged. */
        private void call(StarlarkScript s, TcpTunnel t, String hook, Object... args) {
            t.lock.lock();
            try {
                s.call(hook, t.mu, args);
            } catch (EvalException e) {
                LOG.log(Level.WARNING, s.name() + ": " + hook + " failed: " + e.getMessageWithStack());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                t.lock.unlock();
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // ProxyAuthenticator
    // ---------------------------------------------------------------------------------------

    /**
     * Whether the script in use defines {@code authenticate}, so this can be the authenticator.
     *
     * @return whether the current script provides the authentication hook
     */
    public boolean definesAuthenticate() {
        return script().defines("authenticate");
    }

    /** Not used: {@link #authenticate(HttpRequest, FlowContext)} asks the script instead. */
    @Override
    public boolean authenticate(String userName, String password) {
        return false;
    }

    /**
     * Calls the script's {@code authenticate(req, ctx)}. Fails closed: a script without the
     * function (after a reload), a failing or timed-out call, or an unexpected return value
     * rejects the request with the default challenge, and is logged.
     */
    @Override
    public AuthResult authenticate(HttpRequest request, FlowContext flow) {
        StarlarkScript s = script();
        if (!s.defines("authenticate")) {
            LOG.log(Level.WARNING, s.name() + " defines no authenticate(); rejecting the request");
            return AuthResult.reject();
        }
        Mutability mu = Mutability.create("authenticate");
        // No filters exist yet for this request: the context comes from the connection.
        ScriptContext ctx = new ScriptContext(flow, mu);
        try {
            Object r = s.call("authenticate", mu, new ScriptRequest(request, flow.getClientSslSession() != null, true), ctx);
            if (r instanceof String user) {
                // "" is falsy, like False: `return USERS.get(token, "")` must not let anyone in.
                return user.isEmpty() ? AuthResult.reject() : AuthResult.accept(user);
            }
            if (r == Boolean.TRUE) return AuthResult.accept(null);
            if (r == Boolean.FALSE || r == Starlark.NONE) return AuthResult.reject();
            if (r instanceof ScriptResponse res) return AuthResult.reject(res.response());
            throw Starlark.errorf("authenticate must return a user name, True, False, None or response(...), not %s",
                    Starlark.type(r));
        } catch (EvalException e) {
            LOG.log(Level.WARNING, s.name() + ": authenticate failed; rejecting the request: " + e.getMessageWithStack());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, s.name() + ": authenticate failed; rejecting the request", e);
        }
        return AuthResult.reject();
    }

    /** Whether the script sets {@code AUTHENTICATE_EVERY_REQUEST} to a true value. */
    @Override
    public boolean authenticateEveryRequest() {
        Object every = script().global("AUTHENTICATE_EVERY_REQUEST");
        return every != null && Starlark.truth(every);
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
