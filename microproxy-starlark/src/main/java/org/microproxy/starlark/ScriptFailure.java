package org.microproxy.starlark;

import com.google.common.collect.ImmutableList;
import java.util.Locale;
import org.microproxy.ProxyFailure;
import org.microproxy.thirdparty.starlark.annot.StarlarkBuiltin;
import org.microproxy.thirdparty.starlark.eval.Printer;
import org.microproxy.thirdparty.starlark.eval.Starlark;
import org.microproxy.thirdparty.starlark.eval.StarlarkInt;
import org.microproxy.thirdparty.starlark.eval.StarlarkSemantics;
import org.microproxy.thirdparty.starlark.eval.Structure;
import org.microproxy.thirdparty.starlark.syntax.StarlarkType;
import org.microproxy.thirdparty.starlark.syntax.TypeConstructor;

/**
 * Why the proxy has to answer a request itself, as {@code on_failure} sees it: a read-only view
 * of a {@link ProxyFailure}.
 *
 * <ul>
 *   <li>{@code kind}: the failure in snake case ({@code "unresolved_host"}, {@code
 *       "connect_failed"}, {@code "tls_failed"}, {@code "server_timeout"}, {@code
 *       "bad_server_response"}, {@code "no_route"}, {@code "no_connection_available"}, {@code
 *       "bad_request"}, {@code "request_too_large"});
 *   <li>{@code status}: the status of the proxy's default answer;
 *   <li>{@code host}: the server's name (without the port), or {@code None} when the failure
 *       concerns no server;
 *   <li>{@code message}: the cause's message or the reason, never a stack trace.
 * </ul>
 */
@StarlarkBuiltin(name = "failure", doc = "Why the proxy could not relay a response.")
public final class ScriptFailure implements Structure {

    private static final ImmutableList<String> FIELDS = ImmutableList.of("kind", "status", "host", "message");

    private final ProxyFailure failure;

    ScriptFailure(ProxyFailure failure) {
        this.failure = failure;
    }

    /** Types the builtins that return this class (see {@link ScriptType}). */
    public static TypeConstructor getAssociatedTypeConstructor() {
        return ScriptType.FAILURE_CONSTRUCTOR;
    }

    @Override
    public StarlarkType getStarlarkType(StarlarkSemantics semantics) {
        return ScriptType.FAILURE;
    }

    /** The failure's kind in snake case. */
    static String kind(ProxyFailure failure) {
        return switch (failure) {
            case ProxyFailure.UnresolvedHost f -> "unresolved_host";
            case ProxyFailure.ConnectFailed f -> "connect_failed";
            case ProxyFailure.TlsFailed f -> "tls_failed";
            case ProxyFailure.ServerTimeout f -> "server_timeout";
            case ProxyFailure.BadServerResponse f -> "bad_server_response";
            case ProxyFailure.NoRoute f -> "no_route";
            case ProxyFailure.NoConnectionAvailable f -> "no_connection_available";
            case ProxyFailure.BadRequest f -> "bad_request";
            case ProxyFailure.RequestTooLarge f -> "request_too_large";
        };
    }

    private static String hostAndPort(ProxyFailure failure) {
        return switch (failure) {
            case ProxyFailure.UnresolvedHost f -> f.hostAndPort();
            case ProxyFailure.ConnectFailed f -> f.hostAndPort();
            case ProxyFailure.TlsFailed f -> f.hostAndPort();
            case ProxyFailure.ServerTimeout f -> f.hostAndPort();
            case ProxyFailure.BadServerResponse f -> f.hostAndPort();
            case ProxyFailure.NoRoute f -> f.hostAndPort();
            case ProxyFailure.NoConnectionAvailable f -> f.hostAndPort();
            case ProxyFailure.BadRequest f -> null;
            case ProxyFailure.RequestTooLarge f -> null;
        };
    }

    /** The host part of {@code host:port} (IPv6 literals without brackets), lower-cased. */
    static String host(String hostAndPort) {
        if (hostAndPort == null || hostAndPort.isEmpty()) return null;
        String host = hostAndPort;
        int colon = host.lastIndexOf(':');
        if (colon > host.lastIndexOf(']')) host = host.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        return host.toLowerCase(Locale.ROOT);
    }

    /** One line about the cause: its message, or its type when it has none. */
    static String message(ProxyFailure failure) {
        return switch (failure) {
            case ProxyFailure.UnresolvedHost f -> describe(f.cause(), "cannot resolve " + f.hostAndPort());
            case ProxyFailure.ConnectFailed f -> describe(f.cause(), "cannot connect to " + f.hostAndPort());
            case ProxyFailure.TlsFailed f -> describe(f.cause(), "TLS handshake with " + f.hostAndPort() + " failed");
            case ProxyFailure.ServerTimeout f -> describe(f.cause(), f.hostAndPort() + " did not answer in time");
            case ProxyFailure.BadServerResponse f -> describe(f.cause(), "bad response from " + f.hostAndPort());
            case ProxyFailure.NoRoute f -> f.hostAndPort() == null
                    ? "the request names no host" : "no route to " + f.hostAndPort();
            case ProxyFailure.NoConnectionAvailable f -> "no server connection available for " + f.hostAndPort();
            case ProxyFailure.BadRequest f -> f.reason();
            case ProxyFailure.RequestTooLarge f -> "request body larger than " + f.maxBytes() + " bytes";
        };
    }

    private static String describe(Throwable cause, String fallback) {
        if (cause == null) return fallback;
        String message = cause.getMessage();
        if (message == null || message.isBlank()) return cause.getClass().getSimpleName();
        // A message is one line here: some exceptions carry several.
        return message.lines().findFirst().orElse(fallback).strip();
    }

    @Override
    public Object getValue(String name) {
        return switch (name) {
            case "kind" -> kind(failure);
            case "status" -> StarlarkInt.of(failure.status().code());
            case "host" -> {
                String host = host(hostAndPort(failure));
                yield host == null ? Starlark.NONE : host;
            }
            case "message" -> message(failure);
            default -> null;
        };
    }

    @Override
    public ImmutableList<String> getFieldNames() {
        return FIELDS;
    }

    @Override
    public String getErrorMessageForUnknownField(String field) {
        return "failure has no field '" + field + "'";
    }

    @Override
    public void repr(Printer printer, StarlarkSemantics semantics) {
        printer.append("<failure ").append(kind(failure)).append(' ').append(failure.status().code()).append('>');
    }
}
