package org.microproxy;

import java.io.IOException;
import java.net.UnknownHostException;
import org.microproxy.http.HttpResponseStatus;

/**
 * Why the proxy has to answer a request itself instead of relaying the server's response. Each
 * failure knows the status of the proxy's default answer; {@link HttpFilters#proxyToServerFailure}
 * and a {@link FailureResponder} can answer differently.
 *
 * <p>The default answers are short plain-text bodies ({@code Bad Gateway}, {@code Gateway
 * Timeout}, ...) that never echo the request. Requests the proxy cannot parse at all (malformed
 * or oversized heads, bad chunk framing) are answered with a plain {@code 4xx} without consulting
 * filters or the responder, since there is no request to hand over.
 */
public sealed interface ProxyFailure {

    /** {@return the status of the proxy's default answer} */
    HttpResponseStatus status();

    /**
     * The server's name did not resolve (direct connections). Default {@code 502}.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     * @param cause the failure that triggered this event
     */
    record UnresolvedHost(String hostAndPort, UnknownHostException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * No connection could be made to the server or any chained proxy offered for it: refused,
     * unreachable, timed out, a chained proxy whose own name did not resolve, or a chained proxy
     * that refused the {@code CONNECT} or SOCKS request.
     * With several chained proxies, {@code cause} is the last one's failure. Default {@code 502}.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     * @param cause the failure that triggered this event
     */
    record ConnectFailed(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * The TLS handshake with the server (when intercepting) or with a TLS chained proxy failed or
     * did not finish within {@link HttpProxyServerBootstrap#withTlsHandshakeTimeout} (or the
     * request's {@link HttpFilters#proxyToServerTlsHandshakeTimeout()}), e.g. because its
     * certificate is not trusted. Default {@code 502}.
     *
     * <p>{@code cause} is the handshake's own exception, as the JDK threw it, with its whole cause
     * chain: an {@link javax.net.ssl.SSLHandshakeException} whose causes say, for example, that the
     * certificate was revoked (a {@link java.security.cert.CertPathValidatorException} with reason
     * {@link java.security.cert.CertPathValidatorException.BasicReason#REVOKED}); a {@link
     * java.net.SocketTimeoutException} for a handshake that overran its deadline. {@link #reason()}
     * and {@link #alert()} read the chain for the common cases.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     * @param cause the failure that triggered this event
     */
    record TlsFailed(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }

        /**
         * {@return why the handshake failed, as far as {@link #cause()}'s chain tells}
         *
         * @see Reason#of(Throwable)
         */
        public Reason reason() {
            return Reason.of(cause);
        }

        /**
         * {@return the description of the TLS alert the peer ended the handshake with, as RFC 8446
         * section 6 names it ({@code "unrecognized_name"}, {@code "handshake_failure"}, ...), or
         * null when the peer sent none}
         *
         * @see Reason#alertOf(Throwable)
         */
        public String alert() {
            return Reason.alertOf(cause);
        }

        /**
         * Why a TLS handshake failed, read from the exception's cause chain: the certificate checks
         * first, then an alert from the peer, a timeout, or anything else. {@link #code()} is the
         * snake_case name the access log's {@code %UPSTREAM_TRANSPORT_FAILURE_REASON%} starts with.
         */
        public enum Reason {
            /** The certificate (or one in its chain) has expired. */
            CERTIFICATE_EXPIRED,
            /** The certificate (or one in its chain) is not valid yet. */
            CERTIFICATE_NOT_YET_VALID,
            /** The certificate was revoked: a CRL or an OCSP response said so. */
            CERTIFICATE_REVOKED,
            /** Revocation checking was required, but no CRL or OCSP response could tell. */
            REVOCATION_STATUS_UNKNOWN,
            /** The chain does not lead to a trusted anchor, or failed another validation check. */
            CERTIFICATE_UNTRUSTED,
            /** The certificate is trusted, but not valid for the host name it was checked against. */
            HOSTNAME_MISMATCH,
            /** The peer ended the handshake with an alert ({@link TlsFailed#alert()} names it). */
            ALERT_RECEIVED,
            /** The handshake did not finish within the handshake timeout. */
            TIMEOUT,
            /** Anything else: no common protocol version or cipher suite, the connection closed, ... */
            OTHER;

            private static final java.util.regex.Pattern ALERT = java.util.regex.Pattern.compile(
                    "(?i)received (?:fatal alert|handshake warning): ([a-z0-9_]+)");

            /** {@return the reason's name in lower case: {@code certificate_revoked}, ...} */
            public String code() {
                return name().toLowerCase(java.util.Locale.ROOT);
            }

            /**
             * Classifies a failed handshake by its exception's cause chain. A {@link
             * java.security.cert.CertPathValidatorException} with a {@link
             * java.security.cert.CertPathValidatorException.BasicReason}, a {@link
             * java.security.cert.CertificateExpiredException}, {@link
             * java.security.cert.CertificateNotYetValidException} or {@link
             * java.security.cert.CertificateRevokedException} anywhere in it says what was wrong
             * with the certificate (the innermost specific one wins); any other certificate path
             * failure means it is not trusted; a host name check that failed says so in its
             * message (the JDK's {@code "No subject alternative ... matching ..."}); and the JDK
             * reports an alert from the peer as {@code "Received fatal alert: <description>"}.
             *
             * @param failure the handshake's exception, or null
             * @return the reason, {@link #OTHER} when none is recognized
             */
            public static Reason of(Throwable failure) {
                Reason certificate = null;
                boolean hostname = false;
                boolean timeout = false;
                for (Throwable t = failure; t != null; t = t.getCause() == t ? null : t.getCause()) {
                    Reason found = certificateReason(t);
                    if (found != null && (certificate == null || certificate == CERTIFICATE_UNTRUSTED)) {
                        certificate = found;
                    }
                    String message = t.getMessage();
                    if (t instanceof java.security.cert.CertificateException && message != null
                            && (message.startsWith("No subject alternative") || message.startsWith("No name matching"))) {
                        hostname = true;
                    }
                    if (t instanceof java.net.SocketTimeoutException) timeout = true;
                }
                if (certificate != null) return certificate;
                if (hostname) return HOSTNAME_MISMATCH;
                if (alertOf(failure) != null) return ALERT_RECEIVED;
                return timeout ? TIMEOUT : OTHER;
            }

            private static Reason certificateReason(Throwable t) {
                if (t instanceof java.security.cert.CertificateExpiredException) return CERTIFICATE_EXPIRED;
                if (t instanceof java.security.cert.CertificateNotYetValidException) return CERTIFICATE_NOT_YET_VALID;
                if (t instanceof java.security.cert.CertificateRevokedException) return CERTIFICATE_REVOKED;
                if (t instanceof java.security.cert.CertPathValidatorException v) {
                    if (v.getReason() instanceof java.security.cert.CertPathValidatorException.BasicReason basic) {
                        return switch (basic) {
                            case EXPIRED -> CERTIFICATE_EXPIRED;
                            case NOT_YET_VALID -> CERTIFICATE_NOT_YET_VALID;
                            case REVOKED -> CERTIFICATE_REVOKED;
                            case UNDETERMINED_REVOCATION_STATUS -> REVOCATION_STATUS_UNKNOWN;
                            default -> CERTIFICATE_UNTRUSTED;
                        };
                    }
                    return CERTIFICATE_UNTRUSTED;
                }
                if (t instanceof java.security.cert.CertPathBuilderException) return CERTIFICATE_UNTRUSTED;
                return null;
            }

            /**
             * The description of the alert the peer ended a handshake with, as the JDK reports it:
             * {@code "Received fatal alert: unrecognized_name"}, or {@code "Received handshake
             * warning: ..."} for a warning it does not accept during a handshake.
             *
             * @param failure the handshake's exception, or null
             * @return the alert's description, such as {@code "unrecognized_name"}, or null
             */
            public static String alertOf(Throwable failure) {
                for (Throwable t = failure; t != null; t = t.getCause() == t ? null : t.getCause()) {
                    if (!(t instanceof javax.net.ssl.SSLException) || t.getMessage() == null) continue;
                    java.util.regex.Matcher m = ALERT.matcher(t.getMessage());
                    if (m.find()) return m.group(1).toLowerCase(java.util.Locale.ROOT);
                }
                return null;
            }
        }
    }

    /**
     * The server did not answer within the idle timeout. Default {@code 504}.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     * @param cause the failure that triggered this event
     */
    record ServerTimeout(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.GATEWAY_TIMEOUT;
        }
    }

    /**
     * The server's response was malformed, or the server closed the connection or failed before
     * the response head (or a body the filters asked to buffer) was complete. Default {@code 502}.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     * @param cause the failure that triggered this event
     */
    record BadServerResponse(String hostAndPort, IOException cause) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * There is nowhere to send the request: it names no host ({@code hostAndPort} is null), or the
     * {@link ChainedProxyManager} offered no route. Default {@code 502}.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     */
    record NoRoute(String hostAndPort) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_GATEWAY;
        }
    }

    /**
     * The {@linkplain HttpProxyServerBootstrap#withSharedServerConnectionPool shared connection
     * pool} had no connection to spare within the connect timeout. Default {@code 503}.
     *
     * @param hostAndPort the destination host and port, or {@code null} when unavailable
     */
    record NoConnectionAvailable(String hostAndPort) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.SERVICE_UNAVAILABLE;
        }
    }

    /**
     * The proxy refuses the request: an origin-form request without {@link
     * HttpProxyServerBootstrap#withAllowRequestToOriginServer}, an {@code https://} request without
     * {@link HttpProxyServerBootstrap#withTlsOrigination}, or a {@code CONNECT} target that is not
     * {@code host:port}. Default {@code 400} with the body {@code "Bad Request: " + reason}.
     *
     * @param reason the reason the request was rejected
     */
    record BadRequest(String reason) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.BAD_REQUEST;
        }
    }

    /**
     * The request body is larger than the filters asked to buffer ({@code maxBytes}). The client
     * connection is always closed afterwards, since the rest of the body is never read. Default
     * {@code 413}.
     *
     * @param maxBytes the maximum number of body bytes
     */
    record RequestTooLarge(int maxBytes) implements ProxyFailure {
        @Override
        public HttpResponseStatus status() {
            return HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE;
        }
    }
}
