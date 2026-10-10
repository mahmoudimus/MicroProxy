package org.microproxy.contentviews;

import java.util.Locale;
import java.util.Objects;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpRequest;

/**
 * Turns a message body into readable text: protobuf as YAML with field numbers, gRPC message by
 * message, msgpack, form data, GraphQL, and so on. The idea follows mitmproxy's content views: a
 * view has a name, says how well it suits some data ({@link #priority}), and renders it. {@link
 * ContentViews} holds a set of views and picks the best one for each body.
 *
 * <p>Views see bodies with their {@code Content-Encoding} already removed. They must be safe to
 * call from many threads at once, and must not throw anything but {@link DecodeException} for
 * data they cannot render.
 */
public interface ContentView {

    /** {@return the view's name, in lower case, such as {@code grpc}} */
    String name();

    /**
     * How well this view suits {@code data}: 0 (or less) when it does not apply, more for a
     * better fit. Views for a specific {@code Content-Type} return 1; more specific views (GraphQL
     * among JSON bodies) return more. In {@code auto} mode, the view with the highest priority
     * renders the body.
     *
     * @param data the body, decoded
     * @param metadata what is known about the message
     * @return the priority
     */
    double priority(byte[] data, Metadata metadata);

    /**
     * Whether this view applies to {@code data} at all.
     *
     * @param data the body, decoded
     * @param metadata what is known about the message
     * @return whether {@link #priority} is positive
     */
    default boolean matches(byte[] data, Metadata metadata) {
        return priority(data, metadata) > 0;
    }

    /**
     * Renders {@code data} as text.
     *
     * @param data the body, decoded
     * @param metadata what is known about the message
     * @return the text, usually ending with a newline
     * @throws DecodeException if the data is not what this view renders
     */
    String render(byte[] data, Metadata metadata) throws DecodeException;

    /**
     * What a view knows about a body besides its bytes.
     *
     * @param contentType the {@code Content-Type} field, or {@code null}
     * @param headers the message's header fields (never {@code null})
     * @param trailers the message's trailer fields (never {@code null})
     * @param path the request's path and query (for a response, its request's), or {@code null};
     *     an absolute URI is reduced to its path and query
     * @param request whether the body is a request's
     */
    record Metadata(String contentType, HttpHeaders headers, HttpHeaders trailers, String path, boolean request) {

        /**
         * Fills in empty header fields for {@code null}, and reduces an absolute URI to its path.
         *
         * @param contentType the {@code Content-Type} field, or {@code null}
         * @param headers the header fields, or {@code null}
         * @param trailers the trailer fields, or {@code null}
         * @param path the request's path and query, or {@code null}
         * @param request whether the body is a request's
         */
        public Metadata {
            headers = headers != null ? headers : new HttpHeaders();
            trailers = trailers != null ? trailers : new HttpHeaders();
            path = pathOf(path);
        }

        /**
         * Metadata with only a content type.
         *
         * @param contentType the {@code Content-Type} field, or {@code null}
         * @return the metadata
         */
        public static Metadata of(String contentType) {
            HttpHeaders headers = new HttpHeaders();
            if (contentType != null) headers.set(HttpHeaderNames.CONTENT_TYPE, contentType);
            return new Metadata(contentType, headers, null, null, false);
        }

        /**
         * Metadata for a request's body.
         *
         * @param request the request
         * @return the metadata
         */
        public static Metadata forRequest(HttpRequest request) {
            return new Metadata(request.headers().get(HttpHeaderNames.CONTENT_TYPE), request.headers(),
                    null, request.uri(), true);
        }

        /**
         * Metadata for a response's body.
         *
         * @param request the request the response answers, or {@code null}
         * @param response the response (or any message)
         * @return the metadata
         */
        public static Metadata forResponse(HttpRequest request, HttpMessage response) {
            return new Metadata(response.headers().get(HttpHeaderNames.CONTENT_TYPE), response.headers(),
                    null, request == null ? null : request.uri(), false);
        }

        /**
         * This metadata with trailer fields.
         *
         * @param trailers the trailer fields
         * @return new metadata
         */
        public Metadata withTrailers(HttpHeaders trailers) {
            return new Metadata(contentType, headers, trailers, path, request);
        }

        /**
         * This metadata with a request path.
         *
         * @param path the request's path and query, or {@code null}
         * @return new metadata
         */
        public Metadata withPath(String path) {
            return new Metadata(contentType, headers, trailers, path, request);
        }

        /** {@return the media type of {@link #contentType} in lower case, without parameters, or ""} */
        public String mediaType() {
            if (contentType == null) return "";
            int semi = contentType.indexOf(';');
            return (semi >= 0 ? contentType.substring(0, semi) : contentType).strip().toLowerCase(Locale.ROOT);
        }

        /**
         * A parameter of {@link #contentType}, such as {@code boundary} or {@code charset}.
         *
         * @param name the parameter's name (any case)
         * @return its value without quotes, or {@code null}
         */
        public String parameter(String name) {
            if (contentType == null) return null;
            String[] parts = contentType.split(";");
            for (int i = 1; i < parts.length; i++) {
                int eq = parts[i].indexOf('=');
                if (eq < 0 || !parts[i].substring(0, eq).strip().equalsIgnoreCase(name)) continue;
                String value = parts[i].substring(eq + 1).strip();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                return value;
            }
            return null;
        }

        /**
         * A header field's first value.
         *
         * @param name the field name (any case)
         * @return the value, or {@code null}
         */
        public String header(String name) {
            return headers.get(Objects.requireNonNull(name));
        }

        /** The path and query of a request target, which may be in absolute form. */
        private static String pathOf(String uri) {
            if (uri == null) return null;
            int scheme = uri.indexOf("://");
            if (scheme > 0 && scheme < 8) {
                int slash = uri.indexOf('/', scheme + 3);
                return slash < 0 ? "/" : uri.substring(slash);
            }
            return uri;
        }
    }
}
