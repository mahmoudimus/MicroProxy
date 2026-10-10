/*
 * Ported from mitmproxy_rs (https://github.com/mitmproxy/mitmproxy_rs),
 * mitmproxy-contentviews/src/protobuf/view_grpc.rs: the framing, decompression per grpc-encoding,
 * the content types and the "---" between messages; and existing_proto_definitions.rs: the
 * method's input type for requests and output type for responses. Copyright (c) 2022, Fabio
 * Valentini and Maximilian Hils. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy_rs.txt.
 */
package org.microproxy.contentviews;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.microproxy.http.HttpHeaders;

/**
 * gRPC bodies, message by message: each message is decompressed as {@code grpc-encoding} says and
 * rendered by the protobuf view (with the method's input or output type when the schema knows the
 * request path), separated by {@code ---}. Trailers ({@code grpc-status}, {@code grpc-message},
 * {@code grpc-status-details-bin} as a {@code google.rpc.Status}) follow when the metadata has
 * them, and so do gRPC-Web trailers frames. A body that ends inside a message (one cut short
 * for a log) shows the complete messages and says how much of the last one there is.
 */
final class GrpcView implements ContentView {

    private static final Set<String> TYPES = Set.of(
            "application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto",
            "application/grpc-web-text", "application/grpc-web-text+proto");

    /** The most a message may grow to when decompressed for viewing. */
    static final int MAX_MESSAGE_BYTES = 16 << 20;

    private final ProtoSchema schema;

    GrpcView(ProtoSchema schema) {
        this.schema = schema;
    }

    @Override
    public String name() {
        return "grpc";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        return TYPES.contains(metadata.mediaType()) ? 1 : 0;
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        String type = metadata.mediaType();
        boolean web = type.startsWith("application/grpc-web");
        byte[] body = data;
        if (type.startsWith("application/grpc-web-text")) {
            try {
                body = Base64.getMimeDecoder().decode(data);
            } catch (IllegalArgumentException e) {
                throw new DecodeException("invalid gRPC-Web text: " + e.getMessage(), e);
            }
        }
        Grpc.Scan scan = Grpc.scan(body, web);
        String encoding = metadata.header("grpc-encoding");
        ProtoSchema.MessageType messageType = schema.messageFor(metadata.path(), metadata.request()).orElse(null);
        List<String> parts = new ArrayList<>();
        for (Grpc.Frame frame : scan.frames()) {
            byte[] payload = frame.payload();
            String note = "";
            if (frame.compressed()) {
                payload = Grpc.decompress(payload, encoding, MAX_MESSAGE_BYTES);
                note = "# " + encoding.strip().toLowerCase(Locale.ROOT) + "-compressed, " + frame.payload().length
                        + " bytes\n";
            }
            parts.add(note + ProtobufView.render(schema, payload, messageType));
        }
        if (scan.rest() > 0) {
            parts.add(scan.restDeclared() < 0 ? "# " + scan.rest() + " bytes of an incomplete message header\n"
                    : "# incomplete message: " + (scan.rest() - 5) + " of " + scan.restDeclared() + " bytes\n");
        }
        HttpHeaders trailers = metadata.trailers();
        if (scan.trailers() != null) trailers = webTrailers(scan.trailers());
        if (!trailers.isEmpty()) parts.add("# trailers\n" + Yaml.emit(trailers(trailers, schema)));
        return String.join("\n---\n\n", parts);
    }

    /** A gRPC-Web trailers frame's payload: header lines. */
    private static HttpHeaders webTrailers(byte[] payload) {
        HttpHeaders out = new HttpHeaders();
        for (String line : new String(payload, StandardCharsets.UTF_8).split("\r?\n")) {
            int colon = line.indexOf(':');
            if (colon > 0) out.add(line.substring(0, colon).strip(), line.substring(colon + 1).strip());
        }
        return out;
    }

    /** Trailer (or header) fields, with gRPC's known ones explained. */
    static Yaml.Mapping trailers(HttpHeaders fields, ProtoSchema schema) {
        Yaml.Mapping out = new Yaml.Mapping();
        for (Map.Entry<String, String> e : fields) {
            Yaml.Node described = describe(e.getKey(), e.getValue(), schema);
            out.put(Yaml.string(e.getKey()), described != null ? described : new Yaml.Scalar(Yaml.string(e.getValue())));
        }
        return out;
    }

    /**
     * What a gRPC header or trailer field means: the name of a {@code grpc-status}, the text of a
     * percent-encoded {@code grpc-message}, the status in {@code grpc-status-details-bin}, the
     * message in other binary ({@code -bin}) fields; or {@code null} for other fields.
     */
    static Yaml.Node describe(String name, String value, ProtoSchema schema) {
        String n = name.toLowerCase(Locale.ROOT);
        if (n.equals("grpc-status")) {
            try {
                String code = Grpc.codeName(Integer.parseInt(value.strip()));
                return new Yaml.Scalar(Yaml.string(value), code);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (n.equals("grpc-message")) {
            String message = Grpc.message(value);
            return message.equals(value) ? null : new Yaml.Scalar(Yaml.string(message), "percent-decoded");
        }
        if (n.endsWith("-bin")) {
            try {
                byte[] bytes = Grpc.base64(value);
                if (bytes.length == 0) return null;
                String type = n.equals("grpc-status-details-bin") ? "google.rpc.Status" : null;
                ProtoMessage m = Protobuf.decode(bytes, schema, type);
                return ProtoText.mapping(m);
            } catch (DecodeException e) {
                return null;
            }
        }
        return null;
    }
}
