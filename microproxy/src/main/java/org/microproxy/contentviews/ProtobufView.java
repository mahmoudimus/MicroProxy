/*
 * Ported from mitmproxy_rs (https://github.com/mitmproxy/mitmproxy_rs),
 * mitmproxy-contentviews/src/protobuf/view_protobuf.rs: the content types, and decoding with a
 * schema type when one is known, falling back to decoding without it. Copyright (c) 2022, Fabio
 * Valentini and Maximilian Hils. Licensed under the MIT License; see
 * META-INF/LICENSE-mitmproxy_rs.txt.
 */
package org.microproxy.contentviews;

import java.util.Set;

/**
 * Protobuf bodies, as YAML with field numbers (see {@link ProtoText}). The message type comes from
 * the schema: a {@code messageType} (or {@code proto}, {@code type}) parameter of the {@code
 * Content-Type}, or the request path of a gRPC-style call ({@code /pkg.Service/Method}).
 */
final class ProtobufView implements ContentView {

    private static final Set<String> TYPES = Set.of(
            "application/x-protobuf", "application/x-protobuffer", "application/protobuf",
            "application/vnd.google.protobuf", "application/x-google-protobuf", "application/proto");

    private final ProtoSchema schema;

    ProtobufView(ProtoSchema schema) {
        this.schema = schema;
    }

    @Override
    public String name() {
        return "protobuf";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        return TYPES.contains(metadata.mediaType()) ? 1 : 0;
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        String named = metadata.parameter("messageType");
        if (named == null) named = metadata.parameter("proto");
        if (named == null) named = metadata.parameter("type");
        ProtoSchema.MessageType type = named != null ? schema.message(named).orElse(null) : null;
        if (type == null) type = schema.messageFor(metadata.path(), metadata.request()).orElse(null);
        return render(schema, data, type);
    }

    /** {@code data} decoded as {@code type} (or without a type) and rendered. */
    static String render(ProtoSchema schema, byte[] data, ProtoSchema.MessageType type) throws DecodeException {
        return Protobuf.decode(data, schema, type == null ? null : type.fullName()).render();
    }
}
