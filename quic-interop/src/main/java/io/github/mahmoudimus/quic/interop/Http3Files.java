package io.github.mahmoudimus.quic.interop;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3Frame;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import io.github.mahmoudimus.http3.RequestHeaders;
import io.github.mahmoudimus.http3.ResponseHeaders;
import io.github.mahmoudimus.quic.QuicConnection;
import io.github.mahmoudimus.quic.QuicStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Small static-QPACK HTTP/3 file application, using the repository's native codec. */
final class Http3Files {
    private Http3Files() {}

    static void control(QuicConnection connection) throws IOException {
        QuicStream control = connection.openUnidirectionalStream();
        Http3FrameWriter writer = new Http3FrameWriter(control.getOutputStream());
        writer.writeStreamType(Http3StreamType.CONTROL);
        writer.writeSettings(Http3Settings.builder().qpackMaxTableCapacity(0).qpackBlockedStreams(0).build());
        writer.flush();
        // A control stream must stay open until its connection closes.
    }

    static void drain(QuicStream stream) throws IOException {
        if (stream.isBidirectional()) throw new IOException("unsolicited bidirectional stream");
        InputStream input = stream.getInputStream();
        new Http3FrameReader(input).readStreamType();
        input.transferTo(OutputStream.nullOutputStream());
    }

    static void serve(QuicStream stream, Path root) throws IOException {
        Http3FrameReader reader = new Http3FrameReader(stream.getInputStream());
        reader.setMaxFramePayloadSize(EndpointFiles.MAX_REQUEST_LINE);
        RequestHeaders request = null;
        for (Http3Frame frame; (frame = reader.readFrame()) != null;) {
            if (frame instanceof Http3Frame.Headers headers) {
                if (request != null) throw new IOException("unexpected request trailers");
                request = Http3Headers.toRequest(stream.id(), new QpackDecoder(0, 0).decode(stream.id(), headers.fieldSection()));
            } else if (frame instanceof Http3Frame.Data data && data.data().length != 0) {
                throw new IOException("GET request has a body");
            }
        }
        if (request == null || !request.method().equals("GET") || !request.scheme().equals("https")
                || request.contentLength() > 0) throw new IOException("expected HTTP/3 GET request");
        Path file;
        try {
            file = EndpointFiles.source(root, request.path());
        } catch (IOException e) {
            try (OutputStream output = stream.getOutputStream()) {
                headers(new Http3FrameWriter(output), stream.id(), "404", 0);
            }
            return;
        }
        try (InputStream input = Files.newInputStream(file); OutputStream output = stream.getOutputStream()) {
            Http3FrameWriter writer = new Http3FrameWriter(output);
            headers(writer, stream.id(), "200", Files.size(file));
            byte[] bytes = new byte[64 * 1024];
            for (int n; (n = input.read(bytes)) >= 0;) writer.writeData(bytes, 0, n);
            writer.flush();
        }
    }

    private static void headers(Http3FrameWriter writer, long stream, String status, long size) throws IOException {
        writer.writeHeaders(new QpackEncoder().encode(stream, List.of(new HeaderField(":status", status),
                new HeaderField("content-length", Long.toString(size)), new HeaderField("server", "microproxy-quic"))));
        writer.flush();
    }

    static void fetch(QuicStream stream, InteropEndpoint.Request request, OutputStream body) throws IOException {
        try (OutputStream output = stream.getOutputStream()) {
            Http3FrameWriter writer = new Http3FrameWriter(output);
            writer.writeHeaders(new QpackEncoder().encode(stream.id(), List.of(new HeaderField(":method", "GET"),
                    new HeaderField(":scheme", "https"), new HeaderField(":authority", request.uri().getRawAuthority()),
                    new HeaderField(":path", request.path()))));
            writer.flush();
        }
        Http3FrameReader reader = new Http3FrameReader(stream.getInputStream());
        reader.setMaxFramePayloadSize(16 * 1024 * 1024);
        ResponseHeaders response = null;
        long received = 0;
        for (Http3Frame frame; (frame = reader.readFrame()) != null;) {
            if (frame instanceof Http3Frame.Headers headers) {
                var fields = new QpackDecoder(0, 0).decode(stream.id(), headers.fieldSection());
                if (response == null) {
                    ResponseHeaders candidate = Http3Headers.toResponse(stream.id(), fields);
                    if (!candidate.isInformational()) {
                        if (candidate.status() != 200) throw new IOException("HTTP/3 status " + candidate.status());
                        response = candidate;
                    }
                } else {
                    Http3Headers.validateTrailers(stream.id(), fields);
                }
            } else if (frame instanceof Http3Frame.Data data) {
                if (response == null) throw new IOException("DATA before response HEADERS");
                received += data.data().length;
                Http3Headers.checkContentLength(stream.id(), response.contentLength(), received, false);
                body.write(data.data());
            }
        }
        if (response == null) throw new IOException("HTTP/3 stream ended without a response");
        Http3Headers.checkContentLength(stream.id(), response.contentLength(), received, true);
    }
}
