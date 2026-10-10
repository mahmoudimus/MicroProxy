package org.microproxy.starlark;

import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.FrameReader;
import io.github.mahmoudimus.http2.FrameWriter;
import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.HpackDecoder;
import io.github.mahmoudimus.http2.HpackEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A small HTTP/2 client with prior knowledge ({@code h2c}) for script tests, on the codec: it
 * writes the frames a test wants and collects one stream's response, extension frames included.
 */
public final class RawH2 implements AutoCloseable {

    /** One stream's response. */
    public record Response(List<HeaderField> headers, String body, List<HeaderField> trailers, List<Frame.Unknown> extensions) {
        public String header(String name) {
            for (HeaderField f : headers) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }

        public String trailer(String name) {
            for (HeaderField f : trailers) {
                if (f.name().equals(name)) return f.value();
            }
            return null;
        }
    }

    private final Socket socket;
    private final String authority;
    final FrameReader reader;
    final FrameWriter writer;
    private final HpackEncoder encoder = new HpackEncoder();
    private final HpackDecoder decoder = new HpackDecoder();

    /**
     * Connects to the proxy's plain listener and sends the preface.
     *
     * @param proxy the proxy
     * @param authority the {@code :authority} of requests
     */
    public RawH2(InetSocketAddress proxy, String authority) throws IOException {
        this.socket = new Socket(proxy.getAddress(), proxy.getPort());
        socket.setSoTimeout(10_000);
        this.authority = authority;
        this.reader = new FrameReader(new BufferedInputStream(socket.getInputStream()));
        reader.setDeliverUnknownFrames(true);
        this.writer = new FrameWriter(new BufferedOutputStream(socket.getOutputStream()));
        writer.writeClientPreface();
        writer.writeSettings(Map.of());
        writer.flush();
    }

    /** Sends a request on {@code stream}: its head (with {@code extra} name, value pairs) and, if not null, its body. */
    public void request(int stream, String method, String path, String body, String... extra) throws IOException {
        List<HeaderField> fields = new ArrayList<>(List.of(new HeaderField(":method", method), new HeaderField(":scheme", "http"),
                new HeaderField(":authority", authority), new HeaderField(":path", path)));
        for (int i = 0; i < extra.length; i += 2) fields.add(new HeaderField(extra[i], extra[i + 1]));
        writer.writeHeaders(stream, encoder.encode(fields), body == null);
        if (body != null) {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            writer.writeData(stream, b, 0, b.length, true);
        }
        writer.flush();
    }

    public void frame(Frame frame) throws IOException {
        writer.writeFrame(frame);
        writer.flush();
    }

    /** Reads until {@code stream} ends, acknowledging SETTINGS. */
    public Response response(int stream) throws IOException {
        List<HeaderField> headers = null;
        List<HeaderField> trailers = List.of();
        List<Frame.Unknown> extensions = new ArrayList<>();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            Frame f = reader.readFrame();
            if (f == null) throw new IOException("connection closed");
            switch (f) {
                case Frame.Settings s when !s.ack() -> {
                    writer.writeSettingsAck();
                    writer.flush();
                }
                case Frame.Unknown u -> extensions.add(u);
                case Frame.Headers h -> {
                    List<HeaderField> fields = decoder.decode(h.streamId(), h.fieldBlock());
                    if (h.streamId() != stream) continue;
                    if (headers == null) {
                        headers = fields;
                    } else {
                        trailers = fields;
                    }
                    if (h.endStream()) return new Response(headers, body.toString(StandardCharsets.UTF_8), trailers, extensions);
                }
                case Frame.Data d when d.streamId() == stream -> {
                    body.write(d.data());
                    if (d.endStream()) return new Response(headers, body.toString(StandardCharsets.UTF_8), trailers, extensions);
                }
                case Frame.RstStream r when r.streamId() == stream -> throw new IOException("stream reset: " + r.error());
                default -> {}
            }
        }
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
