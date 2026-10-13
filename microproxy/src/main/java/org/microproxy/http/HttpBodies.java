package org.microproxy.http;

import io.github.mahmoudimus.zstd.ZstdInputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.microproxy.thirdparty.jaybrotli.BrotliContentHandler;
import org.microproxy.thirdparty.jaybrotli.BrotliException;
import org.microproxy.thirdparty.jaybrotli.Decoder;
import org.microproxy.thirdparty.jaybrotli.Encoder;
import org.microproxy.thirdparty.jaybrotli.LimitExceededException;
import org.microproxy.thirdparty.jaybrotli.config.DecoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.EncoderOptions;
import org.microproxy.thirdparty.jaybrotli.config.Limits;
import org.microproxy.thirdparty.jaybrotli.config.TrailingData;

/**
 * Reads and rewrites the bodies of buffered messages ({@link FullHttpMessage}) in filters,
 * taking care of {@code Content-Encoding} and charsets so filters don't have to.
 *
 * <pre>{@code
 * if (o instanceof FullHttpResponse res && HttpBodies.isText(res) && HttpBodies.canDecode(res)) {
 *     String html = HttpBodies.text(res);
 *     HttpBodies.setText(res, html.replace("</body>", "<script src=/x.js></script></body>"));
 * }
 * }</pre>
 *
 * <p>{@code gzip}, {@code x-gzip}, {@code deflate} (zlib-wrapped or raw) and {@code br} (with a
 * bundled copy of the pure-Java Brotli codec jaybrotli) can be decoded, and so can {@code zstd}
 * when the optional {@code zstd-decoder} module is on the class path. Others, such as dictionary
 * codings ({@code dcb}, {@code dcz}), are reported by {@link #canDecode}, and {@link
 * #restrictAcceptEncoding} keeps servers from choosing them. Decoding is capped (64 MiB by
 * default) to defuse compression bombs. Rewriting a body re-applies the original coding (Brotli
 * at quality {@value #BROTLI_QUALITY}; zstd bodies are re-encoded as gzip, since there is no
 * pure-Java zstd encoder) and drops validators ({@code ETag}, {@code Content-MD5}) that no longer
 * match; {@code Content-Length} is fixed when the message is written.
 */
public final class HttpBodies {

    /** Default cap on decoded body size. */
    public static final int DEFAULT_MAX_DECODED_BYTES = 64 << 20;

    /**
     * Content codings this class can decode: {@code gzip}, {@code x-gzip}, {@code deflate} and
     * {@code br}, plus {@code zstd} when the {@code zstd-decoder} module is on the class path.
     */
    public static final Set<String> DECODABLE = ZstdSupport.AVAILABLE
            ? Set.of("gzip", "x-gzip", "deflate", "br", "zstd")
            : Set.of("gzip", "x-gzip", "deflate", "br");

    /** Codings that can be decoded but not produced; rewritten bodies use gzip instead. */
    private static final Set<String> DECODE_ONLY = Set.of("zstd");

    /**
     * The Brotli quality (0 to 11) that {@link #encode} and rewritten {@code br} bodies use, with
     * jaybrotli's default strategies: on HTML and JSON of 10 KB to 1 MB it runs at about 10 to 35
     * MB/s, and its output is mostly 1 to 14% smaller than gzip's default level (at worst 2%
     * larger). Qualities 4 and 6 come out within 1% of it; the higher qualities and the
     * alternative strategies trade too much speed for what they save.
     */
    public static final int BROTLI_QUALITY = 5;

    private HttpBodies() {}

    /**
     * The content codings applied to {@code message}, outermost last ({@code identity} omitted).
     *
     * @param message the message whose body and headers are inspected
     * @return the lower-case content codings in application order, excluding identity
     */
    public static List<String> contentEncodings(HttpMessage message) {
        return message.headers().getAllElements(HttpHeaderNames.CONTENT_ENCODING).stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .filter(s -> !s.equals("identity"))
                .toList();
    }

    /**
     * Whether every content coding of {@code message} can be decoded.
     *
     * @param message the message whose body and headers are inspected
     * @return whether all declared content codings are supported
     */
    public static boolean canDecode(HttpMessage message) {
        for (String coding : contentEncodings(message)) {
            if (!DECODABLE.contains(coding)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The body with all content codings removed.
     *
     * @param message the message whose body and headers are inspected
     * @return the body bytes after all content codings are removed
     * @throws IOException if a coding is unsupported, corrupt, or exceeds the default decoding limit
     */
    public static byte[] decoded(FullHttpMessage message) throws IOException {
        return decoded(message, DEFAULT_MAX_DECODED_BYTES);
    }

    /**
     * Removes all content codings with a limit on each decompression stage.
     *
     * @param message the message whose body and headers are inspected
     * @param maxDecodedBytes the maximum output size in bytes for each decompression stage
     * @return the body bytes after all content codings are removed
     * @throws IOException if a coding is unsupported, corrupt, or exceeds the decoding limit
     */
    public static byte[] decoded(FullHttpMessage message, int maxDecodedBytes) throws IOException {
        byte[] data = message.content();
        List<String> codings = contentEncodings(message);
        for (int i = codings.size() - 1; i >= 0; i--) {
            data = decode(codings.get(i), data, maxDecodedBytes);
        }
        return data;
    }

    /**
     * The first {@code maxBytes} of the body with all content codings removed, for previews and
     * logs: unlike {@link #decoded(FullHttpMessage, int)}, a longer decoded body is cut short
     * rather than an error, and only that much is ever decoded.
     *
     * @param message the message whose body and headers are inspected
     * @param maxBytes the maximum prefix length; nonpositive values produce an empty result
     * @return up to maxBytes decoded body bytes
     * @throws IOException if a coding is unsupported or the decoded prefix cannot be read
     */
    public static byte[] decodedPrefix(FullHttpMessage message, int maxBytes) throws IOException {
        List<String> codings = contentEncodings(message);
        List<Inflater> inflaters = new ArrayList<>(1);
        InputStream in = new ByteArrayInputStream(message.content());
        try {
            for (int i = codings.size() - 1; i >= 0; i--) {
                // The last stage needs only maxBytes; one below it, as much as decoded() allows.
                in = decoding(codings.get(i), in, inflaters, i == 0 ? Math.max(0, maxBytes) : DEFAULT_MAX_DECODED_BYTES);
            }
            try (InputStream decoded = in) {
                return decoded.readNBytes(Math.max(0, maxBytes));
            }
        } catch (RuntimeException e) {
            // Decoders can report corrupt data unchecked.
            throw new IOException("corrupt " + String.join(", ", codings) + " data", e);
        } finally {
            inflaters.forEach(Inflater::end);
        }
    }

    /**
     * A stream that removes {@code coding} from {@code in}. Brotli decoding stops once {@code
     * needed} bytes are out (the decoder is pushed input rather than pulled for output, so this is
     * what keeps a prefix of a compression bomb cheap).
     */
    private static InputStream decoding(String coding, InputStream in, List<Inflater> inflaters, int needed)
            throws IOException {
        return switch (coding) {
            case "gzip", "x-gzip" -> new GZIPInputStream(in);
            case "deflate" -> {
                BufferedInputStream buffered = new BufferedInputStream(in);
                buffered.mark(2);
                byte[] head = buffered.readNBytes(2);
                buffered.reset();
                boolean zlib = head.length == 2 && (head[0] & 0x0f) == 8
                        && (((head[0] & 0xff) << 8) | (head[1] & 0xff)) % 31 == 0;
                Inflater inflater = new Inflater(!zlib);
                inflaters.add(inflater);
                yield new InflaterInputStream(buffered, inflater);
            }
            case "br" -> BrotliCoding.decoding(in, needed);
            case "zstd" -> {
                if (!ZstdSupport.AVAILABLE) throw new IOException("unsupported content coding: zstd");
                yield ZstdSupport.open(in);
            }
            default -> throw new IOException("unsupported content coding: " + coding);
        };
    }

    /**
     * Replaces the body with {@code decodedBody}, re-applying the message's content codings, and
     * removes validators that described the old body.
     *
     * @param message the message to update
     * @param decodedBody the replacement bytes before applying content codings
     * @throws IOException if a content coding is unsupported or encoding fails
     */
    public static void setDecoded(FullHttpMessage message, byte[] decodedBody) throws IOException {
        List<String> codings = contentEncodings(message);
        if (codings.stream().anyMatch(DECODE_ONLY::contains)) {
            // There is no encoder for zstd; gzip is understood by every client that accepts it.
            codings = codings.stream().map(c -> DECODE_ONLY.contains(c) ? "gzip" : c).toList();
            message.headers().set(HttpHeaderNames.CONTENT_ENCODING, String.join(", ", codings));
        }
        byte[] data = decodedBody;
        for (String coding : codings) {
            data = encode(coding, data);
        }
        message.setContent(data);
        message.headers().remove("ETag");
        message.headers().remove("Content-MD5");
        message.headers().remove("Digest");
    }

    /**
     * Decodes the body and removes {@code Content-Encoding}, so later filters see plain bytes.
     *
     * @param message the message to decode and update
     * @throws IOException if a coding is unsupported, corrupt, or exceeds the default decoding limit
     */
    public static void removeContentEncoding(FullHttpMessage message) throws IOException {
        byte[] plain = decoded(message);
        message.headers().remove(HttpHeaderNames.CONTENT_ENCODING);
        message.setContent(plain);
        message.headers().remove("ETag");
        message.headers().remove("Content-MD5");
        message.headers().remove("Digest");
    }

    /**
     * Removes content codings this class cannot decode (e.g. {@code dcb}) from the request's
     * {@code Accept-Encoding}, keeping quality values, so the server picks one that filters can
     * read. Leaves {@code identity} when nothing else remains.
     *
     * @param request the request whose accepted codings are restricted
     */
    public static void restrictAcceptEncoding(HttpRequest request) {
        List<String> offered = request.headers().getAllElements(HttpHeaderNames.ACCEPT_ENCODING);
        if (offered.isEmpty()) return;
        List<String> kept = new ArrayList<>();
        for (String element : offered) {
            int semi = element.indexOf(';');
            String coding = (semi >= 0 ? element.substring(0, semi) : element).strip().toLowerCase(Locale.ROOT);
            if (DECODABLE.contains(coding) || coding.equals("identity")) {
                kept.add(element);
            }
        }
        request.headers().set(HttpHeaderNames.ACCEPT_ENCODING, kept.isEmpty() ? "identity" : String.join(", ", kept));
    }

    /**
     * The decoded body as text, in the message's charset (UTF-8 when none is declared).
     *
     * @param message the message whose body and headers are inspected
     * @return the decoded body interpreted in the declared charset, or UTF-8 by default
     * @throws IOException if a coding is unsupported, corrupt, or exceeds the default decoding limit
     */
    public static String text(FullHttpMessage message) throws IOException {
        return new String(decoded(message), charset(message, StandardCharsets.UTF_8));
    }

    /**
     * Replaces the body with {@code text} in the message's charset (UTF-8 when none is declared).
     *
     * @param message the message to update
     * @param text the replacement text before charset encoding and content coding
     * @throws IOException if a content coding is unsupported or encoding fails
     */
    public static void setText(FullHttpMessage message, String text) throws IOException {
        setDecoded(message, text.getBytes(charset(message, StandardCharsets.UTF_8)));
    }

    /**
     * The {@code charset} parameter of {@code Content-Type}, or {@code fallback} when absent,
     * unknown or malformed.
     *
     * @param message the message whose Content-Type is inspected
     * @param fallback the charset to use when the parameter cannot be resolved
     * @return the declared charset, or fallback if unavailable
     */
    public static Charset charset(HttpMessage message, Charset fallback) {
        String contentType = message.headers().get(HttpHeaderNames.CONTENT_TYPE);
        if (contentType == null) return fallback;
        for (String param : contentType.split(";")) {
            int eq = param.indexOf('=');
            if (eq < 0 || !param.substring(0, eq).strip().equalsIgnoreCase("charset")) continue;
            String value = param.substring(eq + 1).strip();
            if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }
            return Charset.forName(value, fallback);
        }
        return fallback;
    }

    /**
     * The media type of {@code Content-Type} in lower case, without parameters, or "".
     *
     * @param message the message whose Content-Type is inspected
     * @return the lower-case media type without parameters, or an empty string if absent
     */
    public static String mediaType(HttpMessage message) {
        String contentType = message.headers().get(HttpHeaderNames.CONTENT_TYPE);
        if (contentType == null) return "";
        int semi = contentType.indexOf(';');
        return (semi >= 0 ? contentType.substring(0, semi) : contentType).strip().toLowerCase(Locale.ROOT);
    }

    /**
     * Whether the media type is textual: {@code text/*}, JSON, XML, JavaScript or form data.
     *
     * @param message the message whose media type is inspected
     * @return whether the media type is recognized as textual
     */
    public static boolean isText(HttpMessage message) {
        String type = mediaType(message);
        return type.startsWith("text/") || type.endsWith("+json") || type.endsWith("+xml")
                || type.equals("application/json") || type.equals("application/xml")
                || type.equals("application/javascript") || type.equals("application/ecmascript")
                || type.equals("application/x-www-form-urlencoded");
    }

    /**
     * Removes one content coding from {@code data}, as {@link #decoded(FullHttpMessage, int)} does
     * for each coding of a message. Also used for gRPC messages, which are compressed one by one
     * with the coding their {@code grpc-encoding} names.
     *
     * @param coding the coding, in lower case: {@code gzip}, {@code x-gzip}, {@code deflate}
     *     (zlib-wrapped or raw), {@code br}, or {@code zstd} when the module is present
     * @param data the encoded bytes
     * @param max the maximum decoded size in bytes
     * @return the decoded bytes
     * @throws IOException if the coding is unsupported, the data corrupt, or the result larger
     *     than {@code max}
     */
    public static byte[] decode(String coding, byte[] data, int max) throws IOException {
        return switch (coding) {
            case "gzip", "x-gzip" -> readCapped(new GZIPInputStream(new ByteArrayInputStream(data)), max);
            case "deflate" -> inflate(data, max);
            case "br" -> BrotliCoding.decode(data, max);
            case "zstd" -> {
                if (!ZstdSupport.AVAILABLE) throw new IOException("unsupported content coding: zstd");
                yield readCapped(ZstdSupport.open(new ByteArrayInputStream(data)), max);
            }
            default -> throw new IOException("unsupported content coding: " + coding);
        };
    }

    /**
     * The optional zstd-decoder module. Kept in its own class so that {@code HttpBodies} loads
     * (and decodes everything else) when the module is absent.
     */
    private static final class ZstdSupport {
        static final boolean AVAILABLE = present();

        private static boolean present() {
            try {
                Class.forName("io.github.mahmoudimus.zstd.ZstdInputStream", false, HttpBodies.class.getClassLoader());
                return true;
            } catch (ClassNotFoundException | LinkageError e) {
                return false;
            }
        }

        static InputStream open(InputStream in) {
            return Decoder.open(in);
        }

        /** Only loaded once the module is known to be present. */
        private static final class Decoder {
            static InputStream open(InputStream in) {
                return new ZstdInputStream(in);
            }
        }
    }

    /** "deflate" is meant to be zlib-wrapped, but some servers send raw DEFLATE; accept both. */
    private static byte[] inflate(byte[] data, int max) throws IOException {
        boolean zlib = data.length >= 2 && (data[0] & 0x0f) == 8 && (((data[0] & 0xff) << 8) | (data[1] & 0xff)) % 31 == 0;
        // InflaterInputStream only ends inflaters it created, so release the native memory here.
        Inflater inflater = new Inflater(!zlib);
        try {
            return readCapped(new InflaterInputStream(new ByteArrayInputStream(data), inflater), max);
        } finally {
            inflater.end();
        }
    }

    /**
     * Applies one content coding to {@code data}: {@code gzip} (or {@code x-gzip}), {@code
     * deflate} (zlib-wrapped) or {@code br} (at {@link #BROTLI_QUALITY}), the codings this class
     * can produce.
     *
     * @param coding the coding, in lower case
     * @param data the bytes to encode
     * @return the encoded bytes
     * @throws IOException if the coding is not one of those
     */
    public static byte[] encode(String coding, byte[] data) throws IOException {
        if (coding.equals("br")) return BrotliCoding.encode(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length / 2));
        OutputStream encoder = switch (coding) {
            case "gzip", "x-gzip" -> new GZIPOutputStream(out);
            case "deflate" -> new DeflaterOutputStream(out);
            default -> throw new IOException("unsupported content coding: " + coding);
        };
        try (encoder) {
            encoder.write(data);
        }
        return out.toByteArray();
    }

    /** {@code br}, with the vendored jaybrotli codec. */
    private static final class BrotliCoding {

        /** Thrown by a content callback to stop decoding once enough is out. */
        private static final class Enough extends RuntimeException {
            Enough() {
                super(null, null, false, false);
            }
        }

        private BrotliCoding() {}

        /**
         * A decoder for one RFC 7932 stream (no large-window extension, so at most a 16 MiB
         * window) whose output may total {@code max} bytes; the decoder checks that limit before it
         * writes anything, so a compression bomb stops there. Like the reference decoder, it
         * rejects commands that run past the end of their meta-block and any byte after the end of
         * the stream (or non-zero bits padding its last byte), so a body's end is never ambiguous.
         */
        private static Decoder decoder(long max, BrotliContentHandler content) {
            DecoderOptions options = DecoderOptions.defaults()
                    .withLimits(Limits.defaults().withMaxTotalOutput(max))
                    .withTrailingData(TrailingData.REJECT);
            return new Decoder(options).onContent(content);
        }

        static byte[] decode(byte[] data, int max) throws IOException {
            int cap = Math.max(0, max);
            Output out = new Output(Math.min(cap, Math.max(64, data.length * 4)));
            Decoder decoder = decoder(cap, (b, last) -> out.append(b));
            try {
                decoder.receive(ByteBuffer.wrap(data));
                decoder.close();
            } catch (LimitExceededException e) {
                throw new IOException("decoded body exceeds " + max + " bytes", e);
            } catch (BrotliException | RuntimeException e) {
                throw new IOException("corrupt brotli data", e);
            } finally {
                decoder.abort();
            }
            return out.toByteArray();
        }

        /** A growable byte array, without {@link ByteArrayOutputStream}'s locking. */
        private static final class Output {
            byte[] bytes;
            int size;

            Output(int initial) {
                bytes = new byte[Math.max(16, initial)];
            }

            void append(ByteBuffer b) {
                int n = b.remaining();
                if (n > bytes.length - size) {
                    bytes = Arrays.copyOf(bytes, (int) Math.min(Integer.MAX_VALUE - 8, Math.max(2L * bytes.length, (long) size + n)));
                }
                b.get(bytes, size, n);
                size += n;
            }

            byte[] toByteArray() {
                return Arrays.copyOf(bytes, size);
            }
        }

        /**
         * A stream of the first {@code needed} decoded bytes of {@code in}: decoding stops there,
         * and the stream ends. Shorter output is read to the end of {@code in}, so a truncated
         * stream or bytes after its end are still an error.
         */
        static InputStream decoding(InputStream in, int needed) {
            return new InputStream() {
                private final byte[] chunk = new byte[8192];
                private final ArrayDeque<ByteBuffer> queue = new ArrayDeque<>();
                private long produced;
                private boolean done;
                // Output is capped here, exactly at needed bytes, rather than by the decoder's limit.
                private final Decoder decoder = decoder(Long.MAX_VALUE, (b, last) -> {
                    int n = (int) Math.min(b.remaining(), needed - produced);
                    if (n > 0) {
                        byte[] copy = new byte[n];
                        b.get(copy);
                        queue.add(ByteBuffer.wrap(copy));
                        produced += n;
                    }
                    if (produced >= needed) throw new Enough();
                });

                @Override
                public int read() throws IOException {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    Objects.checkFromIndexSize(off, len, b.length);
                    if (len == 0) return 0;
                    while (queue.isEmpty() && !done) fill();
                    ByteBuffer head = queue.peek();
                    if (head == null) return -1;
                    int n = Math.min(len, head.remaining());
                    head.get(b, off, n);
                    if (!head.hasRemaining()) queue.remove();
                    return n;
                }

                private void fill() throws IOException {
                    int n = in.read(chunk);
                    try {
                        if (n < 0) {
                            done = true;
                            decoder.close();
                        } else if (n == 0) {
                            throw new IOException("compressed input made no progress");
                        } else {
                            decoder.receive(ByteBuffer.wrap(chunk, 0, n));
                        }
                    } catch (Enough e) {
                        done = true;
                    } catch (BrotliException | RuntimeException e) {
                        done = true;
                        throw new IOException("corrupt brotli data", e);
                    }
                }

                @Override
                public void close() throws IOException {
                    done = true;
                    queue.clear();
                    decoder.abort();
                    in.close();
                }
            };
        }

        static byte[] encode(byte[] data) throws IOException {
            Output out = new Output(Math.max(64, data.length / 4));
            EncoderOptions options = EncoderOptions.defaults()
                    .withQuality(BROTLI_QUALITY)
                    .withWindowBits(windowBits(data.length));
            Encoder encoder = new Encoder(options).onCompressed(out::append);
            try {
                encoder.receive(ByteBuffer.wrap(data));
                encoder.close();
            } catch (BrotliException | RuntimeException e) {
                throw new IOException("cannot encode brotli data", e);
            }
            return out.toByteArray();
        }

        /**
         * The smallest window (10 to 22 bits, the latter what reference encoders use by default)
         * that spans {@code length} bytes: a smaller window costs the client's decoder less memory.
         */
        static int windowBits(int length) {
            int bits = 10;
            while (bits < 22 && (1 << bits) - 16 < length) bits++;
            return bits;
        }
    }

    private static byte[] readCapped(InputStream in, int max) throws IOException {
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (out.size() + n > max) {
                    throw new IOException("decoded body exceeds " + max + " bytes");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }
}
