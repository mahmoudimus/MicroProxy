package org.microproxy.http;

import io.github.mahmoudimus.zstd.ZstdInputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.microproxy.thirdparty.brotli.BrotliInputStream;

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
 * bundled copy of Google's pure-Java Brotli decoder) can be decoded, and so can {@code zstd} when
 * the optional {@code zstd-decoder} module is on the class path. Others, such as dictionary
 * codings ({@code dcb}, {@code dcz}), are reported by {@link #canDecode}, and {@link
 * #restrictAcceptEncoding} keeps servers from choosing them. Decoding is capped (64 MiB by
 * default) to defuse compression bombs. Rewriting a body re-applies the original coding (Brotli
 * and zstd bodies are re-encoded as gzip, since there are no pure-Java encoders for them) and
 * drops validators ({@code ETag}, {@code Content-MD5}) that no longer match; {@code
 * Content-Length} is fixed when the message is written.
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
    private static final Set<String> DECODE_ONLY = Set.of("br", "zstd");

    private HttpBodies() {}

    /** The content codings applied to {@code message}, outermost last ({@code identity} omitted). */
    public static List<String> contentEncodings(HttpMessage message) {
        return message.headers().getAllElements(HttpHeaderNames.CONTENT_ENCODING).stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .filter(s -> !s.equals("identity"))
                .toList();
    }

    /** Whether every content coding of {@code message} can be decoded. */
    public static boolean canDecode(HttpMessage message) {
        for (String coding : contentEncodings(message)) {
            if (!DECODABLE.contains(coding)) {
                return false;
            }
        }
        return true;
    }

    /** The body with all content codings removed. */
    public static byte[] decoded(FullHttpMessage message) throws IOException {
        return decoded(message, DEFAULT_MAX_DECODED_BYTES);
    }

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
     */
    public static byte[] decodedPrefix(FullHttpMessage message, int maxBytes) throws IOException {
        List<String> codings = contentEncodings(message);
        List<Inflater> inflaters = new ArrayList<>(1);
        InputStream in = new ByteArrayInputStream(message.content());
        try {
            for (int i = codings.size() - 1; i >= 0; i--) {
                in = decoding(codings.get(i), in, inflaters);
            }
            try (InputStream decoded = in) {
                return decoded.readNBytes(Math.max(0, maxBytes));
            }
        } catch (RuntimeException e) {
            // The Brotli decoder reports corrupt data unchecked.
            throw new IOException("corrupt " + String.join(", ", codings) + " data", e);
        } finally {
            inflaters.forEach(Inflater::end);
        }
    }

    /** A stream that removes {@code coding} from {@code in}. */
    private static InputStream decoding(String coding, InputStream in, List<Inflater> inflaters) throws IOException {
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
            case "br" -> new BrotliInputStream(in);
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
     */
    public static void setDecoded(FullHttpMessage message, byte[] decodedBody) throws IOException {
        List<String> codings = contentEncodings(message);
        if (codings.stream().anyMatch(DECODE_ONLY::contains)) {
            // There is no encoder for these; gzip is understood by every client that sends them.
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

    /** Decodes the body and removes {@code Content-Encoding}, so later filters see plain bytes. */
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

    /** The decoded body as text, in the message's charset (UTF-8 when none is declared). */
    public static String text(FullHttpMessage message) throws IOException {
        return new String(decoded(message), charset(message, StandardCharsets.UTF_8));
    }

    /** Replaces the body with {@code text} in the message's charset (UTF-8 when none is declared). */
    public static void setText(FullHttpMessage message, String text) throws IOException {
        setDecoded(message, text.getBytes(charset(message, StandardCharsets.UTF_8)));
    }

    /**
     * The {@code charset} parameter of {@code Content-Type}, or {@code fallback} when absent,
     * unknown or malformed.
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

    /** The media type of {@code Content-Type} in lower case, without parameters, or "". */
    public static String mediaType(HttpMessage message) {
        String contentType = message.headers().get(HttpHeaderNames.CONTENT_TYPE);
        if (contentType == null) return "";
        int semi = contentType.indexOf(';');
        return (semi >= 0 ? contentType.substring(0, semi) : contentType).strip().toLowerCase(Locale.ROOT);
    }

    /** Whether the media type is textual: {@code text/*}, JSON, XML, JavaScript or form data. */
    public static boolean isText(HttpMessage message) {
        String type = mediaType(message);
        return type.startsWith("text/") || type.endsWith("+json") || type.endsWith("+xml")
                || type.equals("application/json") || type.equals("application/xml")
                || type.equals("application/javascript") || type.equals("application/ecmascript")
                || type.equals("application/x-www-form-urlencoded");
    }

    private static byte[] decode(String coding, byte[] data, int max) throws IOException {
        return switch (coding) {
            case "gzip", "x-gzip" -> readCapped(new GZIPInputStream(new ByteArrayInputStream(data)), max);
            case "deflate" -> inflate(data, max);
            case "br" -> {
                try {
                    yield readCapped(new BrotliInputStream(new ByteArrayInputStream(data)), max);
                } catch (RuntimeException e) {
                    throw new IOException("corrupt brotli data", e);
                }
            }
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

    private static byte[] encode(String coding, byte[] data) throws IOException {
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
