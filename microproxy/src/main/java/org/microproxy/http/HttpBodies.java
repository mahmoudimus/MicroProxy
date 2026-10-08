package org.microproxy.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.List;
import java.util.Locale;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

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
 * bundled copy of Google's pure-Java Brotli decoder) can be decoded; others, such as {@code zstd},
 * are reported by {@link #canDecode}, and {@link #restrictAcceptEncoding} keeps servers from
 * choosing them. Decoding is capped (64 MiB by default) to defuse compression bombs. Rewriting a
 * body re-applies the original coding (a Brotli body is re-encoded as gzip, since there is no
 * pure-Java Brotli encoder) and drops validators ({@code ETag}, {@code Content-MD5}) that no
 * longer match; {@code Content-Length} is fixed when the message is written.
 */
public final class HttpBodies {

    /** Default cap on decoded body size. */
    public static final int DEFAULT_MAX_DECODED_BYTES = 64 << 20;

    /** Content codings this class can decode. */
    public static final java.util.Set<String> DECODABLE = java.util.Set.of("gzip", "x-gzip", "deflate", "br");

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
     * Replaces the body with {@code decodedBody}, re-applying the message's content codings, and
     * removes validators that described the old body.
     */
    public static void setDecoded(FullHttpMessage message, byte[] decodedBody) throws IOException {
        List<String> codings = contentEncodings(message);
        if (codings.contains("br")) {
            // No pure-Java Brotli encoder exists; gzip is understood by every client that sends br.
            codings = codings.stream().map(c -> c.equals("br") ? "gzip" : c).toList();
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
     * Removes content codings this class cannot decode (e.g. {@code zstd}) from the request's
     * {@code Accept-Encoding}, keeping quality values, so the server picks one that filters can
     * read. Leaves {@code identity} when nothing else remains.
     */
    public static void restrictAcceptEncoding(HttpRequest request) {
        List<String> offered = request.headers().getAllElements(HttpHeaderNames.ACCEPT_ENCODING);
        if (offered.isEmpty()) return;
        List<String> kept = new java.util.ArrayList<>();
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
            try {
                return Charset.forName(value);
            } catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
                return fallback;
            }
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
                    yield readCapped(new org.microproxy.thirdparty.brotli.BrotliInputStream(new ByteArrayInputStream(data)), max);
                } catch (RuntimeException e) {
                    throw new IOException("corrupt brotli data", e);
                }
            }
            default -> throw new IOException("unsupported content coding: " + coding);
        };
    }

    /** "deflate" is meant to be zlib-wrapped, but some servers send raw DEFLATE; accept both. */
    private static byte[] inflate(byte[] data, int max) throws IOException {
        boolean zlib = data.length >= 2 && (data[0] & 0x0f) == 8 && (((data[0] & 0xff) << 8) | (data[1] & 0xff)) % 31 == 0;
        return readCapped(new InflaterInputStream(new ByteArrayInputStream(data), new Inflater(!zlib)), max);
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
