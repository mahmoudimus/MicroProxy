package org.microproxy.contentviews;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/** JSON bodies ({@code application/json}, {@code text/json}, {@code +json}), indented by two spaces. */
final class JsonView implements ContentView {

    @Override
    public String name() {
        return "json";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        return isJson(metadata) && data.length > 0 ? 1 : 0;
    }

    static boolean isJson(Metadata metadata) {
        String type = metadata.mediaType();
        return type.equals("application/json") || type.equals("text/json") || type.endsWith("+json");
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        return Json.pretty(Json.parse(text(data, metadata)), "  ") + "\n";
    }

    /** The body as text in the charset its {@code Content-Type} names (UTF-8 by default). */
    static String text(byte[] data, Metadata metadata) {
        return new String(data, charset(metadata));
    }

    /** The charset the {@code Content-Type} names, or UTF-8. */
    static Charset charset(Metadata metadata) {
        String name = metadata.parameter("charset");
        if (name == null) return StandardCharsets.UTF_8;
        try {
            return Charset.forName(name, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return StandardCharsets.UTF_8;
        }
    }
}
