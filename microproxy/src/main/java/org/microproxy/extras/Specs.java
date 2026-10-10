/*
 * Ported from mitmproxy's mitmproxy/utils/spec.py and the escape handling of
 * mitmproxy/utils/strutils.py (https://github.com/mitmproxy/mitmproxy), Copyright (c) 2013, Aldo
 * Cortesi. Licensed under the MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.microproxy.FlowContext;
import org.microproxy.http.HttpRequest;

/**
 * The option syntax the addons share with mitmproxy: {@code [/flow-filter]/subject/replacement},
 * where the first character is the separator and may be any character, so {@code
 * |~d example.com|/a|/b} works as well.
 */
final class Specs {

    private Specs() {}

    /**
     * A parsed spec: the filter ({@link FlowFilter#ALL} when the spec has none) and the remaining
     * parts.
     */
    record Spec(FlowFilter filter, List<String> parts) {}

    /**
     * Splits {@code option} into a filter and {@code parts} further parts; with one part more, the
     * first is a filter expression. The last part takes the rest of the option, separators
     * included.
     */
    static Spec parse(String option, int parts, String what) {
        if (option == null || option.length() < 2) {
            throw new IllegalArgumentException("invalid " + what + " spec: " + option);
        }
        String sep = option.substring(0, 1);
        String[] split = option.substring(1).split(Pattern.quote(sep), parts + 1);
        if (split.length == parts) {
            return new Spec(FlowFilter.ALL, List.of(split));
        }
        if (split.length == parts + 1) {
            return new Spec(FlowFilter.parse(split[0]), List.of(split).subList(1, split.length));
        }
        throw new IllegalArgumentException("invalid " + what + " spec " + option + ": expected "
                + parts + " or " + (parts + 1) + " parts separated by '" + sep + "'");
    }

    /** Compiles a regular expression from a spec, naming the spec in the error. */
    static Pattern regex(String regex, int flags, String what) {
        try {
            return Pattern.compile(regex, flags);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("invalid regular expression in " + what + " spec: " + regex
                    + " (" + e.getDescription() + ")", e);
        }
    }

    /**
     * A replacement value: the bytes of the file after {@code @}, or the text with Python's
     * backslash escapes ({@code \n}, {@code \t}, {@code \xHH}, {@code \\}, ...) decoded, as
     * mitmproxy reads replacements.
     */
    static byte[] replacement(String value) {
        if (value.startsWith("@")) {
            Path file = Path.of(expandHome(value.substring(1)));
            try {
                return Files.readAllBytes(file);
            } catch (IOException e) {
                throw new UncheckedIOException("cannot read replacement file " + file, e);
            }
        }
        return unescape(value);
    }

    /**
     * The source of a replacement value: fixed text, or a file ({@code @path}) read again for each
     * use, as mitmproxy does, so edits to it apply at once. The file must be readable now; later
     * read failures fall back to its last contents.
     */
    static Supplier<byte[]> replacementSource(String value) {
        byte[] initial = replacement(value);
        if (!value.startsWith("@")) return () -> initial;
        AtomicReference<byte[]> last = new AtomicReference<>(initial);
        return () -> {
            try {
                byte[] now = replacement(value);
                last.set(now);
                return now;
            } catch (UncheckedIOException e) {
                System.getLogger(Specs.class.getName()).log(System.Logger.Level.WARNING,
                        "could not read replacement file; using its last contents: " + e.getMessage());
                return last.get();
            }
        };
    }

    static String expandHome(String path) {
        if (path.equals("~") || path.startsWith("~/")) return System.getProperty("user.home") + path.substring(1);
        return path;
    }

    /** Decodes Python's string escapes into bytes (other characters as UTF-8). */
    static byte[] unescape(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                int end = i + 1;
                while (end < s.length() && s.charAt(end) != '\\') end++;
                out.writeBytes(s.substring(i, end).getBytes(StandardCharsets.UTF_8));
                i = end;
                continue;
            }
            char e = s.charAt(i + 1);
            i += 2;
            switch (e) {
                case 'n' -> out.write('\n');
                case 'r' -> out.write('\r');
                case 't' -> out.write('\t');
                case '0' -> out.write(0);
                case 'a' -> out.write(7);
                case 'b' -> out.write('\b');
                case 'f' -> out.write('\f');
                case 'v' -> out.write(11);
                case '\\' -> out.write('\\');
                case '\'' -> out.write('\'');
                case '"' -> out.write('"');
                case 'x' -> {
                    if (i + 2 > s.length()) throw new IllegalArgumentException("invalid \\x escape in " + s);
                    try {
                        out.write(Integer.parseInt(s.substring(i, i + 2), 16));
                    } catch (NumberFormatException ex) {
                        throw new IllegalArgumentException("invalid \\x escape in " + s, ex);
                    }
                    i += 2;
                }
                default -> {
                    // Unknown escapes stay as they are, as in Python.
                    out.write('\\');
                    out.writeBytes(String.valueOf(e).getBytes(StandardCharsets.UTF_8));
                }
            }
        }
        return out.toByteArray();
    }

    private static final Pattern PYTHON_GROUP = Pattern.compile("\\\\(?:(\\d{1,2})|g<([^>]+)>)|\\\\\\\\");

    /**
     * Turns a replacement written for Python's {@code re.sub} ({@code \1}, {@code \g<1>}, {@code
     * \g<name>}) into one for {@link Matcher#replaceAll}. Java's own {@code $1} and {@code ${name}}
     * work too; a literal {@code $} is written {@code \$}.
     */
    static String javaReplacement(String replacement) {
        Matcher m = PYTHON_GROUP.matcher(replacement);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String group = m.group(1) != null ? m.group(1) : m.group(2);
            String java;
            if (group == null) {
                java = "\\\\\\\\"; // a literal backslash
            } else if (group.chars().allMatch(Character::isDigit)) {
                java = "\\$" + group;
            } else {
                java = "\\${" + group + "}";
            }
            m.appendReplacement(sb, java);
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * The request's URL in absolute form: as sent, or rebuilt from {@code Host} ({@code https://}
     * inside an intercepted session), as mitmproxy's {@code pretty_url}.
     */
    static String url(HttpRequest request, FlowContext ctx) {
        return RewriteRules.absoluteUrl(request, ctx);
    }

    /** The scheme of an absolute URL, lower case. */
    static String scheme(String url) {
        int sep = url.indexOf("://");
        return sep < 0 ? "" : url.substring(0, sep).toLowerCase(Locale.ROOT);
    }

    /** Splits a comma-separated option value, dropping blanks. */
    static List<String> list(String value) {
        List<String> out = new ArrayList<>();
        for (String s : value.split(",")) {
            if (!s.isBlank()) out.add(s.strip());
        }
        return out;
    }
}
