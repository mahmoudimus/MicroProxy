package org.microproxy.extras;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.microproxy.ResponseFlag;

/** The parser of {@link AccessLogFilter#parse}'s compact syntax. */
final class AccessLogFilterParser {
    private final String text;
    private int pos;

    AccessLogFilterParser(String text) {
        this.text = Objects.requireNonNull(text);
    }

    AccessLogFilter parse() {
        AccessLogFilter f = expr();
        space();
        if (pos < text.length()) throw error("unexpected '" + text.substring(pos) + "'");
        return f;
    }

    private AccessLogFilter expr() {
        List<AccessLogFilter> any = new ArrayList<>();
        any.add(term());
        while (accept("||") || acceptWord("or")) any.add(term());
        return any.size() == 1 ? any.get(0) : AccessLogFilter.anyOf(any.toArray(AccessLogFilter[]::new));
    }

    private AccessLogFilter term() {
        List<AccessLogFilter> all = new ArrayList<>();
        all.add(factor());
        while (accept("&&") || acceptWord("and")) all.add(factor());
        return all.size() == 1 ? all.get(0) : AccessLogFilter.allOf(all.toArray(AccessLogFilter[]::new));
    }

    private AccessLogFilter factor() {
        space();
        if (accept("!") || acceptWord("not")) return factor().negate();
        if (accept("(")) {
            AccessLogFilter f = expr();
            expect(")");
            return f;
        }
        return filter();
    }

    private AccessLogFilter filter() {
        space();
        int start = pos;
        while (pos < text.length() && (Character.isLetterOrDigit(text.charAt(pos)) || text.charAt(pos) == '_')) pos++;
        String name = text.substring(start, pos).toLowerCase(Locale.ROOT);
        switch (name) {
            case "status", "status_code" -> {
                AccessLogFilter.Comparison op = comparison();
                return AccessLogFilter.statusCode(op, (int) integer());
            }
            case "duration" -> {
                AccessLogFilter.Comparison op = comparison();
                long value = integer();
                if (acceptWord("ms")) return AccessLogFilter.duration(op, value);
                if (acceptWord("s")) return AccessLogFilter.duration(op, value * 1000);
                return AccessLogFilter.duration(op, value);
            }
            case "not_health_check" -> {
                String arg = optionalArgument();
                if (arg == null) return AccessLogFilter.notHealthCheck();
                if (arg.startsWith("header=")) return AccessLogFilter.notHealthCheckHeader(arg.substring(7).strip());
                return AccessLogFilter.notHealthCheckPath(arg);
            }
            case "response_flag", "response_flags" -> {
                String arg = optionalArgument();
                if (arg == null || arg.isEmpty()) return AccessLogFilter.responseFlag();
                List<ResponseFlag> flags = new ArrayList<>();
                for (String f : arg.split(",")) flags.add(ResponseFlag.of(f));
                return AccessLogFilter.responseFlag(flags.toArray(ResponseFlag[]::new));
            }
            case "header" -> {
                String arg = optionalArgument();
                if (arg == null || arg.isEmpty()) throw error("header(...) needs a field name");
                int tilde = arg.indexOf('~');
                int eq = arg.indexOf('=');
                if (tilde > 0 && (eq < 0 || tilde < eq)) {
                    return AccessLogFilter.header(arg.substring(0, tilde).strip(), arg.substring(tilde + 1).strip());
                }
                if (eq > 0) return AccessLogFilter.headerEquals(arg.substring(0, eq).strip(), arg.substring(eq + 1).strip());
                return AccessLogFilter.header(arg.strip());
            }
            case "runtime", "sample" -> {
                String arg = optionalArgument();
                if (arg == null) throw error(name + "(...) needs a percentage");
                String p = arg.endsWith("%") ? arg.substring(0, arg.length() - 1) : arg;
                try {
                    return AccessLogFilter.runtime(Double.parseDouble(p.strip()));
                } catch (NumberFormatException e) {
                    throw error("not a percentage: " + arg);
                }
            }
            default -> throw error(name.isEmpty() ? "a filter expected" : "unknown filter '" + name + "'");
        }
    }

    private AccessLogFilter.Comparison comparison() {
        space();
        if (accept("==") || accept("=")) return AccessLogFilter.Comparison.EQ;
        if (accept("!=")) return AccessLogFilter.Comparison.NE;
        if (accept(">=")) return AccessLogFilter.Comparison.GE;
        if (accept("<=")) return AccessLogFilter.Comparison.LE;
        if (accept(">")) return AccessLogFilter.Comparison.GT;
        if (accept("<")) return AccessLogFilter.Comparison.LT;
        throw error("a comparison (=, !=, >=, <=, >, <) expected");
    }

    private long integer() {
        space();
        int start = pos;
        while (pos < text.length() && Character.isDigit(text.charAt(pos))) pos++;
        if (start == pos) throw error("a number expected");
        return Long.parseLong(text.substring(start, pos));
    }

    /** The text inside {@code (...)} after a filter's name, nested parentheses included; null without one. */
    private String optionalArgument() {
        space();
        if (pos >= text.length() || text.charAt(pos) != '(') return null;
        int depth = 0;
        int start = pos + 1;
        for (int i = pos; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                pos = i + 1;
                return text.substring(start, i).strip();
            }
        }
        throw error("unclosed '('");
    }

    private boolean accept(String token) {
        space();
        if (text.startsWith(token, pos)) {
            pos += token.length();
            return true;
        }
        return false;
    }

    private boolean acceptWord(String word) {
        space();
        int end = pos + word.length();
        if (text.regionMatches(true, pos, word, 0, word.length())
                && (end >= text.length() || !Character.isLetterOrDigit(text.charAt(end)) && text.charAt(end) != '_')) {
            pos = end;
            return true;
        }
        return false;
    }

    private void expect(String token) {
        if (!accept(token)) throw error("'" + token + "' expected");
    }

    private void space() {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) pos++;
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("access-log filter \"" + text + "\" at " + pos + ": " + message);
    }
}
