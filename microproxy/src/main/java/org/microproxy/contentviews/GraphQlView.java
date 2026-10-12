/*
 * Ported from mitmproxy (https://github.com/mitmproxy/mitmproxy),
 * mitmproxy/contentviews/_view_graphql.py: recognizing GraphQL queries and batches among JSON
 * bodies, and showing the other members as JSON, then "---", then the query. Copyright (c) 2013,
 * Aldo Cortesi. Licensed under the MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.contentviews;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * GraphQL requests sent as JSON ({@code {"query": ..., "variables": ..., "operationName": ...}},
 * or a batch of them): the other members as indented JSON with the query as {@code "..."}, then
 * {@code ---}, then the query. A query written on one line is laid out with one field per line.
 */
final class GraphQlView implements ContentView {

    @Override
    public String name() {
        return "graphql";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        if (!JsonView.isJson(metadata) || data.length == 0) return 0;
        try {
            Object json = Json.parse(JsonView.text(data, metadata));
            return isQuery(json) || isBatch(json) ? 2 : 0;
        } catch (DecodeException e) {
            return 0;
        }
    }

    private static boolean isQuery(Object json) {
        if (!(json instanceof Map<?, ?> map) || !(map.get("query") instanceof String query)) return false;
        String q = query.strip();
        return q.contains("\n") || q.startsWith("{") || q.startsWith("query") || q.startsWith("mutation")
                || q.startsWith("subscription") || q.startsWith("fragment");
    }

    private static boolean isBatch(Object json) {
        return json instanceof List<?> list && !list.isEmpty() && list.getFirst() instanceof Map<?, ?> first
                && first.get("query") instanceof String;
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        Object json = Json.parse(JsonView.text(data, metadata));
        if (isQuery(json)) return format((Map<?, ?>) json);
        if (isBatch(json)) {
            List<?> list = (List<?>) json;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < list.size(); i++) {
                sb.append("--- ").append(i).append('/').append(list.size() - 1).append('\n');
                if (!(list.get(i) instanceof Map<?, ?> op) || !(op.get("query") instanceof String)) {
                    throw new DecodeException("not a GraphQL batch: element " + i + " has no query");
                }
                sb.append(format(op));
            }
            return sb.toString();
        }
        throw new DecodeException("not a GraphQL message");
    }

    private static String format(Map<?, ?> operation) {
        Map<Object, Object> header = new LinkedHashMap<>(operation);
        String query = (String) header.get("query");
        header.put("query", "...");
        String q = query.contains("\n") ? query.strip() : prettyQuery(query);
        return Json.pretty(header, "  ") + "\n---\n" + q + "\n";
    }

    // ---------------------------------------------------------------------------------------
    // Laying out a query
    // ---------------------------------------------------------------------------------------

    private enum Kind { NAME, STRING, PUNCT, COMMENT }

    private record Token(Kind kind, String text) {}

    /** A one-line query with a line per field and a level of indentation per selection set. */
    static String prettyQuery(String query) {
        List<Token> tokens = tokens(query);
        if (tokens == null) return query.strip();
        StringBuilder sb = new StringBuilder();
        int depth = 0;
        int parens = 0;
        Token prev = null;
        Token prevPrev = null;
        for (Token t : tokens) {
            String x = t.text();
            if (t.kind() == Kind.COMMENT) {
                newline(sb, depth);
                sb.append(x);
                newline(sb, depth);
                continue;
            }
            if (parens == 0 && x.equals("{")) {
                if (!sb.isEmpty() && !endsWithSpace(sb)) sb.append(' ');
                sb.append('{');
                depth++;
                newline(sb, depth);
            } else if (parens == 0 && x.equals("}")) {
                depth = Math.max(0, depth - 1);
                newline(sb, depth);
                sb.append('}');
                if (depth == 0) sb.append('\n');
            } else if (x.equals(",") && parens == 0) {
                continue;
            } else {
                boolean selection = depth > 0 && parens == 0 && prev != null
                        && (prev.kind() == Kind.NAME || prev.kind() == Kind.STRING
                                || prev.text().equals(")") || prev.text().equals("}") || prev.text().equals("]"))
                        && !(prev.text().equals("on") && prevPrev != null && prevPrev.text().equals("..."))
                        && (t.kind() == Kind.NAME || x.equals("..."));
                boolean topLevelBreak = depth == 0 && parens == 0 && prev != null && prev.text().equals("}");
                if (selection) {
                    newline(sb, depth);
                } else if (topLevelBreak) {
                    sb.append('\n');
                } else if (prev != null && needsSpace(prev, t, parens) && !endsWithSpace(sb)) {
                    sb.append(' ');
                }
                sb.append(x);
                if (x.equals("(")) parens++;
                if (x.equals(")")) parens = Math.max(0, parens - 1);
            }
            prevPrev = prev;
            prev = t;
        }
        return sb.toString().strip().replaceAll("[ ]+\n", "\n");
    }

    private static boolean needsSpace(Token prev, Token t, int parens) {
        String p = prev.text();
        String x = t.text();
        if (p.equals("...")) return x.equals("on");
        if (p.equals("(") || p.equals("[") || p.equals("$") || p.equals("@")) return false;
        if (x.equals(")") || x.equals("]") || x.equals(":") || x.equals(",") || x.equals("!") || x.equals("(")) return false;
        if (parens > 0 && (p.equals("{") || x.equals("}"))) return !p.equals("{") || !x.equals("}");
        return true;
    }

    private static boolean endsWithSpace(StringBuilder sb) {
        return !sb.isEmpty() && (sb.charAt(sb.length() - 1) == ' ' || sb.charAt(sb.length() - 1) == '\n');
    }

    private static void newline(StringBuilder sb, int depth) {
        int end = sb.length();
        while (end > 0 && sb.charAt(end - 1) == ' ') end--;
        sb.setLength(end);
        if (!sb.isEmpty() && sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
        sb.append("  ".repeat(depth));
    }

    /** The query's tokens, or {@code null} if it does not tokenize. */
    private static List<Token> tokens(String q) {
        List<Token> out = new ArrayList<>();
        int i = 0;
        while (i < q.length()) {
            char c = q.charAt(i);
            if (Character.isWhitespace(c) || c == '﻿') {
                i++;
            } else if (c == '#') {
                int end = q.indexOf('\n', i);
                end = end < 0 ? q.length() : end;
                out.add(new Token(Kind.COMMENT, q.substring(i, end).stripTrailing()));
                i = end;
            } else if (q.startsWith("\"\"\"", i)) {
                int end = q.indexOf("\"\"\"", i + 3);
                if (end < 0) return null;
                out.add(new Token(Kind.STRING, q.substring(i, end + 3)));
                i = end + 3;
            } else if (c == '"') {
                int j = i + 1;
                while (j < q.length() && q.charAt(j) != '"') j += q.charAt(j) == '\\' ? 2 : 1;
                if (j >= q.length()) return null;
                out.add(new Token(Kind.STRING, q.substring(i, j + 1)));
                i = j + 1;
            } else if (q.startsWith("...", i)) {
                out.add(new Token(Kind.PUNCT, "..."));
                i += 3;
            } else if ("!$&()=:@[]{}|,".indexOf(c) >= 0) {
                out.add(new Token(Kind.PUNCT, String.valueOf(c)));
                i++;
            } else if (Character.isLetterOrDigit(c) || c == '_' || c == '-' || c == '.') {
                int j = i;
                while (j < q.length() && (Character.isLetterOrDigit(q.charAt(j)) || "_-.+".indexOf(q.charAt(j)) >= 0)) j++;
                out.add(new Token(Kind.NAME, q.substring(i, j)));
                i = j;
            } else {
                return null;
            }
        }
        return out;
    }
}
