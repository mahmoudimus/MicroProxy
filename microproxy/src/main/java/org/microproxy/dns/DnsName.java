package org.microproxy.dns;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** An absolute domain name as a list of labels (leftmost first), compared case-insensitively. */
final class DnsName implements Comparable<DnsName> {

    static final DnsName ROOT = new DnsName(new byte[0][]);

    private final byte[][] labels;

    private DnsName(byte[][] labels) {
        this.labels = labels;
    }

    static DnsName of(byte[][] labels) {
        int total = 1;
        for (byte[] l : labels) {
            if (l.length == 0 || l.length > 63) throw new IllegalArgumentException("bad label length");
            total += l.length + 1;
        }
        if (total > 255) throw new IllegalArgumentException("name too long");
        return labels.length == 0 ? ROOT : new DnsName(labels.clone());
    }

    /**
     * Parses presentation format ({@code www.example.com} or {@code www.example.com.}), with
     * {@code \.}, {@code \\} and {@code \DDD} escapes as {@link #toString()} writes them.
     */
    static DnsName parse(String text) {
        if (text.equals(".") || text.isEmpty()) return ROOT;
        List<byte[]> labels = new ArrayList<>();
        ByteArrayOutputStream label = new ByteArrayOutputStream();
        int n = text.length();
        for (int i = 0; i < n; i++) {
            char c = text.charAt(i);
            if (c == '.') {
                if (label.size() == 0) throw new IllegalArgumentException("empty label in " + text);
                labels.add(label.toByteArray());
                label.reset();
            } else if (c == '\\') {
                if (i + 1 >= n) throw new IllegalArgumentException("trailing backslash in " + text);
                char d = text.charAt(i + 1);
                if (d >= '0' && d <= '9') {
                    String digits = i + 4 <= n ? text.substring(i + 1, i + 4) : "";
                    if (digits.length() != 3 || !digits.chars().allMatch(ch -> ch >= '0' && ch <= '9')) {
                        throw new IllegalArgumentException("bad escape in " + text);
                    }
                    int v = Integer.parseInt(digits);
                    if (v > 255) throw new IllegalArgumentException("bad escape in " + text);
                    label.write(v);
                    i += 3;
                } else {
                    label.write(d);
                    i++;
                }
            } else if (c < 0x80) {
                label.write(c);
            } else {
                int cp = text.codePointAt(i);
                label.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                i += Character.charCount(cp) - 1;
            }
        }
        if (label.size() > 0) labels.add(label.toByteArray());
        return of(labels.toArray(byte[][]::new));
    }

    int labelCount() {
        return labels.length;
    }

    byte[] label(int i) {
        return labels[i];
    }

    boolean isRoot() {
        return labels.length == 0;
    }

    boolean isWildcard() {
        return labels.length > 0 && labels[0].length == 1 && labels[0][0] == '*';
    }

    /** The name made of the rightmost {@code n} labels. */
    DnsName suffix(int n) {
        if (n >= labels.length) return this;
        return n == 0 ? ROOT : new DnsName(Arrays.copyOfRange(labels, labels.length - n, labels.length));
    }

    DnsName parent() {
        return suffix(labels.length - 1);
    }

    /** {@code *.} followed by this name. */
    DnsName wildcardChild() {
        byte[][] l = new byte[labels.length + 1][];
        l[0] = new byte[] {'*'};
        System.arraycopy(labels, 0, l, 1, labels.length);
        return of(l);
    }

    /** {@code label.} followed by this name. */
    DnsName child(byte[] label) {
        byte[][] l = new byte[labels.length + 1][];
        l[0] = label;
        System.arraycopy(labels, 0, l, 1, labels.length);
        return of(l);
    }

    /** Whether this name equals {@code ancestor} or lies below it. */
    boolean isSubdomainOf(DnsName ancestor) {
        if (ancestor.labels.length > labels.length) return false;
        return suffix(ancestor.labels.length).equals(ancestor);
    }

    /** Uncompressed wire format, original case. */
    byte[] toWire() {
        return wire(false);
    }

    /** Uncompressed wire format with ASCII letters lowercased (RFC 4034 6.2). */
    byte[] toCanonicalWire() {
        return wire(true);
    }

    private byte[] wire(boolean lower) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        for (byte[] l : labels) {
            out.write(l.length);
            for (byte b : l) out.write(lower ? lower(b) : b);
        }
        out.write(0);
        return out.toByteArray();
    }

    static byte lower(byte b) {
        return b >= 'A' && b <= 'Z' ? (byte) (b + 32) : b;
    }

    /** RFC 4034 section 6.1 canonical ordering. */
    @Override
    public int compareTo(DnsName o) {
        int i = labels.length - 1;
        int j = o.labels.length - 1;
        while (i >= 0 && j >= 0) {
            int c = compareLabel(labels[i], o.labels[j]);
            if (c != 0) return c;
            i--;
            j--;
        }
        return Integer.compare(labels.length, o.labels.length);
    }

    private static int compareLabel(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int k = 0; k < n; k++) {
            int c = Integer.compare(lower(a[k]) & 0xff, lower(b[k]) & 0xff);
            if (c != 0) return c;
        }
        return Integer.compare(a.length, b.length);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DnsName other) || other.labels.length != labels.length) return false;
        for (int i = 0; i < labels.length; i++) {
            if (compareLabel(labels[i], other.labels[i]) != 0) return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(toCanonicalWire());
    }

    @Override
    public String toString() {
        if (labels.length == 0) return ".";
        List<String> parts = new ArrayList<>(labels.length);
        for (byte[] l : labels) {
            StringBuilder sb = new StringBuilder();
            for (byte b : l) {
                int c = b & 0xff;
                if (c == '.' || c == '\\') sb.append('\\').append((char) c);
                else if (c > 0x20 && c < 0x7f) sb.append((char) c);
                else sb.append(String.format(Locale.ROOT, "\\%03d", c));
            }
            parts.add(sb.toString());
        }
        return String.join(".", parts) + ".";
    }
}
