package org.microproxy.contentviews;

import java.util.Locale;

/**
 * Any bytes as a hex dump: offset, sixteen bytes in hex, and the printable ASCII characters. It is
 * never chosen automatically; name it to use it.
 */
final class HexView implements ContentView {

    @Override
    public String name() {
        return "hex";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        return 0;
    }

    @Override
    public String render(byte[] data, Metadata metadata) {
        StringBuilder sb = new StringBuilder();
        for (int off = 0; off < data.length; off += 16) {
            sb.append(String.format(Locale.ROOT, "%08x  ", off));
            StringBuilder ascii = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                if (off + i < data.length) {
                    int b = data[off + i] & 0xff;
                    sb.append(String.format(Locale.ROOT, "%02x ", b));
                    ascii.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
                } else {
                    sb.append("   ");
                }
                if (i == 7) sb.append(' ');
            }
            sb.append(' ').append(ascii).append('\n');
        }
        return sb.toString();
    }
}
