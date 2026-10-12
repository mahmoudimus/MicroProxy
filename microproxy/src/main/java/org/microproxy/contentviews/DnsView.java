package org.microproxy.contentviews;

import org.microproxy.dns.DnsMessage;

/**
 * DNS messages ({@code application/dns-message}, RFC 8484: DNS over HTTPS, and DNS over QUIC's
 * messages) as {@code dig} shows them: the header, then each section's records, with the common
 * types' data in presentation format.
 */
final class DnsView implements ContentView {

    /** The media type of a DNS message in wire format. */
    static final String MEDIA_TYPE = "application/dns-message";

    @Override
    public String name() {
        return "dns";
    }

    @Override
    public double priority(byte[] data, Metadata metadata) {
        return MEDIA_TYPE.equals(metadata.mediaType()) ? 1 : 0;
    }

    @Override
    public String render(byte[] data, Metadata metadata) throws DecodeException {
        try {
            return DnsMessage.decode(data).render();
        } catch (IllegalArgumentException e) {
            throw new DecodeException("not a DNS message: " + e.getMessage());
        }
    }
}
