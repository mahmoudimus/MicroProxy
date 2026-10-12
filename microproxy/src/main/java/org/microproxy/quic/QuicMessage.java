package org.microproxy.quic;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import org.microproxy.contentviews.ContentView;
import org.microproxy.contentviews.ContentViews;
import org.microproxy.contentviews.DecodeException;
import org.microproxy.contentviews.ProtoMessage;
import org.microproxy.contentviews.ProtoSchema;
import org.microproxy.contentviews.Protobuf;
import org.microproxy.dns.DnsMessage;

/**
 * One whole message of a stream of an intercepted QUIC connection, as {@link
 * QuicInterceptor#streamMessage} sees it: the payload a {@link MessageFramer} cut out of the stream
 * (without its length prefix or delimiter), which side sent it, on which stream, and when it was
 * complete.
 *
 * <p>Messages are immutable apart from {@link #data()}, which a hook may change in place; the
 * {@code with} methods make changed copies, which the hook returns to send instead. The decoders
 * read the payload: {@link #dns()} as DNS (DNS over QUIC), {@link #protobuf()} as protobuf, and
 * {@link #render()} with the content views, for logging.
 */
public final class QuicMessage {

    /** The ALPN protocol whose messages are DNS messages (RFC 9250). */
    static final String DOQ = "doq";

    private final byte[] data;
    private final boolean fromClient;
    private final long streamId;
    private final String alpn;
    private final Instant timestamp;

    /**
     * A message.
     *
     * @param data the payload, which the message holds as it is (not copied)
     * @param fromClient whether the client sent it (it goes to the server), rather than the server
     * @param streamId the stream's ID on the client's connection
     * @param alpn the connection's ALPN protocol, or null
     * @param timestamp when the proxy had the whole message
     */
    public QuicMessage(byte[] data, boolean fromClient, long streamId, String alpn, Instant timestamp) {
        this.data = Objects.requireNonNull(data, "data");
        this.fromClient = fromClient;
        this.streamId = streamId;
        this.alpn = alpn;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp");
    }

    /**
     * The payload. The array is the message's own, not a copy: a hook may change it in place and
     * return the message.
     *
     * @return the payload
     */
    public byte[] data() {
        return data;
    }

    /** {@return the payload's length in bytes} */
    public int length() {
        return data.length;
    }

    /** {@return whether the client sent the message (it goes to the server), rather than the server} */
    public boolean fromClient() {
        return fromClient;
    }

    /** {@return the stream's ID on the client's connection} */
    public long streamId() {
        return streamId;
    }

    /** {@return the connection's ALPN protocol, or null} */
    public String alpn() {
        return alpn;
    }

    /** {@return when the proxy had the whole message} */
    public Instant timestamp() {
        return timestamp;
    }

    /**
     * The payload decoded as UTF-8, malformed sequences replaced with U+FFFD.
     *
     * @return the text
     */
    public String text() {
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * A copy of this message with another payload, the same direction, stream and timestamp.
     *
     * @param data the payload of the copy (not copied)
     * @return the copy
     */
    public QuicMessage withData(byte[] data) {
        return new QuicMessage(data, fromClient, streamId, alpn, timestamp);
    }

    /**
     * A copy of this message with the UTF-8 encoding of {@code text}.
     *
     * @param text the text of the copy
     * @return the copy
     */
    public QuicMessage withText(String text) {
        return withData(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * A copy of this message going the other way, or the same: with {@code fromClient} it goes to
     * the server, else to the client, on the same stream. A hook returns one to answer a side itself.
     *
     * @param fromClient whether the copy goes to the server
     * @return the copy
     */
    public QuicMessage withFromClient(boolean fromClient) {
        return new QuicMessage(data, fromClient, streamId, alpn, timestamp);
    }

    /**
     * The payload as a DNS message, as DNS over QUIC ({@code doq}) carries them.
     *
     * @return the DNS message
     * @throws IllegalArgumentException if the payload is not a well-formed DNS message
     */
    public DnsMessage dns() {
        return DnsMessage.decode(data);
    }

    /**
     * A copy of this message whose payload is {@code dns}, encoded.
     *
     * @param dns the DNS message
     * @return the copy
     */
    public QuicMessage withDns(DnsMessage dns) {
        return withData(dns.encode());
    }

    /**
     * The payload as a protobuf message, without a schema: fields by number.
     *
     * @return the message
     * @throws DecodeException if the payload is not a protobuf message
     */
    public ProtoMessage protobuf() throws DecodeException {
        return Protobuf.decode(data);
    }

    /**
     * The payload as a protobuf message of {@code messageType}, its fields named by {@code schema}.
     *
     * @param schema the schema, as from {@link ProtoSchema#load}
     * @param messageType the message type's full name, such as {@code shop.Order}
     * @return the message
     * @throws DecodeException if the payload is not a protobuf message
     */
    public ProtoMessage protobuf(ProtoSchema schema, String messageType) throws DecodeException {
        return Protobuf.decode(data, schema, messageType);
    }

    /**
     * The payload rendered by the best of the default content views that can: as DNS for DNS over
     * QUIC, else as what the bytes look like (protobuf, JSON, ...).
     *
     * @return the rendering, or empty when no view could render the payload
     */
    public Optional<ContentViews.Rendered> render() {
        return render(ContentViews.defaults());
    }

    /**
     * The payload rendered by the best of {@code views} that can. For DNS over QUIC, the views are
     * told the payload is an {@code application/dns-message}.
     *
     * @param views the views
     * @return the rendering, or empty when no view could render the payload
     */
    public Optional<ContentViews.Rendered> render(ContentViews views) {
        return views.render(data, ContentView.Metadata.of(DOQ.equals(alpn) ? "application/dns-message" : null));
    }

    @Override
    public String toString() {
        return (fromClient ? "-> " : "<- ") + "stream " + streamId + ": " + data.length + " bytes";
    }
}
