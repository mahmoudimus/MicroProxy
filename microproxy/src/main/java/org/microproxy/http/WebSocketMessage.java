package org.microproxy.http;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * A whole WebSocket message (RFC 6455 section 5.4): the payloads of a text or binary frame and its
 * continuation frames, joined, and inflated when the connection uses permessage-deflate (RFC
 * 7692). Messages relayed after an upgrade are shown to {@link
 * org.microproxy.HttpFilters#filterWebSocketMessage(WebSocketMessage, boolean)}, which may return
 * one built with {@link #text(String, boolean)}, {@link #binary(byte[], boolean)}, {@link
 * #withText(String)} and the like to send instead.
 *
 * <p>Messages are immutable: the payload is copied in and out.
 *
 * @param type whether the message is text or binary
 * @param payload the application data (UTF-8 for a text message)
 * @param fromClient whether the message travels from the client towards the server
 */
public record WebSocketMessage(Type type, byte[] payload, boolean fromClient) {

    /** The kind of data a message carries (its first frame's opcode). */
    public enum Type {
        /** A text message: UTF-8 ({@link WebSocketFrame#OPCODE_TEXT}). */
        TEXT,
        /** A binary message ({@link WebSocketFrame#OPCODE_BINARY}). */
        BINARY;

        /**
         * The opcode of the first frame of a message of this type.
         *
         * @return {@link WebSocketFrame#OPCODE_TEXT} or {@link WebSocketFrame#OPCODE_BINARY}
         */
        public int opcode() {
            return this == TEXT ? WebSocketFrame.OPCODE_TEXT : WebSocketFrame.OPCODE_BINARY;
        }
    }

    /**
     * A message, with a copy of {@code payload}.
     *
     * @param type whether the message is text or binary
     * @param payload the application data, copied
     * @param fromClient whether the message travels from the client towards the server
     */
    public WebSocketMessage {
        Objects.requireNonNull(type, "type");
        payload = payload.clone();
    }

    /**
     * A text message.
     *
     * @param text the text, encoded as UTF-8
     * @param fromClient whether the message travels towards the server
     * @return a text message
     */
    public static WebSocketMessage text(String text, boolean fromClient) {
        return new WebSocketMessage(Type.TEXT, text.getBytes(StandardCharsets.UTF_8), fromClient);
    }

    /**
     * A binary message.
     *
     * @param data the payload, copied
     * @param fromClient whether the message travels towards the server
     * @return a binary message
     */
    public static WebSocketMessage binary(byte[] data, boolean fromClient) {
        return new WebSocketMessage(Type.BINARY, data, fromClient);
    }

    /**
     * Returns a copy of the application data.
     *
     * @return the payload bytes
     */
    @Override
    public byte[] payload() {
        return payload.clone();
    }

    /**
     * Returns the payload length.
     *
     * @return the number of payload bytes
     */
    public int length() {
        return payload.length;
    }

    /**
     * Checks the message type.
     *
     * @return whether this is a text message
     */
    public boolean isText() {
        return type == Type.TEXT;
    }

    /**
     * Checks the message type.
     *
     * @return whether this is a binary message
     */
    public boolean isBinary() {
        return type == Type.BINARY;
    }

    /**
     * The payload decoded as UTF-8, with malformed input replaced (meaningful for text messages).
     *
     * @return the payload as text
     */
    public String text() {
        return new String(payload, StandardCharsets.UTF_8);
    }

    /**
     * The payload decoded as UTF-8, or {@code null} if it is not valid UTF-8.
     *
     * @return the payload as text, or null
     */
    public String textOrNull() {
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(payload)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /**
     * This message with another payload, keeping its type and direction.
     *
     * @param data the new payload, copied
     * @return a new message
     */
    public WebSocketMessage withPayload(byte[] data) {
        return new WebSocketMessage(type, data, fromClient);
    }

    /**
     * This message with another payload, encoded as UTF-8, keeping its type and direction.
     *
     * @param text the new payload text
     * @return a new message
     */
    public WebSocketMessage withText(String text) {
        return withPayload(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * This message as another type, keeping its payload and direction.
     *
     * @param newType the new type
     * @return a new message
     */
    public WebSocketMessage withType(Type newType) {
        return new WebSocketMessage(newType, payload, fromClient);
    }

    /**
     * This message travelling the other way, or the same way: a hook that returns it with {@code
     * fromClient} changed sends it back to where the original came from.
     *
     * @param fromClient whether the new message travels from the client towards the server
     * @return a new message
     */
    public WebSocketMessage withFromClient(boolean fromClient) {
        return new WebSocketMessage(type, payload, fromClient);
    }

    /**
     * Whether {@code other} has the same type, direction and payload.
     *
     * @param other the object to compare with
     * @return whether the messages are equal
     */
    @Override
    public boolean equals(Object other) {
        return other instanceof WebSocketMessage m && m.type == type && m.fromClient == fromClient
                && Arrays.equals(m.payload, payload);
    }

    @Override
    public int hashCode() {
        return (type.hashCode() * 31 + Boolean.hashCode(fromClient)) * 31 + Arrays.hashCode(payload);
    }

    @Override
    public String toString() {
        return "WebSocketMessage[" + type + (fromClient ? " from client, " : " from server, ") + payload.length
                + " bytes]";
    }
}
