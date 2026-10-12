# WebSockets

Watch, rewrite, drop and add WebSocket frames and whole messages in both directions, over HTTP/1
upgrades and HTTP/2 and HTTP/3 extended `CONNECT`, inside intercepted TLS and through
permessage-deflate. Use this page to write WebSocket filters in Java; scripts use
[`on_websocket_frame` and `on_websocket_message`](scripting.md#websocket-examples).

## WebSocket frames and messages

After a `101` upgrade or HTTP/2 WebSocket extended CONNECT, filters can watch and rewrite every
frame, or every whole message, in both directions and inside intercepted TLS:

- **Watching:** `webSocketFrameReceived(WebSocketFrame frame, boolean fromClient)` sees the
  opcode, FIN, masking and the unmasked payload. LittleProxy's
  `webSocketFrameReceived(Supplier<byte[]>, boolean)` still works and receives each frame's raw
  bytes (LittleProxy delivered raw TCP reads rather than frames).
- **Rewriting frames:** `filterWebSocketFrame(WebSocketFrame frame, boolean fromClient)` returns
  the frame to forward: `frame` itself, a replacement (`frame.withText(...)`,
  `WebSocketFrame.text(...)`, `binary(...)`, `close(code, reason)`), or `null` to drop it. The
  proxy masks frames it sends towards the server, as RFC 6455 requires. Messages split into
  continuation frames are seen one frame at a time.
- **Rewriting messages:** `filterWebSocketMessage(WebSocketMessage message, boolean fromClient)`
  sees a whole text or binary message, its frames joined. `WebSocketMessage` is a record (`type`
  `TEXT` or `BINARY`, `payload`, `fromClient`) with `text()`, `withText(...)`,
  `withPayload(...)`, `withFromClient(...)` and the factories `WebSocketMessage.text(...)` and
  `binary(...)`. Return the message, a replacement, or `null` to drop it. Override
  `filterWebSocketMessages` instead to return a list: each message goes towards the server when
  its `fromClient()` is true and towards the client otherwise, so a filter can answer a message
  itself or add messages in either direction. `HttpFilters.builder().onWebSocketMessage(...)`
  takes a lambda.
- **Order:** with both hooks, each frame goes through `filterWebSocketFrame` first, and
  `filterWebSocketMessage` sees the message joined from what it returned (a dropped frame adds
  nothing). Control frames (ping, pong, close) that arrive between a message's frames reach the
  frame hook and are forwarded at once; they never wait for the message.
- **Fragmentation:** a message returned unchanged goes out split as it arrived; an edited one
  goes out as a single frame.
- **Limits:** frames larger than `withMaxWebSocketFrameBufferSize` (default 1 MiB) arrive at the
  frame hook truncated, without a payload: returning them streams them through, `null` discards
  them. Frames of a message being joined, and compressed frames, are buffered whole instead, up
  to `withMaxWebSocketMessageSize` (default 16 MiB). A message larger than that, joined or
  inflated (a decompression bomb), fails the connection: both peers get a close frame with status
  1009 (message too big), as mitmproxy does. Frames out of order (a continuation outside a
  message, a new message before the last one ended) and invalid compressed data fail it with
  1002.
- **No listener:** if no filter overrides any of these methods, the connection is relayed as raw
  bytes. Frames are only joined into messages for filters that override a message hook, so frame
  filters keep relaying frame by frame, and filters that only watch frames leave compressed
  frames as they are (RSV1 set).

```java
@Override
public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
    if (!frame.isText()) return frame;
    String text = frame.payloadAsText();
    if (fromClient && text.contains("\"password\"")) return null;        // drop it
    return frame.withText(text.replace("staging.example", "prod.example")); // or rewrite it
}

@Override
public WebSocketMessage filterWebSocketMessage(WebSocketMessage message, boolean fromClient) {
    if (message.isBinary() && message.length() > 1 << 20) return null;    // drop big uploads
    return message.isText() ? message.withText(message.text().strip()) : message;
}
```

### permessage-deflate (RFC 7692)

Filters that rewrite frames or messages read compressed
traffic as plain text: the proxy inflates what each peer sends and compresses what it forwards
again. Each direction has two compression contexts, one per hop (client to proxy, proxy to
server), because a hook may change payloads, so the proxy cannot pass compressed bytes on and keep
the receiver's history in step with the sender's. The proxy keeps only the permessage-deflate
offers in the upgrade request's `Sec-WebSocket-Extensions` (it could not read frames of other
extensions) and otherwise leaves the negotiation to the client and server; it then applies what
the server's answer says to the server's hop and what the client received to the client's hop.

- `client_no_context_takeover` and `server_no_context_takeover` are honoured per direction: the
  proxy resets its compressor after each message when it is the sender that agreed to it, and its
  decompressor when the peer is.
- `server_max_window_bits` and `client_max_window_bits`: the JDK's `Inflater` always uses a 32
  KiB window, which reads anything a peer sends whatever window it agreed to. The JDK's `Deflater`
  cannot use a smaller window, and a peer that agreed to a smaller one may keep only that much
  history, so a back-reference further back would corrupt what it reads. Resetting the compressor
  after each message would not help, since one message longer than the window can refer back
  across it. Towards a peer whose window is under 15 bits the proxy therefore compresses with
  Huffman coding only (`Deflater.HUFFMAN_ONLY`): no back-references at all, which any window
  decodes. The parameters stay as the peers agreed them; only the proxy's own output compresses
  less.
- A message goes out compressed when its sender compressed it and the hop agreed to compression;
  a message a filter sends back to a peer is compressed whenever that hop agreed to it.
- `java.net.http.WebSocket` never offers extensions, so the tests use peers built on `Deflater`
  and `Inflater`.
