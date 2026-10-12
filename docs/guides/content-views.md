# Content views, gRPC and protobuf

Render message bodies readably: protobuf without a schema, gRPC message by message with its status
details, JSON, GraphQL, msgpack, forms, Socket.IO and DNS, with field names from a `protoc`
descriptor set. Use this page to read binary traffic in logs, or to decode and edit protobuf and
gRPC from Java; scripts get the same through the [`protobuf` and `grpc`
modules](../reference/starlark-api.md#protobuf-and-grpc).

## Content views

`org.microproxy.contentviews` turns message bodies into readable text, after mitmproxy's content
views. A `ContentView` has a name, rates how well it suits a body (`priority`, from the
`Content-Type`, the request path and the bytes) and renders it. `ContentViews` holds a set of
views and, in `auto` mode, renders each body with the best view that can; when none can, there
is no rendering and callers show the body as before. `HttpLogger` uses them (see
[Request/response logging](../observability/request-logging.md)); they also work on their own:

```java
ContentViews views = ContentViews.defaults();
views.render(body, ContentView.Metadata.forResponse(request, response))
        .ifPresent(r -> System.out.println(r.view() + ":\n" + r.text()));
```

| View | Bodies | Rendering |
|---|---|---|
| `protobuf` | `application/x-protobuf`, `application/protobuf`, `application/vnd.google.protobuf`, ... | YAML with field numbers (names with a schema) |
| `grpc` | `application/grpc`, `application/grpc+proto`, gRPC-Web (`application/grpc-web`, `-web-text`) | each message, decompressed as `grpc-encoding` says (`gzip`, `deflate`, and `zstd` with `zstd-decoder`), separated by `---`, then the trailers |
| `json` | `application/json`, `text/json`, `+json` | indented by two spaces |
| `graphql` | JSON with a `query` (or a batch of them) | the other members as JSON, then `---` and the query, one field per line |
| `msgpack` | `application/msgpack`, `application/x-msgpack` | YAML: every format of the specification, extensions as `!ext<type>`, timestamps as instants |
| `urlencoded`, `multipart` | `application/x-www-form-urlencoded`, `multipart/form-data` | the fields (a repeated name as a list), files' names, types and sizes |
| `query` | requests without a body | the query parameters |
| `socketio` | paths with `/socket.io/` or `/engine.io/` | one line per Engine.IO or Socket.IO packet |
| `dns` | `application/dns-message` (DNS over HTTPS, and [DNS over QUIC](quic-hooks.md#quic-message-framing)'s messages) | as `dig` shows it: the header, then each section's records |
| `hex` | anything, when named | a hex dump |

`views.with(myView)` adds a view (or replaces one of the same name); a view that fails on a body
is skipped. Views get bodies with their `Content-Encoding` removed, and must throw nothing but
`DecodeException` for data they cannot render.

### Protobuf without a schema

```text
1: 150  # !sint: 75
2: hello
3: !fixed32 3.14159  # u32: 1078530000
5:
  1: 42  # !sint: 21
6: !binary 038e029ea705  # packed: [3, 270, 86942]
```

The decoding follows mitmproxy's (ported from mitmproxy_rs):

- **Numbers.** Varints and fixed-width values are what the wire says; each is shown in its
  shortest reading, with the others as a comment: unsigned, signed when the top bit is set (a
  negative `int32` or `int64`, which take ten bytes), zigzag (`!sint`, for `sint32` and
  `sint64`), and as a float or double for `!fixed32` and `!fixed64`. Which one the field really
  is cannot be told from the bytes.
- **Length-delimited values** are guessed per field number, over all of the field's values:
  text when every value is UTF-8 without control characters (other than whitespace); else a
  nested message when every value parses as one (minimal varints, field numbers in range, one
  wire type per field number); else bytes, with a `packed:` comment when they read as two or more
  packed varints. Ambiguity is inherent: `08 96 01` is a message with field 1 = 150 and also the
  packed values 8 and 150; the message wins, as in mitmproxy.
- **Repetition.** A field that occurs more than once is a list. Groups (wire types 3 and 4) are
  `!group` mappings. Fields are sorted by number.
- **Limits.** Messages nest at most 64 deep (deeper values stay bytes), groups too (deeper ones
  are an error), and lengths are checked against the input before anything is allocated. Bad
  input is a `DecodeException`, never anything else; the build fuzzes the decoders with a fixed
  seed.

The same in Java, with editing:

```java
ProtoMessage m = Protobuf.decode(bytes);
Map<Object, Object> fields = m.toPlain();             // {1=150, 2=hello, 5={1=42}}
fields.put(2, "goodbye");
byte[] edited = Protobuf.encode(fields);

List<byte[]> messages = Grpc.messages(body, "gzip");  // split and decompress
byte[] framed = Grpc.join(messages, "gzip");           // frame and compress
Grpc.Status status = Grpc.statusFromTrailer(trailers.get("grpc-status-details-bin"));
```

Encoding a decoded `ProtoMessage` gives back its bytes, except where the input used non-minimal
varints at the top level. The plain form (`toPlain`) re-encodes to the same bytes when each
field's values were together on the wire, as encoders write them; fixed-width values and groups
stay `ProtoValue.Fixed32`, `Fixed64` and `Group` in it, so that they keep their wire types.

### gRPC

A unary call logged with `--mitm --log-http-view auto` (HTTP/2 both ways by default; headers
shortened):

```text
[conn 4 #2 stream 1] --> POST https://api.example.com/echo.Echo/Chat HTTP/2.0
[conn 4 #2 stream 1] content-type: application/grpc
[conn 4 #2 stream 1] te: trailers
[conn 4 #2 stream 1]
[conn 4 #2 stream 1] 1: unary
[conn 4 #2 stream 1] 2: 7  # !sint: -4
[conn 4 #2 stream 1] --> END POST (14-byte body, grpc view)
[conn 4 #2 stream 1] <-- 200 OK https://api.example.com/echo.Echo/Chat (21 ms, ttfb 9 ms, source=server)
[conn 4 #2 stream 1] content-type: application/grpc
[conn 4 #2 stream 1]
[conn 4 #2 stream 1] 1: UNARY
[conn 4 #2 stream 1] 2: 7  # !sint: -4
[conn 4 #2 stream 1] <-- trailers
[conn 4 #2 stream 1] grpc-status: 0  # OK
[conn 4 #2 stream 1] grpc-message: echoed 1
[conn 4 #2 stream 1] <-- END HTTP (14-byte body, grpc view)
```

Streams show each message in turn, separated by `---`; compressed ones say so (`#
gzip-compressed, 23 bytes`). An error's `grpc-status-details-bin` is decoded as a
`google.rpc.Status`, with the standard error details (`BadRequest`, `ErrorInfo`, `RetryInfo`,
...) by name, and `grpc-message` is percent-decoded:

```text
grpc-status: 3  # INVALID_ARGUMENT
grpc-message: invalid%20name  # invalid name
grpc-status-details-bin: CAMSDGludmFsaWQgbmFtZRo...
  code: 3
  message: invalid name
  details:
  - type_url: type.googleapis.com/google.rpc.BadRequest
    value:
      field_violations:
      - field: name
        description: must not be empty
```

### Field names from a descriptor set

With the `FileDescriptorSet` that `protoc` writes, messages decode with field names, enum names
and declared types:

```bash
protoc --include_imports --descriptor_set_out=api.desc -I protos protos/*.proto
java -jar microproxy-starlark-all.jar --mitm --proto-descriptors api.desc   # the -all jar has HTTP/2
```

```java
ProtoSchema schema = ProtoSchema.load(Path.of("api.desc"));
HttpLogger logger = HttpLogger.builder().level(HttpLogger.Level.BODY)
        .contentViews(ContentViews.defaults().withSchema(schema)).build();
ProtoMessage order = Protobuf.decode(bytes, schema, "shop.Order");
byte[] encoded = Protobuf.encode(Map.of("id", 42L, "status", "SHIPPED"), schema, "shop.Order");
```

- gRPC requests decode as their method's input type and responses as its output type, found by
  the request path (`/shop.Shop/GetOrder`). Protobuf bodies use a `messageType` (or `proto`,
  `type`) parameter of their `Content-Type`.
- Declared fields show their names and types: enum value names, zigzag-decoded `sint`s, `bool`s,
  floats, packed fields as lists, map fields as mappings, `Any` as the type its `type_url` names.
  Fields the schema does not declare, or whose wire type does not match, are decoded as without a
  schema.
- The descriptor set is parsed with the package's own decoder; nothing else is needed at run time.
  Extensions, default values and options other than `packed` and `map_entry` are ignored.
- Every schema knows `google.rpc.Status` and its error details, `google.protobuf.Any`,
  `Duration` and `Timestamp`, so status details have names even without one.
