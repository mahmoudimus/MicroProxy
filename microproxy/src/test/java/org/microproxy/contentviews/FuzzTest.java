package org.microproxy.contentviews;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaders;

/**
 * Random and mutated input, with a fixed seed: decoders and views throw nothing but {@link
 * DecodeException}, and whatever decodes renders, converts and encodes without failing.
 */
class FuzzTest {

    private static final long SEED = 0x5eed_c0deL;
    private static final int ROUNDS = 5_000;

    /** Valid inputs to mutate. */
    private static List<byte[]> seeds() throws Exception {
        List<byte[]> seeds = new ArrayList<>();
        for (String hex : ProtobufTest.captured()) seeds.add(ProtobufTest.hex(hex));
        for (ProtobufTest.Vector v : ProtobufTest.vectors()) seeds.add(v.proto());
        seeds.add(TinySchema.bytes());
        seeds.add(Protobuf.encode(ProtoSchemaTest.sampleOrder(), ProtoSchemaTest.tiny(), "shop.Order"));
        seeds.add(GrpcTest.TEST_GRPC);
        seeds.add(GrpcTest.TEST_GZIP);
        seeds.add(ProtobufTest.hex("83a46e616d65a84a6f686e20446f65a3616765" + "1e" + "a474616773" + "92a9646576656c6f706572a472757374"));
        return seeds;
    }

    private static byte[] mutate(byte[] seed, Random r) {
        byte[] b = seed.clone();
        switch (r.nextInt(5)) {
            case 0 -> {
                if (b.length > 0) b[r.nextInt(b.length)] = (byte) r.nextInt(256);
            }
            case 1 -> {
                if (b.length > 0) b[r.nextInt(b.length)] ^= (byte) (1 << r.nextInt(8));
            }
            case 2 -> b = Arrays.copyOf(b, r.nextInt(b.length + 1));
            case 3 -> {
                int at = r.nextInt(b.length + 1);
                byte[] extra = new byte[1 + r.nextInt(8)];
                r.nextBytes(extra);
                byte[] out = new byte[b.length + extra.length];
                System.arraycopy(b, 0, out, 0, at);
                System.arraycopy(extra, 0, out, at, extra.length);
                System.arraycopy(b, at, out, at + extra.length, b.length - at);
                b = out;
            }
            default -> {
                b = new byte[r.nextInt(64)];
                r.nextBytes(b);
            }
        }
        return b;
    }

    @Test
    void decodersThrowOnlyDecodeExceptions() throws Exception {
        Random r = new Random(SEED);
        List<byte[]> seeds = seeds();
        ProtoSchema schema = ProtoSchemaTest.tiny();
        ContentViews views = ContentViews.defaults().withSchema(schema);
        HttpHeaders grpcHeaders = new HttpHeaders().set("content-type", "application/grpc").set("grpc-encoding", "gzip");
        List<ContentView.Metadata> metadata = List.of(
                new ContentView.Metadata("application/grpc", grpcHeaders, null, "/shop.Shop/GetOrder", false),
                ContentView.Metadata.of("application/grpc-web+proto"),
                ContentView.Metadata.of("application/x-protobuf; messageType=shop.Order"),
                ContentView.Metadata.of("application/msgpack"),
                ContentView.Metadata.of("application/json"),
                ContentView.Metadata.of("multipart/form-data; boundary=b"),
                ContentView.Metadata.of("application/x-www-form-urlencoded"),
                new ContentView.Metadata(null, null, null, "/socket.io/?EIO=4", true));
        int decoded = 0;
        for (int i = 0; i < ROUNDS; i++) {
            byte[] data = mutate(seeds.get(r.nextInt(seeds.size())), r);
            try {
                ProtoMessage m = Protobuf.decode(data);
                decoded++;
                assertNotNull(m.render());
                Protobuf.encode(m.toPlain());
                byte[] again = Protobuf.encode(m);
                // A message that decoded encodes back to bytes that decode to the same message.
                assertArrayEquals(again, Protobuf.encode(Protobuf.decode(again)));
                Protobuf.decode(data, schema, "shop.Order").render();
            } catch (DecodeException expected) {
                // fine
            } catch (RuntimeException | StackOverflowError e) {
                throw new AssertionError("protobuf failed on " + java.util.HexFormat.of().formatHex(data), e);
            }
            try {
                ProtoSchema.parse(data);
            } catch (DecodeException expected) {
                // fine
            } catch (RuntimeException e) {
                throw new AssertionError("schema failed on " + java.util.HexFormat.of().formatHex(data), e);
            }
            try {
                Grpc.messages(data, "gzip");
            } catch (DecodeException expected) {
                // fine
            } catch (RuntimeException e) {
                throw new AssertionError("gRPC failed on " + java.util.HexFormat.of().formatHex(data), e);
            }
            for (ContentView.Metadata m : metadata) {
                for (String name : views.names()) {
                    if (name.equals(ContentViews.AUTO)) continue;
                    try {
                        views.get(name).orElseThrow().priority(data, m);
                        views.get(name).orElseThrow().render(data, m);
                    } catch (DecodeException expected) {
                        // fine
                    } catch (RuntimeException e) {
                        throw new AssertionError(name + " failed on " + java.util.HexFormat.of().formatHex(data), e);
                    }
                }
            }
        }
        if (decoded < ROUNDS / 20) fail("too few inputs decoded to exercise the encoder: " + decoded);
    }
}
