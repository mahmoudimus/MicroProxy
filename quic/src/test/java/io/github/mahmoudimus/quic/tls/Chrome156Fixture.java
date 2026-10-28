package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;

/**
 * ClientHellos a real Chrome 156.0.8078.48 (macOS, headless) sent to {@code
 * https://localhost:18443/}, captured with {@code scripts/fingerprints/CaptureBrowser.java}.
 * Hellos 0 and 1 are fresh, with GREASE ECH payloads of 176 and 240 bytes; hello 3 resumes.
 */
final class Chrome156Fixture {

    /** The GREASE values of hello 0. */
    static final Grease GREASE_0 = new Grease(0xaaaa, 0x0a0a, 0x4a4a, 0x5a5a, 0x4a4a, 0x7a7a);

    private Chrome156Fixture() {}

    static byte[] bytes(int n) {
        String name = "/fingerprints/chrome-156/clienthello-" + n + ".bin";
        try (InputStream in = Chrome156Fixture.class.getResourceAsStream(name)) {
            if (in == null) throw new IllegalStateException("missing " + name);
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static ClientHello hello(int n) {
        byte[] message = bytes(n);
        try {
            return ClientHello.decode(new Reader(Arrays.copyOfRange(message, 4, message.length)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] extension(int n, int type) {
        byte[] body = HandshakeMessage.Extension.find(hello(n).extensions(), type);
        if (body == null) throw new IllegalStateException("hello " + n + " has no extension " + type);
        return body;
    }
}
