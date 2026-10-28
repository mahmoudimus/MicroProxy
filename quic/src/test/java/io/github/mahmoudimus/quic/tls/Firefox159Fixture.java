package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.tls.HandshakeMessage.ClientHello;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;

/**
 * ClientHellos a real Firefox 159.0 (macOS, headless) sent to {@code https://localhost:8443/},
 * captured with {@code scripts/fingerprints/CaptureBrowser.java}: a new connection's, and the
 * next connection's, which resumes the first one's session.
 */
final class Firefox159Fixture {

    static final String FRESH = "clienthello-0.bin";
    static final String RESUMED = "clienthello-resumed.bin";

    private Firefox159Fixture() {}

    static byte[] bytes(String name) {
        String path = "/fingerprints/firefox-159/" + name;
        try (InputStream in = Firefox159Fixture.class.getResourceAsStream(path)) {
            if (in == null) throw new IllegalStateException("missing " + path);
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static ClientHello hello(String name) {
        byte[] message = bytes(name);
        try {
            return ClientHello.decode(new Reader(Arrays.copyOfRange(message, 4, message.length)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
