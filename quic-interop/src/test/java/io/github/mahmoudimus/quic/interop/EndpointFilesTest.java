package io.github.mahmoudimus.quic.interop;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EndpointFilesTest {
    @TempDir Path temporary;

    @Test
    void unsupportedDispatchDoesNotTouchCertificatesOrParseOtherOptions() {
        for (String testcase : new String[] {"v2", "versionnegotiation", "connectionmigration", "unknown"}) {
            assertEquals(127, InteropEndpoint.execute(Map.of("ROLE", "client", "TESTCASE", testcase,
                    "PORT", "not-a-number", "CERTS", "/does-not-exist")));
        }
        assertEquals(127, InteropEndpoint.execute(Map.of("ROLE", "server", "TESTCASE", "keyupdate")));
        assertEquals(127, InteropEndpoint.execute(Map.of("ROLE", "invalid", "TESTCASE", "handshake")));
    }

    @Test
    void requestLineIsBoundedAndRequiresGetAndCrlf() throws Exception {
        assertEquals("/nested/a%20b", EndpointFiles.readRequest(input("GET /nested/a%20b\r\n")));
        for (String bad : new String[] {"POST /a\r\n", "GET /a\n", "GET /a HTTP/1.1\r\n",
                "GET /a\r\nbody", "GET /" + "a".repeat(8192) + "\r\n"}) {
            assertThrows(IOException.class, () -> EndpointFiles.readRequest(input(bad)), bad.substring(0, Math.min(10, bad.length())));
        }
    }

    @Test
    void decodesPathsAndRejectsTraversalAndEscapingSymlinks() throws Exception {
        Path root = Files.createDirectory(temporary.resolve("www"));
        Path nested = Files.createDirectory(root.resolve("nested"));
        Path file = Files.writeString(nested.resolve("a b"), "contents");
        assertEquals(file.toRealPath(), EndpointFiles.source(root, "/nested/a%20b"));
        for (String bad : new String[] {"/../outside", "/%2e%2e/outside", "/nested/../../outside",
                "/nested\\outside", "/%00", "/%ff", "https://host/file", "/"}) {
            assertThrows(IOException.class, () -> EndpointFiles.source(root, bad), bad);
        }
        Path outside = Files.writeString(temporary.resolve("outside"), "secret");
        Files.createSymbolicLink(root.resolve("link"), outside);
        assertThrows(IOException.class, () -> EndpointFiles.source(root, "/link"));
    }

    @Test
    void downloadsCannotFollowSymlinksOrOverwriteExistingFiles() throws Exception {
        Path root = Files.createDirectory(temporary.resolve("downloads"));
        Path outside = Files.createDirectory(temporary.resolve("outside"));
        Files.createSymbolicLink(root.resolve("escape"), outside);
        assertThrows(IOException.class, () -> EndpointFiles.download(root, "/escape/file", out -> out.write(1)));
        EndpointFiles.download(root, "/nested/a%20b", out -> out.write(new byte[] {1, 2, 3}));
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(root.resolve("nested/a b")));
        assertThrows(IOException.class, () -> EndpointFiles.download(root, "/nested/a%20b", out -> out.write(4)));
        assertThrows(IOException.class, () -> EndpointFiles.download(root, "/partial", out -> {
            out.write(9);
            throw new IOException("transfer failed");
        }));
        assertFalse(Files.exists(root.resolve("partial")));
    }

    private static ByteArrayInputStream input(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII));
    }
}
