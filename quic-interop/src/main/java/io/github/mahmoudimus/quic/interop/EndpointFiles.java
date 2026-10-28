package io.github.mahmoudimus.quic.interop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** File and request parsing used only by the optional interoperability endpoint. */
final class EndpointFiles {
    static final int MAX_REQUEST_LINE = 8192;

    private EndpointFiles() {}

    static String readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        for (int i = 0; i < MAX_REQUEST_LINE; i++) {
            int b = in.read();
            if (b < 0) throw new IOException("request ended before CRLF");
            if (b == '\n') {
                String text = line.toString(StandardCharsets.US_ASCII);
                if (!text.startsWith("GET ") || !text.endsWith("\r")) throw new IOException("expected GET path CRLF");
                String path = text.substring(4, text.length() - 1);
                relative(path);
                if (in.read() != -1) throw new IOException("unexpected request body");
                return path;
            }
            if (b > 0x7e || b < 0x20 && b != '\r') throw new IOException("invalid request character");
            line.write(b);
        }
        throw new IOException("request line too long");
    }

    static Path relative(String rawPath) throws IOException {
        try {
            URI uri = URI.create(rawPath);
            if (rawPath.length() >= MAX_REQUEST_LINE - 6 || !rawPath.startsWith("/")
                    || rawPath.startsWith("//") || uri.isAbsolute() || uri.getRawAuthority() != null
                    || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new IOException("expected an absolute request path");
            }
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            for (int i = 0; i < rawPath.length(); i++) {
                char c = rawPath.charAt(i);
                if (c == '%') {
                    if (i + 2 >= rawPath.length()) throw new IOException("incomplete path escape");
                    int hi = Character.digit(rawPath.charAt(++i), 16);
                    int lo = Character.digit(rawPath.charAt(++i), 16);
                    if (hi < 0 || lo < 0) throw new IOException("invalid path escape");
                    bytes.write(hi * 16 + lo);
                } else {
                    if (c > 127) throw new IOException("request paths must use percent encoding");
                    bytes.write(c);
                }
            }
            String decoded = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
            for (int i = 0; i < decoded.length(); i++) {
                char c = decoded.charAt(i);
                if (c < 0x20 || c == 0x7f || c == '\\') throw new IOException("invalid path character");
            }
            String[] segments = decoded.substring(1).split("/", -1);
            for (String segment : segments) {
                if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) throw new IOException("invalid path component");
            }
            Path result = Path.of(decoded.substring(1));
            if (result.isAbsolute()) throw new IOException("absolute filesystem path");
            return result;
        } catch (IllegalArgumentException | CharacterCodingException e) {
            throw new IOException("invalid request path", e);
        }
    }

    static Path source(Path root, String rawPath) throws IOException {
        Path realRoot = root.toRealPath();
        Path file = realRoot.resolve(relative(rawPath)).toRealPath();
        if (!file.startsWith(realRoot) || !Files.isRegularFile(file)) throw new IOException("file is outside document root or not regular");
        return file;
    }

    @FunctionalInterface
    interface Download { void write(OutputStream out) throws IOException; }

    static void download(Path root, String rawPath, Download body) throws IOException {
        Files.createDirectories(root);
        Path realRoot = root.toRealPath();
        Path relative = relative(rawPath);
        Path parent = realRoot;
        for (int i = 0; i < relative.getNameCount() - 1; i++) {
            parent = parent.resolve(relative.getName(i));
            if (Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(parent) || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("download parent is not a plain directory");
                }
            } else {
                try {
                    Files.createDirectory(parent);
                } catch (FileAlreadyExistsException e) {
                    // Parallel downloads may create the same parent directory.
                    if (Files.isSymbolicLink(parent) || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) throw e;
                }
            }
            if (!parent.toRealPath().startsWith(realRoot)) throw new IOException("download escaped root");
        }
        Path destination = parent.resolve(relative.getFileName());
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) throw new IOException("download already exists: " + destination);
        Path temporary = Files.createTempFile(parent, ".quic-download-", ".part");
        try {
            try (OutputStream out = Files.newOutputStream(temporary, LinkOption.NOFOLLOW_LINKS)) {
                body.write(out);
            }
            // No REPLACE_EXISTING: a peer cannot overwrite an existing file or symlink.
            Files.move(temporary, destination);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
