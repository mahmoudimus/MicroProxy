package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.microproxy.impl.BootstrapProbe;

/**
 * Fails when the command-line or properties reference falls behind the launcher: every flag the
 * {@link Launcher} accepts must be in {@code docs/reference/cli.md}, and every key a properties
 * file is read for must be in {@code docs/reference/properties.md}.
 *
 * <p>Flags come from the launcher itself: every {@code --option} its {@code --help} text names
 * (as an entry or in a description) is offered to its parser, which tells known options from
 * unknown ones. Property keys come from reading a {@link Properties} that records every key the
 * bootstrap asks for, offered each key in turn with sample values so that keys read only when
 * another is set (such as {@code log_http_format} after {@code log_http}) are found too.
 */
class DocsDriftTest {

    private static final Pattern OPTION = Pattern.compile("(?<![\\w-])--[a-z0-9][a-z0-9-]*");
    private static final Pattern CODE_SPAN = Pattern.compile("`([^`\\n]+)`");
    private static final Pattern FENCE = Pattern.compile("(?ms)^\\s*```.*?^\\s*```[^\\n]*$");
    private static final String UNKNOWN = "--zz-not-an-option";

    /** The repository's {@code docs} directory, from a module directory or the root. */
    public static Path docsDir() {
        for (Path dir : List.of(Path.of("docs"), Path.of("..", "docs"))) {
            if (Files.isDirectory(dir.resolve("reference"))) return dir;
        }
        throw new IllegalStateException("docs/reference not found from " + Path.of("").toAbsolutePath());
    }

    /** The launcher's {@code --help} text, with whatever extensions are on the class path. */
    public static String launcherHelp() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Launcher.parse(new String[] {"--help"}, new PrintStream(out, true, StandardCharsets.UTF_8));
        return out.toString(StandardCharsets.UTF_8);
    }

    /** Every option the help text names that the launcher's parser accepts. */
    public static Set<String> acceptedFlags() throws IOException {
        Set<String> accepted = new TreeSet<>();
        Matcher m = OPTION.matcher(launcherHelp());
        while (m.find()) {
            if (accepts(m.group())) accepted.add(m.group());
        }
        return accepted;
    }

    /** The options listed as entries of the help text (at the start of a line). */
    public static Set<String> listedFlags() throws IOException {
        Set<String> listed = new TreeSet<>();
        for (String line : launcherHelp().split("\n")) {
            Matcher m = Pattern.compile("^ {2}(--[a-z0-9][a-z0-9-]*)").matcher(line);
            if (m.find()) listed.add(m.group(1));
        }
        return listed;
    }

    /**
     * Whether the parser knows {@code flag}: it is followed by an unknown option, so a known flag
     * fails on that one (or on its value) before anything is configured or created, and an unknown
     * flag fails on itself.
     */
    static boolean accepts(String flag) {
        try {
            Launcher.parse(new String[] {flag, UNKNOWN, UNKNOWN, UNKNOWN}, new PrintStream(new ByteArrayOutputStream()));
            return true;
        } catch (IOException | UncheckedIOException e) {
            return true;
        } catch (RuntimeException e) {
            String message = String.valueOf(e.getMessage());
            return !message.startsWith("unknown option: " + flag + "\n");
        }
    }

    /** The inline code spans of a Markdown file, outside fenced code blocks. */
    static Set<String> codeSpans(Path markdown) throws IOException {
        Set<String> spans = new TreeSet<>();
        String text = FENCE.matcher(Files.readString(markdown, StandardCharsets.UTF_8)).replaceAll("");
        Matcher m = CODE_SPAN.matcher(text);
        while (m.find()) spans.add(m.group(1).strip());
        return spans;
    }

    /** The flags in {@code flags} that no code span of {@code cli.md} starts with. */
    public static Set<String> undocumentedFlags(Set<String> flags) throws IOException {
        Set<String> spans = codeSpans(docsDir().resolve("reference/cli.md"));
        Set<String> missing = new TreeSet<>();
        for (String flag : flags) {
            boolean documented = spans.stream().anyMatch(s -> s.equals(flag) || s.startsWith(flag + " "));
            if (!documented) missing.add(flag);
        }
        return missing;
    }

    @Test
    void everyListedFlagIsAccepted() throws IOException {
        Set<String> listed = listedFlags();
        assertTrue(listed.size() > 100, "too few flags found in --help: " + listed);
        Set<String> rejected = new TreeSet<>(listed);
        rejected.removeAll(acceptedFlags());
        assertEquals(Set.of(), rejected, "--help lists options the launcher does not accept");
    }

    @Test
    void unknownFlagsAreRejected() {
        assertTrue(!accepts("--no-such-flag-anywhere"), "the probe must tell unknown options apart");
        assertTrue(accepts("--port"));
        assertTrue(accepts("--mitm"));
    }

    @Test
    void everyFlagIsInTheCliReference() throws IOException {
        Set<String> missing = undocumentedFlags(acceptedFlags());
        assertEquals(Set.of(), missing, "flags missing from docs/reference/cli.md");
    }

    @Test
    void everyPropertyIsInThePropertiesReference(@TempDir Path tmp) throws IOException {
        Set<String> keys = BootstrapProbe.propertyKeys(tmp);
        assertTrue(keys.size() > 100, "too few property keys found: " + keys);
        Set<String> spans = codeSpans(docsDir().resolve("reference/properties.md"));
        Set<String> missing = new TreeSet<>();
        for (String key : keys) {
            if (!spans.contains(key)) missing.add(key);
        }
        assertEquals(Set.of(), missing, "properties missing from docs/reference/properties.md");
    }
}
