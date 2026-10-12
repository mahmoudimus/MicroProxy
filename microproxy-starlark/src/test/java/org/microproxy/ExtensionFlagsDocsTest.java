package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The launcher's options from extensions ({@code --script*} from this module, {@code --otel*} from
 * {@code microproxy-otel}) must be in {@code docs/reference/cli.md} too: the core's {@link
 * DocsDriftTest} sees only the core's options, since the extensions are not on its class path.
 */
class ExtensionFlagsDocsTest {

    @Test
    void extensionFlagsAreInTheCliReference() throws IOException {
        Set<String> flags = DocsDriftTest.acceptedFlags();
        assertTrue(flags.contains("--script") && flags.contains("--otel"), "extensions not loaded: " + flags);
        assertEquals(Set.of(), DocsDriftTest.undocumentedFlags(flags), "flags missing from docs/reference/cli.md");
    }
}
