package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ActivityLoggerEscapingTest {

    @Test
    void jsonEscapingHandlesQuotesBackslashesAndControls() {
        // LittleProxy escaped quotes before backslashes, which corrupted both.
        assertEquals("a\\\"b\\\\c\\n\\u0001", ActivityLogger.json("a\"b\\c\n\u0001"));
    }

    @Test
    void csvQuotesPerRfc4180() {
        assertEquals("\"say \"\"hi\"\"\"", ActivityLogger.csv("say \"hi\""));
    }
}
