package org.microproxy.extras;

/** The proxy's JSON parser, for tests in other packages. */
public final class JsonForTests {

    private JsonForTests() {}

    /**
     * Parses {@code text}: objects become maps, arrays lists, numbers longs or doubles.
     *
     * @param text the JSON text
     * @return the value
     * @throws IllegalArgumentException if it is not valid JSON
     */
    public static Object parse(String text) {
        return Json.parse(text);
    }
}
