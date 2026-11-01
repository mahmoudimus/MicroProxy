/** Negative control: runtime type test on an attacker-controlled object. */
public final class ClassOracle {
    public static int run(byte[] ignored, Object value) {
        return value instanceof String ? 1 : 0;
    }
}
