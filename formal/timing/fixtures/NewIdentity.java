/** Negative control: object identity/null conflation. */
public final class NewIdentity {
    public static int run(byte[] ignored) {
        Object value = new Object();
        return value == null ? 1 : 0;
    }
}
