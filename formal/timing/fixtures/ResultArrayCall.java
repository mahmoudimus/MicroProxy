/** Negative control: a call-result array role without an explicit length contract. */
public final class ResultArrayCall {
    static byte[] make(byte[] input) {
        return input;
    }

    public static int run(byte[] input) {
        byte[] result = make(input);
        return result[0] != 0 ? 1 : 0;
    }
}
