/** Negative control: storing a secret-content array reference into a public array field. */
public final class FieldAlias {
    int[] f = new int[] { 7 };

    public int run(byte[] secret) {
        int[] secretArray = new int[secret.length];
        for (int i = 0; i < secret.length; i++) {
            secretArray[i] = secret[i];
        }
        f = secretArray;
        return f[0] != 0 ? 1 : 0;
    }
}
