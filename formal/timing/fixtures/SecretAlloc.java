/** Negative control: secret-sized allocation. */
public final class SecretAlloc {
    public static byte[] run(byte[] secret) {
        byte[] buffer = new byte[secret.length + (secret[0] & 7)];
        buffer[0] = 1;
        return buffer;
    }
}
