package io.github.mahmoudimus.quic.tls;

import io.github.mahmoudimus.quic.Hkdf;
import java.nio.file.Path;

/** Compare HKDF backends while keeping the complete hybrid handshake identical. */
public final class HkdfHandshakeBenchmark {
    private HkdfHandshakeBenchmark() {}

    private static void origin(Class<?> type, String expected) throws Exception {
        Path actual = Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if (!actual.equals(Path.of(expected).toRealPath())) {
            throw new AssertionError("Unexpected HKDF class origin: " + type + " " + actual);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 8) {
            throw new IllegalArgumentException("hkdf main fixtures harness generated warmup batch runtime");
        }
        origin(Hkdf.class, args[0]);
        origin(HkdfHandshakeBenchmark.class, args[3]);
        origin(dafny.Helpers.class, args[7]);
        if (Boolean.parseBoolean(args[4])) {
            origin(Class.forName("io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default"), args[1]);
            origin(Class.forName("io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge"), args[1]);
            origin(Class.forName("io.github.mahmoudimus.verifiedcrypto.JdkHmac"), args[1]);
        }
        HybridHandshakeBenchmark.main(new String[] {
                args[1], args[1], args[2], args[3], args[1], args[5], args[6]});
    }
}
