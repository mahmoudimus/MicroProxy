package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dafny.DafnySequence;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.BytesResult;
import io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default;
import io.github.mahmoudimus.verifiedcrypto.JdkHmac;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/** Regressions at the generated array entry boundary, including allowed aliases. */
class HkdfArrayInputTest {
    private static final BigInteger SHA256 = BigInteger.valueOf(32);

    @Test
    void generatedCopyIsAnImmutableSnapshotForEveryOctet() {
        byte[] input = new byte[256];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) i;
        }
        byte[] expected = input.clone();
        DafnySequence<? extends Byte> snapshot = __default.CopyInput(input);
        input[0] = 99;
        input[255] = 0;
        assertArrayEquals(expected, JdkHmac.bytes(snapshot));
        byte[] returned = JdkHmac.bytes(snapshot);
        returned[128] = 0;
        assertArrayEquals(expected, JdkHmac.bytes(snapshot));
    }

    @Test
    void arrayRoutesAcceptSharedInputsAndPreserveThem() {
        byte[] shared = {0, 1, 127, (byte) 128, (byte) 255};
        byte[] before = shared.clone();
        BytesResult extract = __default.ExtractArrays(SHA256, shared, shared);
        assertTrue(extract.is_Success());
        assertArrayEquals(Hkdf.SHA256.extract(shared, shared), JdkHmac.bytes(extract.dtor_bytes()));
        BytesResult expand = __default.ExpandArrays(SHA256, shared, shared, BigInteger.valueOf(65));
        assertTrue(expand.is_Success());
        assertArrayEquals(Hkdf.SHA256.expand(shared, shared, 65), JdkHmac.bytes(expand.dtor_bytes()));
        assertArrayEquals(before, shared);
    }

    @Test
    void totalArrayEntryKeepsHashLengthKeyAndUtf16ErrorPrecedence() {
        byte[] empty = {};
        assertTrue(__default.ExpandArrays(BigInteger.ONE, empty, empty, BigInteger.valueOf(-1))
                .dtor_reason().is_InvalidHash());
        assertTrue(__default.ExpandArrays(SHA256, empty, empty, BigInteger.valueOf(-1))
                .dtor_reason().is_InvalidLength());
        assertTrue(__default.ExpandArrays(SHA256, empty, empty, BigInteger.ZERO)
                .dtor_reason().is_InvalidKey());
        assertTrue(__default.LabelInfoArray(DafnySequence.of(new short[] {(short) 0xd800}),
                empty, BigInteger.ZERO).dtor_reason().is_InvalidLabel());
        assertTrue(__default.LabelInfoArray(DafnySequence.of(new short[] {(short) 0xd800}),
                empty, BigInteger.valueOf(-1)).dtor_reason().is_InvalidLength());
        assertTrue(__default.ExtractArrays(SHA256, empty, empty).is_Success());
    }
}
