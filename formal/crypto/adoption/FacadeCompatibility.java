package io.github.mahmoudimus.quic.tls;
public final class FacadeCompatibility {
    interface TestCase { void run() throws Exception; }
    static int count;
    static void run(String name, TestCase test) throws Exception {
        test.run(); count++; System.out.println("PASS "+name);
    }
    public static void main(String[] args) throws Exception {
        if (!Shake.class.getProtectionDomain().getCodeSource().getLocation().toURI().equals(java.nio.file.Path.of(args[0]).toUri()))
            throw new AssertionError("Wrong facade class origin");
        if (!MlKem768.class.getProtectionDomain().getCodeSource().getLocation().toURI().equals(java.nio.file.Path.of(args[0]).toUri()))
            throw new AssertionError("Wrong KEM facade class origin");
        run("ShakeTest.matchesPythonsHashlib", () -> new ShakeTest().matchesPythonsHashlib());
        run("ShakeTest.piecewiseInputAndOutputMatchOneShot", () -> new ShakeTest().piecewiseInputAndOutputMatchOneShot());
        run("ShakeTest.updateAfterReadIsRejected", () -> new ShakeTest().updateAfterReadIsRejected());
        run("GeneratedCryptoFacadeTest.invalidSlicesAreAtomicAndCheckedBeforeAbsorption", () -> new GeneratedCryptoFacadeTest().invalidSlicesAreAtomicAndCheckedBeforeAbsorption());
        run("GeneratedCryptoFacadeTest.failedNullReadDoesNotStartSqueezingButEmptyReadDoes", () -> new GeneratedCryptoFacadeTest().failedNullReadDoesNotStartSqueezingButEmptyReadDoes());
        run("GeneratedCryptoFacadeTest.keyInputsExportsAndRepeatedDecapsulationRemainIndependent", () -> new GeneratedCryptoFacadeTest().keyInputsExportsAndRepeatedDecapsulationRemainIndependent());
        run("GeneratedCryptoFacadeTest.invalidMessageLengthsAreRejected", () -> new GeneratedCryptoFacadeTest().invalidMessageLengthsAreRejected());
        run("GeneratedCryptoFacadeTest.internallyGeneratedSeedAndMessageBuffersAreWiped", () -> new GeneratedCryptoFacadeTest().internallyGeneratedSeedAndMessageBuffersAreWiped());
        run("MlKem768Test.sizesAreFips203s", () -> new MlKem768Test().sizesAreFips203s());
        run("MlKem768Test.malformedInputsAreRejected", () -> new MlKem768Test().malformedInputsAreRejected());
        run("MlKem768Test.aTamperedCiphertextGivesADifferentKey", () -> new MlKem768Test().aTamperedCiphertextGivesADifferentKey());
        run("MlKem768Test.accumulated100", () -> new MlKem768Test().accumulated100());
        run("MlKem768Test.accumulated10000", () -> new MlKem768Test().accumulated10000());
        if (count != 13) throw new AssertionError("Incomplete test inventory");
        System.out.println("PASS compatibility count="+count+" Go accumulated=100+10000");
    }
}
