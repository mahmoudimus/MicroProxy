// Class FailureKind
// Dafny class FailureKind compiled into Java
package io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec;

import io.github.mahmoudimus.quic.internal.verifiedcrypto.NativeTypes.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.PolySpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.CodecSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SamplingSpec.*;
import io.github.mahmoudimus.quic.internal.verifiedcrypto.SpongeSpec.*;

@SuppressWarnings({"unchecked", "deprecation"})
public abstract class FailureKind {
  public FailureKind() {
  }
  private static final dafny.TypeDescriptor<FailureKind> _TYPE = dafny.TypeDescriptor.<FailureKind>referenceWithInitializer(FailureKind.class, () -> FailureKind.Default());
  public static dafny.TypeDescriptor<FailureKind> _typeDescriptor() {
    return (dafny.TypeDescriptor<FailureKind>) (dafny.TypeDescriptor<?>) _TYPE;
  }

  private static final FailureKind theDefault = io.github.mahmoudimus.quic.internal.verifiedcrypto.KemSpec.FailureKind.create_InvalidSeedLength();
  public static FailureKind Default() {
    return theDefault;
  }
  public static FailureKind create_InvalidSeedLength() {
    return new FailureKind_InvalidSeedLength();
  }
  public static FailureKind create_InvalidKeyLength() {
    return new FailureKind_InvalidKeyLength();
  }
  public static FailureKind create_InvalidMessageLength() {
    return new FailureKind_InvalidMessageLength();
  }
  public static FailureKind create_InvalidCiphertextLength() {
    return new FailureKind_InvalidCiphertextLength();
  }
  public static FailureKind create_ModulusError() {
    return new FailureKind_ModulusError();
  }
  public static FailureKind create_RejectionLimit() {
    return new FailureKind_RejectionLimit();
  }
  public boolean is_InvalidSeedLength() { return this instanceof FailureKind_InvalidSeedLength; }
  public boolean is_InvalidKeyLength() { return this instanceof FailureKind_InvalidKeyLength; }
  public boolean is_InvalidMessageLength() { return this instanceof FailureKind_InvalidMessageLength; }
  public boolean is_InvalidCiphertextLength() { return this instanceof FailureKind_InvalidCiphertextLength; }
  public boolean is_ModulusError() { return this instanceof FailureKind_ModulusError; }
  public boolean is_RejectionLimit() { return this instanceof FailureKind_RejectionLimit; }
  public static java.util.ArrayList<FailureKind> AllSingletonConstructors() {
    java.util.ArrayList<FailureKind> singleton_iterator = new java.util.ArrayList<>();
    singleton_iterator.add(new FailureKind_InvalidSeedLength());
    singleton_iterator.add(new FailureKind_InvalidKeyLength());
    singleton_iterator.add(new FailureKind_InvalidMessageLength());
    singleton_iterator.add(new FailureKind_InvalidCiphertextLength());
    singleton_iterator.add(new FailureKind_ModulusError());
    singleton_iterator.add(new FailureKind_RejectionLimit());
    return singleton_iterator;
  }
}
